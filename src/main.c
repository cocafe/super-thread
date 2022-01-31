#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>

#include <conio.h>
#include <fcntl.h>
#include <windows.h>
#include <windowsx.h>
#include <winuser.h>
#include <winnls.h>
#include <winternl.h>
#include <fileapi.h>
#include <TlHelp32.h>

#include "utils.h"
#include "config.h"
#include "logging.h"
#include "supervisor.h"
#include "config_opts.h"

void processor_group_test(void)
{
        int nr_grps = GetActiveProcessorGroupCount();
        if (nr_grps < 1) {
                pr_info("no processor group\n");
                return;
        }

        pr_info("has %d processor groups\n", nr_grps);

        for (int i = 0; i < nr_grps; i++) {
                pr_info("group %d has %lu processors\n", i, GetMaximumProcessorCount(i));
        }
}

#include <sysinfoapi.h>

void DumpLPI(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX pslpi)
{
        union {
                PPROCESSOR_RELATIONSHIP Processor;
                PNUMA_NODE_RELATIONSHIP NumaNode;
                PCACHE_RELATIONSHIP Cache;
                PGROUP_RELATIONSHIP Group;
        } u;

        u.Processor = &pslpi->Processor;

        switch (pslpi->Relationship) {
        case RelationProcessorPackage:
                pr_info("RelationProcessorPackage(GroupCount = %u)\n", u.Processor->GroupCount);

                WORD GroupCount;
                if ((GroupCount = u.Processor->GroupCount))
                {
                        PGROUP_AFFINITY GroupMask = u.Processor->GroupMask;
                        do
                        {
                                pr_info("group<%u> Mask = %016llx\n", GroupMask->Group, GroupMask->Mask);
                        } while (GroupMask++, --GroupCount);
                }
                break;

        case RelationProcessorCore:
                pr_info("RelationProcessorCore(%x): Mask = %016llx\n", u.Processor->Flags, u.Processor->GroupMask->Mask);
                break;

        case RelationGroup:
                pr_info("RelationGroup(%u/%u)\n", u.Group->ActiveGroupCount, u.Group->MaximumGroupCount);

                WORD ActiveGroupCount;
                if ((ActiveGroupCount = u.Group->ActiveGroupCount))
                {
                        PPROCESSOR_GROUP_INFO GroupInfo = u.Group->GroupInfo;
                        do
                        {
                                pr_info("<%d/%d %016llx>\n",
                                         GroupInfo->ActiveProcessorCount,
                                         GroupInfo->MaximumProcessorCount,
                                         GroupInfo->ActiveProcessorMask);
                        } while (GroupInfo++, --ActiveGroupCount);
                }
                break;

        case RelationCache:
                pr_info("Cache L%d (%x, %lx) %x\n", u.Cache->Level, u.Cache->LineSize, u.Cache->CacheSize, u.Cache->Type);
                break;

        case RelationNumaNode:
                pr_info("NumaNode<%lu> (group = %d, mask = %016llx)\n", u.NumaNode->NodeNumber, u.NumaNode->GroupMask.Group, u.NumaNode->GroupMask.Mask);
                break;

        default:
                pr_info("unknown Relationship=%x\n", pslpi->Relationship);
        }
}

void processor_topology_test()
{
        DWORD sz = 0, info_sz, err;
        BOOL ok;
        void *buf, *__buf;


        GetLogicalProcessorInformationEx(RelationAll, NULL, &sz);
        if ((err = GetLastError()) != ERROR_INSUFFICIENT_BUFFER) {
                pr_err("GetLogicalProcessorInformationEx() failed, err = %lu\n", err);
                return;
        }

        __buf = calloc(1, sz);
        if (!__buf) {
                pr_err("failed to allocate %lu bytes\n", sz);
                return;
        }

        buf = __buf;

        ok = GetLogicalProcessorInformationEx(RelationAll, buf, &sz);
        if (!ok || !sz) {
                pr_err("GetLogicalProcessorInformationEx() failed, err = %lu\n", (err = GetLastError()));
                goto out;
        }

        do {
                DumpLPI(buf);
                info_sz = ((SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *) buf)->Size;
                buf = (uint8_t *)buf + info_sz;
        } while (sz -= info_sz);

out:
        free(__buf);
}

static int __privilege_get(const wchar_t *priv_name)
{
        HANDLE token;
        TOKEN_PRIVILEGES tkp;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
                pr_err("OpenProcessToken() failed, err=%lu\n", GetLastError());
                return -EINVAL;
        }

        LookupPrivilegeValue(NULL, priv_name, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(token, FALSE, &tkp, 0, NULL, 0)) {
                pr_err("AdjustTokenPrivileges() err=%lu\n", GetLastError());
                return -EINVAL;
        }

        return 0;
}

static int privilege_get(void)
{
        static const wchar_t *sec_tokens[] = {
                SE_ASSIGNPRIMARYTOKEN_NAME,
                SE_DEBUG_NAME,
                SE_INC_BASE_PRIORITY_NAME,
        };

        int err;

        for (size_t i = 0; i < ARRAY_SIZE(sec_tokens); i++) {
                if ((err = __privilege_get(sec_tokens[i]))) {
                        pr_err("failed to request %ls\n", sec_tokens[i]);
                        break;
                }
        }

        return err;
}

int WINAPI wWinMain(HINSTANCE ins, HINSTANCE prev_ins,
                    LPWSTR cmdline, int cmdshow)
{
        UNUSED_PARAM(ins);
        UNUSED_PARAM(prev_ins);
        UNUSED_PARAM(cmdline);
        UNUSED_PARAM(cmdshow);
        MSG msg;
        int err;

        heap_init();

        if ((err = wchar_longopts_parse(__argc, __wargv))) {
                goto out;
        }

        if ((err = logging_init()))
                goto out;

#ifndef UNICODE
        iconv_winnt_locale_init();
#endif

        if ((err = privilege_get())) {
                MB_MSG_ERR("failed to get privileges");
                goto exit_logging;
        }

        {
//                HWND console_wnd = GetConsoleWindow();
//                ShowWindow(console_wnd, SW_HIDE);
//                ShowWindow(console_wnd, SW_NORMAL);
//                ShowWindow(console_wnd, SW_RESTORE);
        }


        if ((err = usrcfg_init())) {
                MB_MSG_ERR("failed to load config: \"%s\"", g_cfg.json_path);
                goto exit_logging;
        }

        MB_MSG_INFO("PRESS TO START");

        {
                supervisor_t sv = { 0 };

                supervisor_init(&sv);
                supervisor_run(&sv);
                supervisor_deinit(&sv);
        }

        while (GetMessage(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
        }

        usrcfg_deinit();

exit_logging:
        logging_exit();

out:
        return err;
}
