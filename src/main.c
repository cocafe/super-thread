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
#include "sysinfo.h"
#include "supervisor.h"
#include "config_opts.h"

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

        sysinfo_init(&g_sys_info);

        {
//                HWND console_wnd = GetConsoleWindow();
//                ShowWindow(console_wnd, SW_HIDE);
//                ShowWindow(console_wnd, SW_NORMAL);
//                ShowWindow(console_wnd, SW_RESTORE);
        }


        if ((err = usrcfg_init())) {
                MB_MSG_ERR("failed to load config: \"%s\"", g_cfg.json_path);
                goto exit_sysinfo;
        }

        MB_MSG_INFO("PRESS TO START");

        supervisor_init(&g_sv);

        supervisor_run(&g_sv);

        while (GetMessage(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
        }

        supervisor_deinit(&g_sv);

        usrcfg_deinit();

exit_sysinfo:
        sysinfo_deinit(&g_sys_info);

exit_logging:
        logging_exit();

out:
        return err;
}
