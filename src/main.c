#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>

#include <iconv.h>

#include <conio.h>
#include <fcntl.h>
#include <windows.h>
#include <windowsx.h>
#include <winuser.h>
#include <winnls.h>
#include <winternl.h>
#include <fileapi.h>
#include <TlHelp32.h>

#include "logging.h"
#include "syshandle.h"
#include "config_opts.h"

#define TT_INFO                 "INFO"
#define TT_DEBUG                "DEBUG"
#define TT_ERROR                "ERROR"
#define TT_WARNING              "WARNING"

#define MB_MSG_ERR(fmt, ...)    mb_printf(TT_ERROR, MB_ICONERROR | MB_OK, fmt, ##__VA_ARGS__)
#define MB_MSG_INFO(fmt, ...)   mb_printf(TT_INFO, MB_ICONINFORMATION | MB_OK, fmt, ##__VA_ARGS__)

#define MB_FUNC_ERR()           MB_MSG_ERR("%s:%d %s() failed", __FILE__, __LINE__, __func__)

#define ICONV_UTF8              "UTF-8"
#define ICONV_CP936             "CP936"
#ifdef __x86_64__
#define ICONV_WIN_WCHAR         "UTF-16LE"
#endif

int mb_printf(const char *title, UINT flags, const char *fmt, ...)
{
        char buf[1024] = { 0 };
        va_list args;

        va_start(args, fmt);

        vsnprintf(buf, sizeof(buf), fmt, args);

        MessageBox(NULL, buf, title, flags);

        va_end(args);

        return 0;
}

int iconv_convert(char *in, size_t in_len, const char *from, const char *to, char *out, size_t out_len)
{
        iconv_t cd;

        if (!in || !from || !to || !out || !in_len || !out_len)
                return -EINVAL;

        cd = iconv_open(to, from);
        if (cd == (iconv_t)-1) {
                if (errno == EINVAL)
                        pr_err("iconv does not support %s->%s\n", from, to);
                else
                        pr_err("iconv_open() failed, err = %d\n", errno);

                return -errno;
        }

        iconv(cd, &in, &in_len, &out, &out_len);

        if (iconv_close(cd) != 0)
                pr_err("iconv_close() failed\n");

        return 0;
}

static char locale_cp[64] = { 0 };
static int iconv_ok = 1;

int iconv_init(void)
{
        iconv_t t;

        snprintf(locale_cp, sizeof(locale_cp), "CP%u", GetACP());

        t = iconv_open(ICONV_UTF8, locale_cp);
        if (t == (iconv_t)-1) {
                pr_err("iconv does not support %s->%s\n", locale_cp, ICONV_UTF8);
                iconv_ok = 0;
        } else {
                iconv_close(t);
        }

        return 0;
}

int locale_to_utf8(char *in, size_t len_in, char *out, size_t out_len)
{
        return iconv_convert(in, len_in, locale_cp, ICONV_UTF8, out, out_len);
}

int iconv_strncmp(char *s1, char *c1, size_t l1, char *s2, char *c2, size_t l2, int *err)
{
        char *b1 = NULL;
        char *b2 = NULL;
        int ret = -EINVAL;
        int __err = 0;
        const int extra = 32;

        if (!s1 || !c1 || !s2 || !c2)
                return -EINVAL;

        if (strcasecmp(c1, ICONV_UTF8)) {
                b1 = calloc(l1 + extra, sizeof(char));
                if (!b1) {
                        __err = -ENOMEM;
                        goto out;
                }

                __err = iconv_convert(s1, l1, c1, ICONV_UTF8, b1, l1 + extra);
                if (__err)
                        goto out;

                s1 = b1;
                l1 += extra;
        }

        if (strcasecmp(c2, ICONV_UTF8)) {
                b2 = calloc(l2 + extra, sizeof(char));
                if (!b2) {
                        __err = -ENOMEM;
                        goto out;
                }

                __err = iconv_convert(s2, l2, c2, ICONV_UTF8, b2, l2 + extra);
                if (__err)
                        goto out;

                s2 = b2;
                l2 += extra;
        }

        ret = strncmp(s1, s2, (l1 > l2) ? l1 : l2);

out:
        if (b1)
                free(b1);

        if (b2)
                free(b2);

        if (err)
                *err = __err;

        return ret;
}

int iconv_strncmp_test(void)
{
        char ex1_cp936[] = {
                0x73,0x75,0x70,0x65,0x72,0x2d,0x74,0x68,
                0x72,0x65,0x61,0x64,0x20,0x2d,0x20,0xb9,
                0xfe,0xb9,0xfe,0xb9,0xfe,0x2e,0x65,0x78,
                0x65,0x00,0x00
        };
        char ex2_cp936[] = {
                0x73,0x75,0x70,0x65,0x72,0x2d,0x74,0x68,
                0x72,0x65,0x61,0x64,0x20,0x2d,0x20,0xb9,
                0xfe,0xb9,0xfe,0xb9,0xfe,0x2e,0x65,0x78,
                0x65,0x11,0x00
        };
        char ex1_utf8[] = "super-thread - 哈哈哈.exe";

        int ret;
        int err;

        ret = iconv_strncmp(ex1_cp936, "CP936", sizeof(ex1_cp936), ex2_cp936, "CP936", sizeof(ex2_cp936), &err);
        MB_MSG_ERR("%s(): ret: %d err: %d\n", __func__, ret, err);

        return 0;
}

int process_name_pid_resolve(char *name, size_t name_len, DWORD *pid)
{
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        int err = 0;

        if (snapshot == INVALID_HANDLE_VALUE) {
                MB_FUNC_ERR();
                return -EINVAL;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(snapshot, &pe32) == FALSE) {
                err = -ENOENT;
                goto out;
        }

        do {
                size_t exe_len = _countof(pe32.szExeFile);

                pr_info("pid: %6lu process name: %s\n", pe32.th32ProcessID, pe32.szExeFile);

                if (iconv_ok) {
                        int e, ret;

                        ret = iconv_strncmp(pe32.szExeFile, locale_cp, exe_len,
                                            name, ICONV_UTF8, name_len, &e);
                        if (e)
                                MB_MSG_ERR("iconv_strncmp() failed: %d\n", e);

                        if (!ret) {
                                if (pid)
                                        *pid = pe32.th32ProcessID;
                        }
                } else {
                        if (!strncmp(pe32.szExeFile, name, (exe_len > name_len) ? exe_len : name_len)) {
                                if (pid)
                                        *pid = pe32.th32ProcessID;
                        }
                }
        } while (Process32Next(snapshot, &pe32));

out:
        CloseHandle(snapshot);

        return err;
}

int process_module_list(DWORD pid)
{
        HANDLE hModuleSnap;
        MODULEENTRY32 me32;
        int ret = 0;

        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if (hModuleSnap == INVALID_HANDLE_VALUE) {
                MB_FUNC_ERR();
                return -EINVAL;
        }

        me32.dwSize = sizeof(MODULEENTRY32);

        if (!Module32First(hModuleSnap, &me32)) {
                MB_FUNC_ERR();
                ret = -EFAULT;
                goto out;
        }

        do {
                pr_info("pid: %5lu module name: %s executable: %s \n",
                        me32.th32ProcessID, me32.szModule, me32.szExePath);
        } while (Module32Next(hModuleSnap, &me32));

out:
        CloseHandle(hModuleSnap);

        return ret;
}

int process_thread_list(DWORD pid)
{
        HANDLE hThreadSnap;
        THREADENTRY32 te32;
        int ret = 0;

        hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap == INVALID_HANDLE_VALUE) {
                MB_FUNC_ERR();
                return -EINVAL;
        }

        te32.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(hThreadSnap, &te32)) {
                MB_FUNC_ERR();
                ret = -EINVAL;
                goto out;
        }

        do {
                if (te32.th32OwnerProcessID == pid) {
                        pr_info("tid: %5lu base_prio: %ld delta_prio: %ld\n",
                                te32.th32ThreadID, te32.tpBasePri, te32.tpDeltaPri);
                }
        } while (Thread32Next(hThreadSnap, &te32));

out:
        CloseHandle(hThreadSnap);

        return ret;
}

int process_cmdline_get(DWORD pid)
{
        HANDLE process, heap;
        PROCESS_BASIC_INFORMATION *pbi;
        ULONG pbi_sz;
        int ret = 0, nt_ret;

        process = OpenProcess(PROCESS_QUERY_INFORMATION |
                                PROCESS_QUERY_LIMITED_INFORMATION |
                                PROCESS_VM_READ,
                                FALSE,
                                pid);

        if (process == NULL) {
                pr_err("OpenProcess() failed, err=%lu\n", GetLastError());
                return -EFAULT;
        }

        heap = GetProcessHeap();
        pbi = HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(PROCESS_BASIC_INFORMATION));

        if (!pbi) {
                pr_err("failed to allocate memory for PBI\n");
                ret = -ENOMEM;
                goto out_handle;
        }

        nt_ret = NtQueryInformationProcess(process,
                                           ProcessBasicInformation,
                                           pbi,
                                           sizeof(PROCESS_BASIC_INFORMATION),
                                           &pbi_sz);
        if (nt_ret >= 0 && sizeof(PROCESS_BASIC_INFORMATION) < pbi_sz) {
                HeapFree(heap, 0, pbi);
                pbi = HeapAlloc(heap, HEAP_ZERO_MEMORY, pbi_sz);
                if (!pbi) {
                        pr_err("failed to allocate memory for PBI\n");
                        goto out_handle;
                }

                nt_ret = NtQueryInformationProcess(process,
                                                   ProcessBasicInformation,
                                                   pbi,
                                                   pbi_sz,
                                                   &pbi_sz);
        }

        if (!NT_SUCCESS(nt_ret)) {
                pr_err("NtQueryInformationProcess() err=%lu\n", GetLastError());
                ret = -EFAULT;
                goto out_free;
        }

        if (!pbi->PebBaseAddress) {
                pr_err("invalid PEB base address\n");
                ret = -EINVAL;
                goto out_free;
        }

        {
                PEB peb;
                RTL_USER_PROCESS_PARAMETERS cmdl_info;
                size_t nread;
                wchar_t *cmdl;

                if (0 == ReadProcessMemory(process, pbi->PebBaseAddress, &peb, sizeof(peb), &nread))
                        goto out_free;

                if (0 == ReadProcessMemory(process, peb.ProcessParameters, &cmdl_info, sizeof(cmdl_info), &nread))
                        goto out_free;

                cmdl = HeapAlloc(heap, HEAP_ZERO_MEMORY, cmdl_info.CommandLine.Length);
                if (!cmdl)
                        goto out_free;

                if (0 == ReadProcessMemory(process,
                                           cmdl_info.CommandLine.Buffer,
                                           cmdl,
                                           cmdl_info.CommandLine.Length,
                                           &nread)) {
                        HeapFree(heap, 0, cmdl);
                        goto out_free;
                }

                {
                        char utf8[256] = { 0 };
                        char cp936[256] = { 0 };

                        // this convert to utf8 but, with junk at the end
//                        wcstombs(wcc, cmdl, sizeof(wcc) < cmdl_info.CommandLine.Length ? sizeof(wcc) : cmdl_info.CommandLine.Length);

                        iconv_convert((void *)cmdl, cmdl_info.CommandLine.Length, ICONV_WIN_WCHAR, ICONV_UTF8, utf8, sizeof(utf8));
                        iconv_convert(utf8, strlen(utf8), ICONV_UTF8, ICONV_CP936, cp936, sizeof(cp936));

                        pr_info("iconv utf8: %s\n", utf8);
                        pr_info("iconv cp936: %s\n", cp936);
                }

                pr_info("pid: %lu cmdline: %.*ls\n", pid, cmdl_info.CommandLine.Length, cmdl);
        }

out_free:
        if (pbi)
                HeapFree(heap, 0, pbi);

out_handle:
        CloseHandle(process);

        return ret;
}

int system_process_list(void)
{
        HANDLE hProcessSnap;
        HANDLE hProcess;
        PROCESSENTRY32 pe32;
        DWORD dwPriorityClass;
        int ret = 0;

        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
                MB_FUNC_ERR();
                return -EINVAL;
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hProcessSnap, &pe32)) {
                MB_FUNC_ERR();
                ret = -EFAULT;
                goto out;
        }

        do {
                dwPriorityClass = 0;
                hProcess = OpenProcess(PROCESS_ALL_ACCESS |
                                        PROCESS_QUERY_INFORMATION |
                                        PROCESS_QUERY_LIMITED_INFORMATION,
                                        FALSE,
                                        pe32.th32ProcessID);
                if (hProcess) {
                        dwPriorityClass = GetPriorityClass(hProcess);
                        if (!dwPriorityClass)
                                pr_err("GetPriorityClass() failed for process %s\n", pe32.szExeFile);

                        CloseHandle(hProcess);
                }

                pr_info("pid: %5lu name: %s prio_class: %ld\n", pe32.th32ProcessID, pe32.szExeFile, dwPriorityClass);

                process_module_list(pe32.th32ProcessID);
                process_thread_list(pe32.th32ProcessID);
        } while (Process32Next(hProcessSnap, &pe32));

out:
        CloseHandle(hProcessSnap);

        return ret;
}

int iconv_test(void)
{
        char from[] = "哈哈哈";
        char to[100] = { 0 };
        char *f = from;
        char *t = to;
        size_t fs = strlen(from), ts = sizeof(to);
        iconv_t cd = iconv_open("CP936", ICONV_UTF8);

        if (cd == (iconv_t)-1) {
                if (errno == EINVAL)
                        pr_err("not support such conversion\n");
                else
                        pr_err("iconv_open() failed, err = %d\n", errno);

                return -errno;
        }

        iconv(cd, &f, &fs, &t, &ts);

        pr_err("original string: %s\n", from);
        pr_err("converted string: %s\n", to);

        if (iconv_close(cd) != 0)
                pr_err("iconv_close() error\n");

        return 0;
}

void iconv_test1()
{
//        char in[] = "御神木";
        char in[] = "~~TesT!!!!";
        char out[100] = { 0 };

        iconv_convert(in, sizeof(in), ICONV_UTF8, "CP936", out, sizeof(out));

        pr_err("%s(): in: %s\n", __func__, in);
        pr_err("%s(): out: %s\n", __func__, out);
}

void iconv_test2()
{
        char str_codepage[64] = { 0 };
        uint32_t codepage = GetACP();

        snprintf(str_codepage, sizeof(str_codepage), "CP%u", codepage);

        pr_err("current code page: %u\n", codepage);
}

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

int __privilege_get(const char *priv_name)
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

int privilege_get(void)
{
        static const char *sec_tokens[] = {
                SE_ASSIGNPRIMARYTOKEN_NAME,
                SE_DEBUG_NAME,
                SE_INC_BASE_PRIORITY_NAME,
        };

        int err;

        for (size_t i = 0; i < ARRAY_SIZE(sec_tokens); i++) {
                if ((err = __privilege_get(sec_tokens[i]))) {
                        pr_err("failed to request %s\n", sec_tokens[i]);
                        break;
                }
        }

        return err;
}

int group_affinity_get(HANDLE process, GROUP_AFFINITY *gf)
{
        PROCESS_BASIC_INFORMATION pbi;
        WORD *pgi;
        ULONG pgi_sz = sizeof(int64_t);
        HANDLE heap;
        ULONG needed;
        int ret = 0, nt_ret;

        if (INVALID_HANDLE_VALUE == process || !gf)
                return -EINVAL;

        heap = GetProcessHeap();
        pgi = HeapAlloc(heap, HEAP_ZERO_MEMORY, pgi_sz);

        nt_ret = NtQueryInformationProcess(process,
                                           ProcessGroupInformation,
                                           pgi,
                                           pgi_sz,
                                           &needed);
        if (!NT_SUCCESS(nt_ret)) {
                pr_err("failed to query process group info, err=%lu\n", GetLastError());
                return -EFAULT;
        }

        nt_ret = NtQueryInformationProcess(process,
                                           ProcessBasicInformation,
                                           &pbi,
                                           sizeof(pbi),
                                           &needed);
        if (!NT_SUCCESS(nt_ret)) {
                pr_err("failed to query process basic info\n");
                ret = -EFAULT;
                goto out;
        }

        memset(gf, 0x00, sizeof(GROUP_AFFINITY));
        gf->Mask = pbi.AffinityMask;
        gf->Group = *pgi;

out:
        HeapFree(heap, 0, pgi);

        return ret;
}

int group_affinity_set(HANDLE process, GROUP_AFFINITY *gf)
{
        int nt_ret;

        if (INVALID_HANDLE_VALUE == process || !gf)
                return -EINVAL;

        nt_ret = NtSetInformationProcess(process,
                                         ProcessAffinityMask,
                                         gf,
                                         sizeof(GROUP_AFFINITY));
        if (!NT_SUCCESS(nt_ret)) {
                pr_err("failed to set process affnity mask\n");
                return -EFAULT;
        }

        return 0;
}

void affinity_test(DWORD pid)
{
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS |
                                        PROCESS_QUERY_INFORMATION |
                                        PROCESS_QUERY_LIMITED_INFORMATION,
                                        FALSE,
                                        pid);
        GROUP_AFFINITY gf = { 0 };

        if (!process)
                return;

        if (group_affinity_get(process, &gf)) {
                pr_err("group_affinity_get() failed\n");
                return;
        }

        if (gf.Mask == 0) {
                pr_err("process is thread group affinity managed\n");
                return;
        }

        memset(&gf, 0x00, sizeof(gf));

        gf.Mask = 0xf;
        gf.Group = 1;

        group_affinity_set(process, &gf);

        CloseHandle(process);
}

static size_t active_processor_group;

int process_processor_group_get(DWORD pid, uint16_t *group_cnt, uint16_t **group_arr)
{
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE,
                                     pid);
        USHORT cnt;
        USHORT *arr;
        int err = 0;

        if (!process)
                return -ENOENT;

        if (GetProcessGroupAffinity(process, &cnt, NULL) == FALSE) {
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                        err = -EFAULT;
                        goto err_handle;
                }
        }

        arr = calloc(cnt, sizeof(USHORT));
        if (!arr) {
                err = -ENOMEM;
                goto err_handle;
        }

        if (FALSE == GetProcessGroupAffinity(process, &cnt, arr)) {
                err = -EFAULT;
                goto err_free;
        }

        if (group_cnt)
                *group_cnt = cnt;

        if (group_arr)
                *group_arr = arr;

        return err;

err_free:
        free(arr);

err_handle:
        CloseHandle(process);

        return err;
}

int process_group_check(DWORD pid)
{
        uint16_t group_cnt = 0;
        uint16_t *group_arr = NULL;
        int err = 0;

        if ((err = process_processor_group_get(pid, &group_cnt, &group_arr))) {
                pr_err("GetProcessGroupAffinity() failed\n");
                return err;
        }

        if (group_cnt > 1)
                pr_info("pid %lu is already multi-group!\n", pid);

        if (group_arr) {
                pr_info("pid %lu currently on group: ", pid);
                for (unsigned i = 0; i < group_cnt; i++) {
                        pr_raw("%hu ", group_arr[i]);
                }
                pr_raw("\n");
        }

        if (group_arr)
                free(group_arr);

        return err;
}

int thread_iterate(THREADENTRY32 te32)
{
        GROUP_AFFINITY affinity;
        HANDLE thread = OpenThread(THREAD_SET_INFORMATION |
                                   THREAD_QUERY_INFORMATION,
                                   FALSE,
                                   te32.th32ThreadID);
        int err = 0;

        if (!thread) {
                pr_err("OpenThread() failed, tid: %lu err=%lu\n",
                       te32.th32ThreadID, GetLastError());
                return -EFAULT;
        }

        if (0 == GetThreadGroupAffinity(thread, &affinity)) {
                pr_err("GetThreadGroupAffinity() failed, tid=%lu err=%lu\n",
                       te32.th32ThreadID, GetLastError());
                err = -EFAULT;
                goto out_handle;
        }

        pr_raw("tid: %6lu group: %2hu affinity: 0x%016zx\n", te32.th32ThreadID, affinity.Group, affinity.Mask);

//        {
//                unsigned cnt = rand() % 2;
//
//                affinity.Group = cnt;
//                affinity.Mask = 0xfff;
//
//                if (0 == SetThreadGroupAffinity(thread, &affinity, NULL))
//                        pr_err("SetThreadGroupAffinity() failed, tid=%lu err=%lu\n", te32.th32ThreadID, GetLastError());
//        }

out_handle:
        CloseHandle(thread);

        return err;
}

int thread_affinity_manage(DWORD pid)
{
        HANDLE snap;
        THREADENTRY32 te32;
        int err = 0;

        if ((err = process_group_check(pid)))
                return err;

        // @th32ProcessID is ignored in TH32CS_SNAPTHREAD
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) {
                pr_err("CreateToolhelp32Snapshot() failed, err=%lu\n", GetLastError());
                err = -EFAULT;
                goto out;
        }

        te32.dwSize = sizeof(THREADENTRY32);
        if (!Thread32First(snap, &te32)) {
                pr_err("Thread32First() failed\n");
                err = -EFAULT;
                goto out_handle;
        }

        pr_info("pid: %lu\n", pid);

        do {
                if (pid != te32.th32OwnerProcessID)
                        continue;

                thread_iterate(te32);
        } while(Thread32Next(snap, &te32));

out_handle:
        CloseHandle(snap);

out:
        return err;
}

int thread_affinity_manage_init(void)
{
        active_processor_group = GetActiveProcessorGroupCount();

        if (active_processor_group < 2) {
                pr_info("active processor group count %zu < 2\n", active_processor_group);
        }

        return 0;
}

int WINAPI WinMain(HINSTANCE ins, HINSTANCE prev_ins,
                   LPSTR cmdline, int cmdshow)
{
        (void)ins;
        (void)prev_ins;
        (void)cmdline;
        (void)cmdshow;
        MSG msg;

//        mb_printf("TEST", MB_ICONERROR | MB_OKCANCEL, "%s(): this is a %s\n0x%08x\n", __func__, "test", 0xc0cafe00);

        if (longopts_parse(__argc, __argv)) {
                goto out;
        }

        logging_init();
        iconv_init();

//        processor_topology_test();


//        tommy_hashit_test();

        MB_MSG_ERR("PRESS TO START");

        privilege_get();

        thread_affinity_manage_init();
        thread_affinity_manage(17356);

//        affinity_test(26012);

//        process_cmdline_get(14140);

//        system_handle_query();

//        {
//                char proc[] = "super-thread - 哈哈哈.exe";
//                DWORD pid;
//                process_name_pid_resolve(proc, sizeof(proc), &pid);
//        }

        //
        // MAIN PROCEDURE
        //

        while (GetMessage(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
        }

free_logging:
        logging_exit();

out:
        MB_MSG_INFO("DONE");

        return 0;
}
