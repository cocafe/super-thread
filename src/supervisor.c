#include <stdint.h>
#include <string.h>
#include <pthread.h>

#include <windows.h>
#include <windowsx.h>
#include <winuser.h>
#include <winnls.h>
#include <winternl.h>
#include <fileapi.h>
#include <TlHelp32.h>
#include <processthreadsapi.h>

#include <libgen.h>

#include <tommy.h>
#include <psapi.h>

#include "config.h"
#include "logging.h"
#include "supervisor.h"
#include "myntapi.h"

static void *tommy_hashtable_get(tommy_hashtable *tbl, tommy_hash_t hash)
{
        tommy_node *n = tommy_hashtable_bucket(tbl, hash);

        while (n) {
                if (n->index == hash)
                        return n->data;

                n = n->next;
        }

        return NULL;
}

static inline proc_entry_t *proc_entry_alloc(void)
{
        return calloc(1, sizeof(proc_entry_t));
}

void proc_entry_init(proc_entry_t *entry, PROCESSENTRY32 *pe32, size_t profile_idx)
{
        proc_info_t *info = &entry->info;

        entry->is_new = 1;

        entry->profile = &g_cfg.profiles[profile_idx];
        entry->profile_idx = profile_idx;

        info->pid = pe32->th32ProcessID;
        wcsncpy(info->name, pe32->szExeFile, wcslen(pe32->szExeFile));

//        tommy_hashtable_init(&entry->threads, THRD_HASH_TBL_BUCKET);
}

//void proc_threads_tbl_free(void *data)
//{
//        if (data)
//                free(data);
//}

void proc_entry_free(proc_entry_t *entry)
{
//        tommy_hashtable_foreach(&entry->threads, proc_threads_tbl_free);
//        tommy_hashtable_done(&entry->threads);
        free(entry);
}

#if 0
static int process_processor_group_get(DWORD pid, uint16_t *group_cnt, uint16_t **group_arr)
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

                if (iconv_locale_ok) {
                        int e, ret;

                        ret = iconv_strncmp(pe32.szExeFile, iconv_locale_cp(), exe_len,
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
#endif

int thread_group_affinity_set(DWORD tid, GROUP_AFFINITY *affinity)
{
        HANDLE thread = OpenThread(THREAD_SET_INFORMATION |
                                   THREAD_QUERY_INFORMATION,
                                   FALSE,
                                   tid);

        if (!thread) {
                pr_err("OpenThread() failed, tid=%lu err=%lu\n", tid, GetLastError());
                return 0; // thread might just be closed
        }

        if (0 == SetThreadGroupAffinity(thread, affinity, NULL))
                pr_err("SetThreadGroupAffinity() failed, tid=%lu err=%lu\n", tid, GetLastError());

        CloseHandle(thread);

        return 0;
}

static int process_threads_iterate(DWORD pid, int (*func)(DWORD tid, void *), void *data)
{
        HANDLE snap;
        THREADENTRY32 te32;
        int err = 0;

        if (!func)
                return -EINVAL;

        // @th32ProcessID is ignored in TH32CS_SNAPTHREAD
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) {
                pr_err("CreateToolhelp32Snapshot() failed, err=%lu\n", GetLastError());
                return -EFAULT;
        }

        te32.dwSize = sizeof(THREADENTRY32);
        if (!Thread32First(snap, &te32)) {
                pr_err("Thread32First() failed\n");
                err = -EFAULT;
                goto out_handle;
        }

        do {
                if (pid != te32.th32OwnerProcessID)
                        continue;

                if ((err = func(te32.th32ThreadID, data)))
                        break;

        } while(Thread32Next(snap, &te32));

out_handle:
        CloseHandle(snap);

        return err;
}

static int proc_group_affinity_get(HANDLE process, GROUP_AFFINITY *gf)
{
        PROCESS_BASIC_INFORMATION pbi;
        WORD *pgi;
        ULONG pgi_sz = sizeof(int64_t);
        HANDLE heap;
        ULONG needed;
        int ret = 0, status;

        if (INVALID_HANDLE_VALUE == process || !gf)
                return -EINVAL;

        heap = GetProcessHeap();
        pgi = HeapAlloc(heap, HEAP_ZERO_MEMORY, pgi_sz);

        status = NtQueryInformationProcess(process,
                                           ProcessGroupInformation,
                                           pgi,
                                           pgi_sz,
                                           &needed);
        if (!NT_SUCCESS(status)) {
                pr_err("failed to query process group info, err=%lu\n", GetLastError());
                return -EFAULT;
        }

        status = NtQueryInformationProcess(process,
                                           ProcessBasicInformation,
                                           &pbi,
                                           sizeof(pbi),
                                           &needed);
        if (!NT_SUCCESS(status)) {
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

static int proc_group_affinity_set(HANDLE process, GROUP_AFFINITY *gf)
{
        int status;

        if (INVALID_HANDLE_VALUE == process || !gf)
                return -EINVAL;

        status = NtSetInformationProcess(process,
                                         ProcessAffinityMask,
                                         gf,
                                         sizeof(GROUP_AFFINITY));
        if (!NT_SUCCESS(status)) {
                pr_err("failed to set process affinity mask\n");
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

        if (proc_group_affinity_get(process, &gf)) {
                pr_err("proc_group_affinity_get() failed\n");
                return;
        }

        if (gf.Mask == 0) {
                pr_err("process is thread group affinity managed\n");
                return;
        }

        memset(&gf, 0x00, sizeof(gf));

        gf.Mask = 0xf;
        gf.Group = 1;

        proc_group_affinity_set(process, &gf);

        CloseHandle(process);
}

#if 0
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

        // @th32ProcessID: only for TH32CS_SNAPHEAPLIST/SNAPMODULE/SNAPMODULE32/SNAPALL
        // TH32CS_SHAPTHREAD: always iterate whole system threads
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
#endif

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

                        iconv_wc2utf8((void *)cmdl, cmdl_info.CommandLine.Length, utf8, sizeof(utf8));
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

int process_io_prio_get(HANDLE process, IO_PRIORITY_HINT *io_prio)
{
        int status = NtQueryInformationProcess(process,
                                               ProcessIoPriority,
                                               io_prio,
                                               sizeof(IO_PRIORITY_HINT),
                                               NULL);
        if (!NT_SUCCESS(status)) {
                pr_err("NtQueryInformationProcess(): ProcessIoPriority failed, status=0x%08x\n", status);
                return -EFAULT;
        }

        return 0;
}

int process_io_prio_set(HANDLE process, IO_PRIORITY_HINT *io_prio)
{
        int status = NtSetInformationProcess(process,
                                             ProcessIoPriority,
                                             io_prio,
                                             sizeof(IO_PRIORITY_HINT)
                                             );
        if (!NT_SUCCESS(status)) {
                pr_err("NtQueryInformationProcess(): ProcessIoPriority failed, status=0x%08x\n", status);
                return -EFAULT;
        }

        return 0;
}

int process_prio_cls_get(HANDLE process, PROCESS_PRIORITY_CLASS *prio_cls)
{
        int status = NtQueryInformationProcess(process,
                                               ProcessPriorityClass,
                                               prio_cls,
                                               sizeof(PROCESS_PRIORITY_CLASS),
                                               NULL
                                               );
        if (!NT_SUCCESS(status)) {
                pr_err("NtQueryInformationProcess(): ProcessPriorityClass failed, status=0x%08x\n", status);
                return -EFAULT;
        }

        return 0;
}

int process_prio_cls_set(HANDLE process, PROCESS_PRIORITY_CLASS *prio_cls)
{
        int status = NtSetInformationProcess(process,
                                             ProcessPriorityClass,
                                             prio_cls,
                                             sizeof(PROCESS_PRIORITY_CLASS)
                                             );
        if (!NT_SUCCESS(status)) {
                pr_err("NtSetInformationProcess(): PriocessPriorityClass failed, status=0x%08x\n", status);
                return -EFAULT;
        }

        return 0;
}

int is_pid_tracked(tommy_hashtable *tbl, PROCESSENTRY32 *pe32)
{
        /*
        size_t pid = pe32->th32ProcessID;
        tommy_hash_t hash = tommy_inthash_u32(pid);
        tommy_node *n = tommy_hashtable_bucket(tbl, hash);

        while (n) {
                proc_entry_t *entry = n->data;
                proc_info_t *info = &entry->info;

                if (info->pid == pid && !wcsncmp(info->name, pe32->szExeFile, wcslen(info->name)))
                        return 1;

                n = n->next;
        }
         */


        size_t pid = pe32->th32ProcessID;
        proc_entry_t *entry = tommy_hashtable_get(tbl, tommy_inthash_u32(pid));
        proc_info_t *info;

        if (entry == NULL)
                return 0;

        info = &entry->info;

        if (info->pid == pid && !wcsncmp(info->name, pe32->szExeFile, wcslen(info->name)))
                return 1;

        pr_err("hash matched but pid & process exe mismatched!\n");

        return 0;
}

int is_str_match_id(wchar_t *str, struct proc_identity *id)
{
        if (id->filter == STR_FILTER_CONTAIN) {
                wchar_t *sub_str = id->value;

                if (!sub_str)
                        return 0;

                if (wcsstr(str, sub_str))
                        return 1;

                return 0;
        }

        if (id->filter == STR_FILTER_IS) {
                wchar_t *to_match = id->value;

                if (!to_match)
                        return 0;

                if (!wcsncmp(str, to_match, wcslen(str)))
                        return 1;

                return 0;
        }

        return 0;
}

static int is_file_handle_match(SYSTEM_HANDLE_ENTRY *hdl, DWORD pid, struct proc_identity *id)
{
        wchar_t path[MAX_PATH] = { 0 };
        int ret = 0, nt_ret = 0;
        int is_remote = pid != GetCurrentProcessId();

        // case for owner is self
        HANDLE hdup = (void *)((size_t)hdl->HandleValue);

        if (is_remote) {
                HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
                if (!process) {
                        pr_err("OpenProcess() failed, pid: %lu\n", pid);
                        return 0;
                }

                nt_ret = DuplicateHandle(process,
                                         (HANDLE)((size_t)hdl->HandleValue),
                                         GetCurrentProcess(),
                                         &hdup,
                                         0,
                                         FALSE,
                                         DUPLICATE_SAME_ACCESS);

                CloseHandle(process);

                if (!NT_SUCCESS(nt_ret)) {
                        pr_dbg("DuplicateHandle() failed, err: %lu pid: %lu\n", GetLastError(), pid);
                        return 0;
                }
        }

        ret = 0;

        // return ZERO on failure
        if (GetFinalPathNameByHandle(hdup, path, sizeof(path), VOLUME_NAME_DOS)) {
                // XXX: the PATH is CODE PAGEd
                pr_dbg("pid: %lu hdl: %d hdup: %zu file_path: %ls\n", pid, hdl->HandleValue, (size_t)hdup, path);

                if (is_str_match_id(path, id))
                        ret = 1;
        }

        if (hdup && is_remote)
                CloseHandle(hdup);

        return ret;
}

static int system_info_query(void **info, SYSTEM_INFORMATION_CLASS type, size_t *size)
{
        void *__info = NULL;
        size_t sz = 0x2000; // sizeof(SYSTEM_HANDLE_INFORMATION)
        unsigned long needed = 0;
        int ret = 0;

        if (!(*info)) {
                pr_err("info must be empty\n");
                return -EINVAL;
        }

try_again:
        if (needed) // when try again, needed is set probably
                sz = needed;

        __info = calloc(1, sz);
        if (!__info) {
                pr_err("failed to allocate memory");
                return -ENOMEM;
        }

        NTSTATUS status = NtQuerySystemInformation(type, __info, sz, &needed);
        if (!NT_SUCCESS(status)) {
                if (needed == 0 || needed == sz) {
                        pr_err("unknown error!\n");
                        ret = -EFAULT;
                        goto err_free;
                }

                free(__info);
                needed += 1024;
                pr_dbg("adjust allocate size to %lu\n", needed);
                goto try_again;
        }

        *info = __info;
        *size = sz;

        return ret;

err_free:
        free(__info);

        return ret;
}

static int is_pid_has_file_handle(DWORD pid, struct proc_identity *id)
{
        SYSTEM_HANDLE_INFORMATION *hinfo;
        size_t sz;
        int err;

        if ((err = system_info_query((void **)&hinfo, SystemHandleInformation, &sz)))
                return err;

        for (ULONG i = 0; i < hinfo->Count; i++) {
                SYSTEM_HANDLE_ENTRY *h = &hinfo->Handle[i];

                if (h->OwnerPid != pid)
                        continue;

                if (is_file_handle_match(h, pid, id))
                        return 1;
        }

        free(hinfo);

        return 0;
}

int is_profile_matched(PROCESSENTRY32 *pe32, size_t *profile_idx)
{
        size_t pid = pe32->th32ProcessID;

        for (size_t i = 0; i < g_cfg.profile_cnt; i++) {
                profile_t *profile = &g_cfg.profiles[i];
                int matched = 0;

                if (!profile->enabled)
                        continue;

                for (size_t j = 0; j < profile->id_cnt; j++) {
                        struct proc_identity *id = &profile->id[j];

                        switch (profile->id->type) {
                        case IDENTITY_PROCESS_EXE:
                                if (is_str_match_id(pe32->szExeFile, id)) {
                                        matched = 1;
                                        goto out_id_cmp;
                                }

                                break;

                        case IDENTITY_FILE_HANDLE:
                                if (is_pid_has_file_handle(pid, id)) {
                                        matched = 1;
                                        goto out_id_cmp;
                                }

                                break;

                        case IDENTITY_CMDLINE:
                                break;

                        default:
                                break;
                        }
                }

out_id_cmp:
                if (matched) {
                        if (profile_idx)
                                *profile_idx = i;

                        return 1;
                }
        }

        return 0;
}

int process_try_open(PROCESSENTRY32 *pe32)
{
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS |
                                     PROCESS_QUERY_INFORMATION |
                                     PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE,
                                     pe32->th32ProcessID);
        if (!process) {
                pr_verbose("OpenProcess() failed for pid %lu \"%ls\", err=%lu\n",
                           pe32->th32ProcessID, pe32->szExeFile, GetLastError());
                return -EINVAL;
        }

        CloseHandle(process);

        return 0;
}

int process_list_build(supervisor_t *sv)
{
        HANDLE hProcessSnap;
        PROCESSENTRY32 pe32;
        tommy_hashtable *proc_selected = &sv->proc_selected;
        int err = 0;

        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
                pr_err("CreateToolhelp32Snapshot() failed: %lu\n", GetLastError());
                return -EINVAL;
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hProcessSnap, &pe32)) {
                pr_err("Process32First() failed\n");
                err = -EFAULT;
                goto out;
        }

        do {
                proc_entry_t *entry = NULL;
                size_t profile_idx = 0;

                if (process_try_open(&pe32))
                        continue;

                if (is_pid_tracked(proc_selected, &pe32))
                        continue;

                if (!is_profile_matched(&pe32, &profile_idx))
                        continue;

                entry = proc_entry_alloc();
                if (!entry) {
                        pr_err("failed to allocate memory\n");
                        err = -ENOMEM;
                        goto out;
                }

                pr_info("pid: %lu \"%ls\" matched profile \"%s\"\n",
                        pe32.th32ProcessID, pe32.szExeFile,
                        g_cfg.profiles[profile_idx].name);

                proc_entry_init(entry, &pe32, profile_idx);

                tommy_hashtable_insert(proc_selected, &entry->node, entry,
                                       tommy_inthash_u32(pe32.th32ProcessID));

        } while (Process32Next(hProcessSnap, &pe32));

out:
        CloseHandle(hProcessSnap);

        return err;
}

//void proc_track_iterate(void *data)
//{
//        proc_entry_t *entry = data;
//        proc_info_t *info = &entry->info;
//
//        pr_info("pid: %5zu name: %s proc_prio: %zd io_prio: %zd\n",
//                info->pid, info->name, info->proc_prio, info->io_prio);
//}

void proc_hashit_iterate(tommy_hashtable *tbl)
{
        for (size_t i = 0; i < tbl->bucket_max; i++) {
                tommy_node *n = tbl->bucket[i];

                while (n) {
                        proc_entry_t *entry = n->data;
                        proc_info_t *info = &entry->info;

                        pr_info("bucket[%zu] === pid: %5zu name: \"%ls\" proc_prio: %hhu io_prio: %d\n",
                                i, info->pid, info->name, info->proc_prio.PriorityClass, info->io_prio);

                        n = n->next;
                }
        }
}

static uint8_t priofile_proc_prio_cls[] = {
        [PROC_PRIO_UNCHANGED]           = PROCESS_PRIORITY_CLASS_UNKNOWN,
        [PROC_PRIO_IDLE]                = PROCESS_PRIORITY_CLASS_IDLE,
        [PROC_PRIO_NORMAL]              = PROCESS_PRIORITY_CLASS_NORMAL,
        [PROC_PRIO_HIGH]                = PROCESS_PRIORITY_CLASS_HIGH,
        [PROC_PRIO_REALTIME]            = PROCESS_PRIORITY_CLASS_REALTIME,
        [PROC_PRIO_BELOW_NORMAL]        = PROCESS_PRIORITY_CLASS_BELOW_NORMAL,
        [PROC_PRIO_ABOVE_NORMAL]        = PROCESS_PRIORITY_CLASS_ABOVE_NORMAL,
};

static int32_t profile_ioprio_ntval[] = {
        [IO_PRIO_UNCHANGED]             = 0,
        [IO_PRIO_VERY_LOW]              = IoPriorityVeryLow,
        [IO_PRIO_LOW]                   = IoPriorityLow,
        [IO_PRIO_NORMAL]                = IoPriorityNormal,
        [IO_PRIO_HIGH]                  = IoPriorityHigh,
};

int profile_proc_prio_set(profile_t *profile, HANDLE process)
{
        PROCESS_PRIORITY_CLASS prio_class __attribute__((aligned(4))) = { 0 };

        if (profile->proc_prio >= NUM_PROC_PRIOS)
                return -EINVAL;

        if (profile->proc_prio == PROC_PRIO_UNCHANGED)
                return 0;

        prio_class.PriorityClass = priofile_proc_prio_cls[profile->proc_prio];

        if (process_prio_cls_set(process, &prio_class))
                return -EFAULT;

        return 0;
}

int profile_prio_ioprio_set(profile_t *profile, HANDLE process)
{
        IO_PRIORITY_HINT io_prio;

        if (profile->io_prio >= NUM_IO_PRIOS)
                return -EINVAL;

        if (profile->io_prio == IO_PRIO_UNCHANGED)
                return 0;

        io_prio = profile_ioprio_ntval[profile->io_prio];

        if (process_io_prio_set(process, &io_prio))
                return -EFAULT;

        return 0;
}

int is_image_path_contains(HANDLE process, proc_info_t *info)
{
        wchar_t image_path[MAX_PATH] = { 0 };

        if (0 == GetProcessImageFileName(process, image_path, sizeof(image_path))) {
                pr_err("GetProcessImageFileNameW() failed for pid %zu \"%ls\"\n", info->pid, info->name);
                return 0;
        }

        // rare case maybe, different process start with pid that stored early
        if (!wcsstr(image_path, info->name)) {
                pr_info("abort, pid %zu has different process name: \"%ls\" \"%ls\"\n", info->pid, info->name, image_path);
                return 0;
        }

        return 1;
}

thrd_entry_t *thrd_entry_get(tommy_hashtable *tbl, DWORD tid, DWORD pid)
{
        thrd_entry_t *entry = tommy_hashtable_get(tbl, tommy_inthash_u32(tid));
        if (!entry)
                return NULL;

        if (entry->tid == tid && entry->pid == pid)
                return entry;

        return NULL;
}

struct thrd_aff_set_data {
        supervisor_t *sv;
        proc_entry_t *entry;
        GROUP_AFFINITY *aff;
};

#if 0
static int sched_thread_affinity_set(DWORD tid, void *data)
{
        supervisor_t *sv = ((struct thrd_aff_set_data *)data)->sv;
        proc_entry_t *proc = ((struct thrd_aff_set_data *)data)->entry;
        GROUP_AFFINITY *new_aff = ((struct thrd_aff_set_data *)data)->aff;
        thrd_entry_t *thrd_entry = thrd_entry_get(&proc->threads, tid, proc->info.pid);
        size_t pid = proc->info.pid;
        wchar_t *proc_name = proc->info.name;
        GROUP_AFFINITY curr_aff;
        int delete = 0, err = 0;
        HANDLE thrd_hdl = OpenThread(THREAD_SET_INFORMATION |
                                     THREAD_QUERY_INFORMATION,
                                     FALSE,
                                     tid);

        if (!thrd_hdl) { // thread might just be closed
                pr_err("OpenThread() failed, tid=%lu pid=%zu name=\"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                err = -EFAULT;
                if (thrd_entry)
                        delete = 1;

                goto not_exist;
        }

        if (0 == GetThreadGroupAffinity(thrd_hdl, &curr_aff)) {
                pr_err("GetThreadGroupAffinity() failed, tid=%lu pid=%zu name=\"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                err = -EFAULT;
                if (thrd_entry)
                        delete = 1;

                goto out;
        }

        // new thread
        if (!thrd_entry) {
                thrd_entry = calloc(1, sizeof(thrd_entry_t));
                if (!thrd_entry) {
                        err = -ENOMEM;
                        goto out;
                }

                thrd_entry->tid = tid;
                thrd_entry->pid = proc->info.pid;
                tommy_hashtable_insert(&proc->threads, &thrd_entry->node, thrd_entry, tommy_inthash_u32(tid));
        } else { // old thread
                GROUP_AFFINITY *last_aff = &thrd_entry->last_aff;

                if (last_aff->Group == curr_aff.Group && last_aff->Mask == curr_aff.Mask) {
                        pr_dbg("tid: %5lu pid: %5zu \"%ls\" affinity did not change\n", tid, pid, proc_name);
                        goto out;
                }
        }

        pr_dbg("tid: %5lu pid: %5zu \"%ls\" set node: %hu affinity: 0x%016jx\n",
               tid, pid, proc_name, new_aff->Group, new_aff->Mask);

        if (0 == SetThreadGroupAffinity(thrd_hdl, new_aff, NULL)) {
                pr_err("SetThreadGroupAffinity() failed, tid=%lu pid=%zu \"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                err = -EFAULT;
                delete = 1;

                goto out;
        }

        memcpy(&thrd_entry->last_aff, &curr_aff, sizeof(GROUP_AFFINITY));

out:
        thrd_entry->last_update = sv->update_stamp;

        CloseHandle(thrd_hdl);

not_exist:
        if (thrd_entry && delete) {
                tommy_node *n = &thrd_entry->node;

                pr_dbg("delete tid: %5lu pid: %5zu\n", tid, pid);

                tommy_hashtable_remove_existing(&proc->threads, n);
                free(thrd_entry);
        }

        return err;
}
#endif

static int sched_thread_affinity_set(DWORD tid, void *data)
{
        proc_entry_t *proc = ((struct thrd_aff_set_data *)data)->entry;
        GROUP_AFFINITY *new_aff = ((struct thrd_aff_set_data *)data)->aff;
        GROUP_AFFINITY *proc_aff = &proc->last_aff;
        GROUP_AFFINITY curr_aff;
        size_t pid = proc->info.pid;
        wchar_t *proc_name = proc->info.name;
        int err = 0;

        HANDLE thread = OpenThread(THREAD_SET_INFORMATION |
                                   THREAD_QUERY_INFORMATION,
                                   FALSE,
                                   tid);

        if (!thread) { // thread might just be closed
                pr_err("OpenThread() failed, tid=%lu pid=%zu name=\"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                err = -EFAULT;
                goto out;
        }

        if (0 == GetThreadGroupAffinity(thread, &curr_aff)) {
                pr_err("GetThreadGroupAffinity() failed, tid=%lu pid=%zu name=\"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                err = -EFAULT;
                goto out;
        }

        if (proc_aff->Group == curr_aff.Group && proc_aff->Mask == curr_aff.Mask) {
                pr_verbose("tid: %5lu pid: %5zu \"%ls\" affinity did not change\n", tid, pid, proc_name);
                goto out;
        }

        pr_dbg("set [group: %2hu affinity: 0x%016jx] for [tid: %5lu pid: %5zu \"%ls\"] \n",
               new_aff->Group, new_aff->Mask, tid, pid, proc_name);

        if (0 == SetThreadGroupAffinity(thread, new_aff, NULL)) {
                pr_err("SetThreadGroupAffinity() failed, tid=%lu pid=%zu \"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                err = -EFAULT;
        }

out:
        CloseHandle(thread);

        return err;
}

static int processes_sched_set_new_affinity(supervisor_t *sv, proc_entry_t *entry,
                                            HANDLE process, GROUP_AFFINITY *new_aff)
{
        proc_info_t *info = &entry->info;
        GROUP_AFFINITY *last_aff = &entry->last_aff;
        int err;

        if (!info->use_thread_affinity) {
                if (!entry->is_new) {
                        if (last_aff->Mask == info->curr_aff.Mask &&
                            last_aff->Group == info->curr_aff.Group) {
                                pr_verbose("pid: %5zu \"%ls\" group affinity did not change, skip\n",
                                           info->pid, info->name);

                                return 0;
                        }
                }

                pr_info("set [group %hu affinity 0x%016jx] for [pid: %5zu \"%ls\"] \n",
                        new_aff->Group, new_aff->Mask, info->pid, info->name);
                err = proc_group_affinity_set(process, new_aff);
        } else {
                struct thrd_aff_set_data data = {
                        .sv = sv,
                        .entry = entry,
                        .aff = new_aff,
                };

                err = process_threads_iterate(info->pid, sched_thread_affinity_set, &data);
        }

        if (entry->is_new) {
                memcpy(last_aff, new_aff, sizeof(GROUP_AFFINITY));
        }

        return err;
}

static int processes_sched_by_map(supervisor_t *sv, proc_entry_t *entry, HANDLE process)
{
        profile_t *profile = entry->profile;
        GROUP_AFFINITY new_aff = { 0 };

        new_aff.Mask = profile->processes.affinity;
        new_aff.Group = find_first_bit((void *)&profile->processes.node_map,
                                       sizeof(profile->processes.node_map));

        return processes_sched_set_new_affinity(sv, entry, process, &new_aff);;
}

static unsigned long node_map_next(unsigned long curr, unsigned long mask)
{
        unsigned long supported_mask = GENMASK((MAX_PROC_GROUPS - 1), 0);

        for (int i = 0; i < (MAX_PROC_GROUPS * 2); i++) {
                curr = curr << 1;

                // overflow, reset
                if ((curr & supported_mask) == 0)
                        curr = 1;

                if ((curr & mask) != 0)
                        break;
        }

        return curr;
}

static int processes_sched_rr(supervisor_t *sv, proc_entry_t *entry, HANDLE process)
{
        profile_t *profile = entry->profile;
        unsigned long node_map = profile->processes.node_map;
        struct procs_sched *val = &(sv->vals[entry->profile_idx].u.procs_sched);
        GROUP_AFFINITY new_aff = { 0 };
        int err;

        // init for the first time
        if (!val->node_map_init) {
                val->node_map_init = 1 << find_first_bit(&node_map, sizeof(node_map));
                val->node_map_next = val->node_map_init;
        }

        new_aff.Mask = profile->processes.affinity;
        new_aff.Group = find_first_bit(&val->node_map_next, sizeof(val->node_map_next));

        err = processes_sched_set_new_affinity(sv, entry, process, &new_aff);

        val->node_map_next = node_map_next(val->node_map_next, node_map);

        return err;
}

//static void dead_thread_entry_remove(supervisor_t *sv, proc_entry_t *proc_entry)
//{
//        tommy_hashtable *thrd_tbl = &proc_entry->threads;
//
//        if (thrd_tbl->count == 0) {
//                pr_verbose("pid: %5zu \"%ls\" does not have thread tracked\n",
//                           proc_entry->info.pid, proc_entry->info.name);
//                return;
//        }
//
//        for (size_t i = 0; i < thrd_tbl->bucket_max; i++) {
//                tommy_node *n = thrd_tbl->bucket[i];
//
//                while (n) {
//                        tommy_node *next = n->next;
//
//                        thrd_entry_t *thrd_entry = n->data;
//
//                        if (thrd_entry->last_update != sv->update_stamp) {
//                                pr_dbg("remove dead thread: tid: %5zu pid: %5zu \"%ls\"\n",
//                                       thrd_entry->tid, thrd_entry->pid, proc_entry->info.name);
//                                tommy_hashtable_remove_existing(thrd_tbl, n);
//                                free(n->data);
//                        }
//
//                        n = next;
//                }
//        }
//}

static int supervisor_processes_sched(supervisor_t *sv, proc_entry_t *entry, HANDLE process)
{
        // DO NOT CHECK ERROR RETURN
        // since there are multiple processes

        switch (entry->profile->processes.balance) {
        case PROC_BALANCE_BY_MAP:
                processes_sched_by_map(sv, entry, process);
                break;

        case PROC_BALANCE_RR:
                processes_sched_rr(sv, entry, process);
                break;

        case PROC_BALANCE_RAND:
                break;

        case PROC_BALANCE_ONLOAD:
        default:
                pr_err("invalid balance mode\n");
                return -EINVAL;
        }

//        dead_thread_entry_remove(sv, entry);

        return 0;
}

static int process_info_update(proc_info_t *info, HANDLE process)
{
        int err;

        if ((err = process_io_prio_get(process, &info->io_prio)))
                return err;

        if ((err = process_prio_cls_get(process, &info->proc_prio)))
                return err;

        if ((err = proc_group_affinity_get(process, &info->curr_aff)))
                return err;

        info->use_thread_affinity = 0;
        if (info->curr_aff.Mask == 0)
                info->use_thread_affinity = 1;

        return err;
}

static int __profile_settings_apply(supervisor_t *sv, proc_entry_t *entry)
{
        proc_info_t *info = &entry->info;
        profile_t *profile = entry->profile;
        int err = 0;
        HANDLE process;

        if (!profile) {
                pr_err("profile == NULL\n");
                return -EINVAL;
        }

        process = OpenProcess(PROCESS_ALL_ACCESS |
                              PROCESS_QUERY_INFORMATION |
                              PROCESS_QUERY_LIMITED_INFORMATION,
                              FALSE,
                              info->pid);
        if (!process) {
                pr_err("OpenProcess() failed for pid %zu \"%ls\"\n", info->pid, info->name);
                return -ENOENT;
        }

        if (!entry->is_new && !is_image_path_contains(process, info)) {
                err = -EINVAL;
                goto out;
        }

        if ((err = process_info_update(info, process))) {
                pr_err("failed to update info for pid %zu \"%ls\"\n", info->pid, info->name);
                goto out;
        }

        if ((err = profile_proc_prio_set(profile, process)))
                goto out;

        if ((err = profile_prio_ioprio_set(profile, process)))
                goto out;

        if (profile->granularity == SUPERVISOR_PROCESSES) {
                if ((err = supervisor_processes_sched(sv, entry, process)))
                        goto out;
        }

        entry->is_new = 0;

out:
        CloseHandle(process);

        return err;
}

static int profile_settings_apply(supervisor_t *sv)
{
        tommy_hashtable *tbl = &sv->proc_selected;
        int err;

        // FOR EACH ENTRY
        //      OPEN PROCESS, IS SUCCESS?
        //              SET BY PROFILE SETTINGS
        //      ELSE
        //              DELETE (PROC TERMINATED?)

        for (size_t i = 0; i < tbl->bucket_max; i++) {
                tommy_node *n = tbl->bucket[i];

                while (n) {
                        tommy_node *next = n->next;

                        err = __profile_settings_apply(sv, n->data);
                        if (err) {
                                tommy_hashtable_remove_existing(tbl, n);
                                proc_entry_free(n->data);
                        }

                        n = next;
                }
        }

        return 0;
}

int supervisor_loop(supervisor_t *sv)
{
        tommy_hashtable *proc_selected = &sv->proc_selected;
        int err;

        if ((err = process_list_build(sv)))
                return err;

        printf("----------------------------------\n");

//        tommy_hashtable_foreach(proc_track, proc_track_iterate);

        profile_settings_apply(sv);

        proc_hashit_iterate(proc_selected);

        // dead processes will be detected and removed in next round

        return 0;
}

void *supervisor_woker(void *data)
{
        supervisor_t *sv = data;
        sv->update_stamp = 1;

        while (1) {
                printf("update_stamp: %d\n", sv->update_stamp);

                supervisor_loop(sv);

                sv->update_stamp++;
                if (unlikely(sv->update_stamp == 0)) // overflowed
                        sv->update_stamp = 1;

                usleep(g_cfg.sampling_ms * 1000);
        }

        pthread_exit(NULL);
}

int supervisor_run(supervisor_t *sv)
{
        int err = 0;

        if ((err = pthread_create(&sv->tid_worker, NULL, supervisor_woker, sv)))
                return err;

        return 0;
}

int supervisor_init(supervisor_t *sv)
{
        size_t profile_cnt = g_cfg.profile_cnt;

        sv->active_proc_grp = GetActiveProcessorGroupCount();

        if (sv->active_proc_grp < 2)
                pr_notice("active processor group count %zu < 2\n", sv->active_proc_grp);

        tommy_hashtable_init(&sv->proc_selected, PROC_HASH_TBL_BUCKET);

        sv->vals = NULL;
        if (profile_cnt) {
                sv->vals = calloc(profile_cnt, sizeof(supervisor_val_t));
                if (!sv->vals) {
                        pr_err("failed to allocate memory\n");
                        return -ENOMEM;
                }
        }

        return 0;
}

static void proc_selected_free(void *data)
{
        proc_entry_free(data);
}

int supervisor_deinit(supervisor_t *sv)
{
        if (sv->tid_worker)
                pthread_join(sv->tid_worker, NULL);

        if (sv->vals)
                free(sv->vals);

        tommy_hashtable_foreach(&sv->proc_selected, proc_selected_free);
        tommy_hashtable_done(&sv->proc_selected);

        return 0;
}
