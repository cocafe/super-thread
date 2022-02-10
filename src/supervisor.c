#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>

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
#include "sysinfo.h"
#include "supervisor.h"
#include "myntapi.h"
#include "superthread.h"

supervisor_t g_sv = { 0 };

static uint8_t priofile_proc_prio_cls[] = {
        [PROC_PRIO_UNCHANGED]           = ProcPrioClassUnknown,
        [PROC_PRIO_IDLE]                = ProcPrioClassIdle,
        [PROC_PRIO_NORMAL]              = ProcPrioClassNnormal,
        [PROC_PRIO_HIGH]                = ProcPrioClassHigh,
        [PROC_PRIO_REALTIME]            = ProcPrioClassRealtime,
        [PROC_PRIO_BELOW_NORMAL]        = ProcPrioClassBelowNormal,
        [PROC_PRIO_ABOVE_NORMAL]        = ProcPrioClassAboveNormal,
};

static int32_t profile_ioprio_ntval[] = {
        [IO_PRIO_UNCHANGED]             = 0,
        [IO_PRIO_VERY_LOW]              = IoPriorityVeryLow,
        [IO_PRIO_LOW]                   = IoPriorityLow,
        [IO_PRIO_NORMAL]                = IoPriorityNormal,
        [IO_PRIO_HIGH]                  = IoPriorityHigh,
};

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
                needed += 4096;
                pr_verbose("adjust allocate size to %lu\n", needed);
                goto try_again;
        }

        *info = __info;
        *size = sz;

        return ret;

err_free:
        free(__info);

        return ret;
}

/**
 * @param foreach: return non zero to break loop
 * @param data: userdata
 * @return 0 on success
 */
int system_handle_iterate(int (*foreach)(SYSTEM_HANDLE_ENTRY *, va_list arg), ...)
{
        SYSTEM_HANDLE_INFORMATION *hinfo;
        size_t sz;
        int err;
        va_list ap;

        if ((err = system_info_query((void **)&hinfo, SystemHandleInformation, &sz)))
                return err;

        va_start(ap, foreach);
        for (ULONG i = 0; i < hinfo->Count; i++) {
                SYSTEM_HANDLE_ENTRY *hdl = &hinfo->Handle[i];
                if ((err = foreach(hdl, ap)))
                        break;
        }
        va_end(ap);

        free(hinfo);

        return err;
}

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

int is_pid_tracked(tommy_hashtable *tbl, DWORD pid, wchar_t *exe_file)
{
        proc_entry_t *entry = tommy_hashtable_get(tbl, tommy_inthash_u32(pid));
        proc_info_t *info;

        if (entry == NULL)
                return 0;

        info = &entry->info;

        if (info->pid == pid && is_wstr_equal(info->name, exe_file))
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

                if (is_wstr_equal(str, to_match))
                        return 1;

                return 0;
        }

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

static inline proc_entry_t *proc_entry_alloc(void)
{
        return calloc(1, sizeof(proc_entry_t));
}

void proc_entry_init(proc_entry_t *entry, DWORD pid, wchar_t *proc_exe, size_t profile_idx)
{
        proc_info_t *info = &entry->info;

        entry->is_new = 1;
        entry->last_stamp = 0;

        entry->profile = &g_cfg.profiles[profile_idx];
        entry->profile_idx = profile_idx;

        info->pid = pid;
        wcsncpy(info->name, proc_exe, wcslen(proc_exe)); // check string len?

        tommy_hashtable_init(&entry->threads, THRD_HASH_TBL_BUCKET);
}

void proc_threads_tbl_free(void *data)
{
        if (data)
                free(data);
}

void proc_entry_free(proc_entry_t *entry)
{
        tommy_hashtable_foreach(&entry->threads, proc_threads_tbl_free);
        tommy_hashtable_done(&entry->threads);

        free(entry);
}

int proc_entry_init_insert(tommy_hashtable *tbl, DWORD pid, wchar_t *exe, size_t profile_idx)
{
        proc_entry_t *entry = NULL;

        entry = proc_entry_alloc();
        if (!entry) {
                pr_err("failed to allocate memory\n");
                return -ENOMEM;
        }

        proc_entry_init(entry, pid, exe, profile_idx);
        tommy_hashtable_insert(tbl, &entry->node, entry, tommy_inthash_u32(pid));

        return 0;
}

static int image_path_extract_file_name(DWORD pid, wchar_t *exe_name, size_t maxlen)
{
        wchar_t image_path[_MAX_PATH] = { 0 };
        wchar_t file_name[_MAX_FNAME] = { 0 };
        wchar_t ext_name[_MAX_EXT] = { 0 };
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS |
                                     PROCESS_QUERY_INFORMATION |
                                     PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE,
                                     pid);
        if (!process) {
                pr_verbose("OpenProcess() failed for pid %lu, err=%lu\n", pid, GetLastError());
                return -EFAULT;
        }

        if (0 == GetProcessImageFileName(process, image_path, sizeof(image_path))) {
                pr_err("GetProcessImageFileNameW() failed for pid %lu\n", pid);
                CloseHandle(process);
                return -EFAULT;
        }

        // WINDOWS SUCKS :)
        _wsplitpath(image_path, NULL, NULL, file_name, ext_name);

        // XXX: hardcoded _MAX_FNAME length
        swprintf(exe_name, maxlen, L"%ls%ls", file_name, ext_name);

        CloseHandle(process);

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

static int process_cmdl_read(HANDLE process, PROCESS_BASIC_INFORMATION *pbi, wchar_t **cmdl)
{
        PEB peb;
        RTL_USER_PROCESS_PARAMETERS cmdl_info = { 0 };
        size_t nread;
        wchar_t *buf;
        int err = 0;

        if (0 == ReadProcessMemory(process, pbi->PebBaseAddress, &peb, sizeof(peb), &nread)) {
                pr_dbg("ReadProcessMemory() failed on pbi->PebBaseAddress\n");
                return -EFAULT;
        }

        if (0 == ReadProcessMemory(process, peb.ProcessParameters, &cmdl_info, sizeof(cmdl_info), &nread)) {
                pr_dbg("ReadProcessMemory() failed on peb.ProcessParameters\n");
                return -EFAULT;
        }

        // this LENGTH is the MEMORY SIZE of the string
        buf = halloc(cmdl_info.CommandLine.Length + 4);
        if (!buf) {
                pr_err("heap alloc %hu bytes failed\n", cmdl_info.CommandLine.Length);
                return -EFAULT;
        }

        if (0 == ReadProcessMemory(process,
                                   cmdl_info.CommandLine.Buffer,
                                   buf,
                                   cmdl_info.CommandLine.Length,
                                   &nread)) {
                pr_dbg("ReadProcessMemory() failed on cmdl_info.CommandLine.Buffer\n");
                err = -EFAULT;
                goto out;
        }

        if (cmdl)
                *cmdl = buf;

out:
        if (err)
                hfree(buf);

        return err;
}

static int process_pbi_read(HANDLE process, PROCESS_BASIC_INFORMATION **ppbi)
{
        PROCESS_BASIC_INFORMATION *pbi;
        ULONG pbi_sz;
        int err, nt_ret = 0;

        if (ppbi)
                *ppbi = NULL;

        pbi = halloc(sizeof(PROCESS_BASIC_INFORMATION));

        if (!pbi) {
                pr_err("failed to allocate memory for PBI\n");
                return -ENOMEM;
        }

        nt_ret = NtQueryInformationProcess(process,
                                           ProcessBasicInformation,
                                           pbi,
                                           sizeof(PROCESS_BASIC_INFORMATION),
                                           &pbi_sz);
        if (nt_ret >= 0 && sizeof(PROCESS_BASIC_INFORMATION) < pbi_sz) {
                hfree(pbi);
                pbi = halloc(pbi_sz);
                if (!pbi) {
                        pr_err("failed to allocate memory for PBI\n");
                        return -ENOMEM;
                }

                nt_ret = NtQueryInformationProcess(process,
                                                   ProcessBasicInformation,
                                                   pbi,
                                                   pbi_sz,
                                                   &pbi_sz);
        }

        if (!NT_SUCCESS(nt_ret)) {
                pr_err("NtQueryInformationProcess() err=%lu\n", GetLastError());
                err = -EFAULT;
                goto out;
        }

        if (!pbi->PebBaseAddress) {
                pr_err("invalid PEB base address\n");
                err = -EINVAL;
                goto out;
        }

        if (ppbi)
                *ppbi = pbi;

out:
        if (pbi && err)
                hfree(pbi);

        return err;
}

/**
 * process_cmdline_read() - read process's cmdline
 *
 * @param pid: pid
 * @param cmdl: will be allocated if succeed, use hfree() to free externally
 * @return 0 on success with @cmdl allocated, otherwise @cmdl will be NULL
 */
int process_cmdline_read(DWORD pid, wchar_t **cmdl)
{
        PROCESS_BASIC_INFORMATION *pbi;
        HANDLE process;
        int err = 0;

        if (cmdl)
                *cmdl = NULL;

        process = OpenProcess(PROCESS_QUERY_INFORMATION |
                              PROCESS_QUERY_LIMITED_INFORMATION |
                              PROCESS_VM_READ,
                              FALSE,
                              pid);

        if (process == NULL) {
                pr_err("OpenProcess() failed, pid=%lu err=%lu\n", pid, GetLastError());
                return -EFAULT;
        }

        if ((err = process_pbi_read(process, &pbi)))
                goto out_process;

        if ((err = process_cmdl_read(process, pbi, cmdl)))
                goto out_pbi;

out_pbi:
        if (pbi)
                hfree(pbi);

out_process:
        CloseHandle(process);

        return err;
}

//
// XXX: this function may hang!!! use a detached thread to pull info, if timed out kill it?
//
static int is_file_handle_matched(SYSTEM_HANDLE_ENTRY *hdl, DWORD pid, struct proc_identity *id)
{
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

#if 0 // FAST PATH, not reliable
        {
                wchar_t path[MAX_PATH] = { 0 };

                // return ZERO on failure
                if (GetFinalPathNameByHandle(hdup, path, sizeof(path), VOLUME_NAME_DOS)) {
                        pr_verbose("pid: %lu hdl: %d hdup: %zu file_path: %ls\n", pid, hdl->HandleValue, (size_t)hdup, path);

                        if (is_str_match_id(path, id))
                                ret = 1;
                }
        }
#endif

#if 0
        {
                size_t name_sz = sizeof(FILE_NAME_INFO) + sizeof(wchar_t) * _MAX_FNAME;
                FILE_NAME_INFO *name_info = calloc(1, name_sz);
                FILE_BASIC_INFO basic_info;

                name_info->FileNameLength = _MAX_PATH;

                if (0 == GetFileInformationByHandleEx(hdup, FileBasicInfo, &basic_info, sizeof(basic_info)))
                        goto free;

                // return ZERO on failure
                if (GetFileInformationByHandleEx(hdup, FileNameInfo, name_info, name_sz)) {
                        if (is_str_match_id(name_info->FileName, id))
                                ret = 1;
                }

free:
                free(name_info);
        }
#endif

        {
                OBJECT_TYPE_INFORMATION *obj = NULL;
                ULONG sz = 0;

                NtQueryObject(hdup, ObjectTypeInformation, NULL, 0, &sz);
                if (sz == 0) {
                        pr_verbose("NtQueryObject() failed to query size, err = %lu\n", GetLastError());
                        goto out_handle;
                }

                obj = malloc(sz);
                if (!obj) {
                        pr_err("failed to allocate buf, size: %lu\n", sz);
                        goto out_handle;
                }

                nt_ret = NtQueryObject(hdup, ObjectTypeInformation, obj, sz, NULL);
                if (!NT_SUCCESS(nt_ret)) {
                        pr_verbose("NtQueryObject() failed, err=%lu\n", GetLastError());
                        goto out_free;
                }

                // pr_verbose("pid: %lu handle type: %.*ls\n", pid, obj->TypeName.Length, obj->TypeName.Buffer);

                if (wcscmp(obj->TypeName.Buffer, L"File") == 0) {
                        wchar_t path[_MAX_PATH] = { 0 };

                        // return ZERO on failure
                        if (GetFinalPathNameByHandle(hdup, path, sizeof(path), FILE_NAME_NORMALIZED)) {
                                pr_verbose("pid: %lu %.*ls: %ls\n", pid, obj->TypeName.Length, obj->TypeName.Buffer, path);

                                if (is_str_match_id(path, id))
                                        ret = 1;
                        }
                }

out_free:
                free(obj);
out_handle:
                ;
        }

        if (hdup && is_remote)
                CloseHandle(hdup);

        return ret;
}

static int _is_process_handle_matched(SYSTEM_HANDLE_ENTRY *hdl, va_list arg)
{
        struct proc_identity *id = NULL;
        int *matched = 0;
        DWORD pid = 0;

        id      = va_arg(arg, struct proc_identity *);
        pid     = va_arg(arg, DWORD);
        matched = va_arg(arg, int *);

        if (hdl->OwnerPid != pid)
                return 0;

        if (is_file_handle_matched(hdl, pid, id)) {
                *matched = 1;
                return 1; // to break system handle iteration
        }

        return 0;
}

int is_process_handle_matched(PROCESSENTRY32 *pe32, struct proc_identity *id)
{
        DWORD pid = pe32->th32ProcessID;
        int matched = 0;

        system_handle_iterate(_is_process_handle_matched, id, pid, &matched);

        return matched;
}

int is_process_cmdline_matched(PROCESSENTRY32 *pe32, struct proc_identity *id)
{
        DWORD pid = pe32->th32ProcessID;
        WCHAR *exe = pe32->szExeFile;
        wchar_t *cmdl = NULL;
        int matched = 0;

        process_cmdline_read(pid, &cmdl);

        if (!cmdl) {
                pr_info("failed to read cmdline of pid: %lu \"%ls\"\n", pid, exe);
                return 0;
        }

        if (is_str_match_id(cmdl, id))
                matched = 1;

        hfree(cmdl);

        return matched;
}

int is_process_properties_matched(PROCESSENTRY32 *pe32, struct proc_identity *id)
{
        int matched = 0;

        if (is_str_match_id(pe32->szExeFile, id)) {
                matched = 1;

                // if both cmdline and handle identity are defined,
                // both of them must be matched (&& logic)

                if (id->cmdl) {
                        matched = is_process_cmdline_matched(pe32, id->cmdl);

                        if (!matched)
                                goto out;
                }

                if (id->file_hdl) {
                        matched = is_process_handle_matched(pe32, id->file_hdl);

                        if (!matched)
                                goto out;
                }
        }

out:
        return matched;
}

int is_profile_matched(PROCESSENTRY32 *pe32, size_t *profile_idx)
{
        for (size_t i = 0; i < g_cfg.profile_cnt; i++) {
                profile_t *profile = &g_cfg.profiles[i];
                int matched = 0;

                if (!profile->enabled)
                        continue;

                for (size_t j = 0; j < profile->id_cnt; j++) {
                        struct proc_identity *id = &profile->id[j];

                        switch (profile->id->type) {
                        case IDENTITY_PROCESS_EXE:
                                if (is_process_properties_matched(pe32, id)) {
                                        matched = 1;
                                        goto out_matched;
                                }

                                break;

                        case IDENTITY_CMDLINE:
                                if (is_process_cmdline_matched(pe32, id)) {
                                        matched = 1;
                                        goto out_matched;
                                }

                                break;

                        case IDENTITY_FILE_HANDLE:
                                pr_notice("file handle is broken on system-wide search now\n");
                                break;

                        default:
                                break;
                        }
                }

out_matched:
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
                size_t profile_idx = 0;

                if (process_try_open(&pe32))
                        continue;

                if (is_pid_tracked(proc_selected, pe32.th32ProcessID, pe32.szExeFile)) {
                        pr_verbose("pid: %lu \"%ls\" is tracked\n",
                                   pe32.th32ProcessID, pe32.szExeFile);
                        continue;
                }

                if (!is_profile_matched(&pe32, &profile_idx)) {
                        pr_verbose("pid: %lu \"%ls\" did not match any profiles\n",
                                   pe32.th32ProcessID, pe32.szExeFile);
                        continue;
                }

                pr_info("pid: %lu \"%ls\" new process matched profile \"%ls\"\n",
                        pe32.th32ProcessID, pe32.szExeFile,
                        g_cfg.profiles[profile_idx].name);

                proc_entry_init_insert(proc_selected,
                                       pe32.th32ProcessID,
                                       pe32.szExeFile,
                                       profile_idx);
        } while (Process32Next(hProcessSnap, &pe32));

out:
        CloseHandle(hProcessSnap);

        return err;
}

void proc_hashit_iterate(tommy_hashtable *tbl)
{
        static const char *proc_prio_strs[] = {
                [ProcPrioClassUnknown]          = "unknown",
                [ProcPrioClassIdle]             = "idle",
                [ProcPrioClassNnormal]          = "normal",
                [ProcPrioClassHigh]             = "high",
                [ProcPrioClassRealtime]         = "realtime",
                [ProcPrioClassBelowNormal]      = "normal-",
                [ProcPrioClassAboveNormal]      = "normal+",
        };

        static const char *io_prio_strs[] = {
                [IoPriorityVeryLow]             = "very_low",
                [IoPriorityLow]                 = "low",
                [IoPriorityNormal]              = "normal",
                [IoPriorityHigh]                = "high",
                [IoPriorityCritical]            = "critical",
        };

        if (tbl->count == 0)
                return;

        pr_raw("+------------+-------+--------------------+-----------+---------+----------+------+--------------------+\n");
        pr_raw("| profile    | pid   | name               | proc prio | io prio | threaded | node | affinity           |\n");
        pr_raw("+------------+-------+--------------------+-----------+---------+----------+------+--------------------+\n");

        for (size_t i = 0; i < tbl->bucket_max; i++) {
                tommy_node *n = tbl->bucket[i];

                while (n) {
                        proc_entry_t *entry = n->data;
                        proc_info_t *info = &entry->info;
                        profile_t *profile = &g_cfg.profiles[entry->profile_idx];
                        uint8_t proc_prio = info->proc_prio.PriorityClass;
                        uint8_t io_prio = info->io_prio;
                        wchar_t profile_name[11] = { 0 };
                        wchar_t name[18] = { 0 };

                        wcsncpy(profile_name, profile->name, WCBUF_LEN(profile_name));
                        profile_name[WCBUF_LEN(profile_name) - 1] = L'\0';

                        wcsncpy(name, info->name, WCBUF_LEN(name));
                        name[WCBUF_LEN(name) - 1] = L'\0';

                        pr_raw("| %-10ls | %-5zu | %-18ls | %-9s | %-7s | %-8d | %-4d | 0x%016jx |\n",
                               profile_name,
                               info->pid,
                               name,
                               proc_prio < MaxProcPrioClasses ? proc_prio_strs[proc_prio] : "ERR",
                               io_prio < MaxIoPriorityTypes ? io_prio_strs[io_prio] : "ERR",
                               info->use_thread_affinity,
                               info->curr_aff.Group,
                               info->curr_aff.Mask);

                        n = n->next;
                }
        }

        pr_raw("+------------+-------+--------------------+-----------+---------+----------+------+--------------------+\n");
}

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

static void affinity_mask_limit(GROUP_AFFINITY *new_aff, uint64_t affinity, uint32_t group)
{
        struct cpu_grp_info *cpu_grp = &g_sys_info.cpu_grp[group];

        affinity &= cpu_grp->grp_mask;
        if (unlikely(affinity == 0))
                affinity = cpu_grp->grp_mask;

        memset(new_aff, 0x00, sizeof(GROUP_AFFINITY));
        new_aff->Mask = affinity;
        new_aff->Group = group;
}

static int process_sched_thread_affinity_set(DWORD tid, void *data)
{
        proc_entry_t *proc = ((struct thrd_aff_set_data *)data)->entry;
        GROUP_AFFINITY *new_aff = ((struct thrd_aff_set_data *)data)->aff;
        GROUP_AFFINITY *proc_aff = &proc->last_aff;
        GROUP_AFFINITY curr_aff;
        size_t pid = proc->info.pid;
        wchar_t *proc_name = proc->info.name;

        HANDLE thread = OpenThread(THREAD_SET_INFORMATION |
                                   THREAD_QUERY_INFORMATION,
                                   FALSE,
                                   tid);

        if (!thread) { // thread might just be closed
                pr_err("OpenThread() failed, tid=%lu pid=%zu name=\"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                goto out;
        }

        if (0 == GetThreadGroupAffinity(thread, &curr_aff)) {
                pr_err("GetThreadGroupAffinity() failed, tid=%lu pid=%zu name=\"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                goto out;
        }

        if (!proc->is_new && !proc->always_set) {
                if (proc_aff->Group == curr_aff.Group && proc_aff->Mask == curr_aff.Mask) {
                        pr_verbose("tid: %5lu pid: %5zu \"%ls\" affinity did not change\n", tid, pid, proc_name);
                        goto out;
                }
        }

        affinity_mask_limit(new_aff, new_aff->Mask, new_aff->Group);

        pr_rawlvl(DEBUG, "[tid: %5lu pid: %5zu \"%ls\"] set [group: %2hu affinity: 0x%016jx]\n",
                  tid, pid, proc_name, new_aff->Group, new_aff->Mask);

        if (0 == SetThreadGroupAffinity(thread, new_aff, NULL)) {
                pr_err("SetThreadGroupAffinity() failed, tid=%lu pid=%zu \"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
        }

out:
        CloseHandle(thread);

        return 0;
}

static int processes_sched_set_new_affinity(supervisor_t *sv, proc_entry_t *entry,
                                            HANDLE process, GROUP_AFFINITY *new_aff)
{
        proc_info_t *info = &entry->info;
        GROUP_AFFINITY *last_aff = &entry->last_aff;
        int err;

        if (!info->use_thread_affinity) {
                if (!entry->is_new && !entry->always_set) {
                        if (last_aff->Mask == info->curr_aff.Mask &&
                            last_aff->Group == info->curr_aff.Group) {
                                pr_verbose("pid: %5zu \"%ls\" group affinity did not change, skip\n",
                                           info->pid, info->name);

                                return 0;
                        }
                }

                affinity_mask_limit(new_aff, new_aff->Mask, new_aff->Group);

                pr_rawlvl(DEBUG, "[pid: %5zu \"%ls\"] set [group %hu affinity 0x%016jx]\n",
                          info->pid, info->name, new_aff->Group, new_aff->Mask);

                err = proc_group_affinity_set(process, new_aff);
        } else {
                struct thrd_aff_set_data data = {
                        .sv = sv,
                        .entry = entry,
                        .aff = new_aff,
                };

                err = process_threads_iterate(info->pid, process_sched_thread_affinity_set, &data);
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
                                       SIZE_TO_BITS(profile->processes.node_map));

        return processes_sched_set_new_affinity(sv, entry, process, &new_aff);;
}

static unsigned long node_map_next(unsigned long curr, unsigned long mask)
{
        unsigned long supported_mask = NODE_MAP_SUPPORT_MASK;

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

        val->node_map_next = node_map_next(val->node_map_next, node_map);

        affinity_mask_limit(&new_aff, profile->processes.affinity,
                            find_first_bit(&val->node_map_next, SIZE_TO_BITS(val->node_map_next)));

        err = processes_sched_set_new_affinity(sv, entry, process, &new_aff);

        return err;
}

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

        return 0;
}

static void thread_node_map_update(supervisor_t *sv, proc_entry_t *proc, GROUP_AFFINITY *new_aff)
{
        profile_t *profile = proc->profile;
        unsigned long node_map = profile->threads.node_map;
        struct thrds_sched *val = &(sv->vals[proc->profile_idx].u.thrds_sched);

        val->node_map_next = node_map_next(val->node_map_next, node_map);

        affinity_mask_limit(new_aff, profile->threads.affinity,
                            find_first_bit(&val->node_map_next, SIZE_TO_BITS(val->node_map_next)));

}

static thrd_entry_t *thrd_entry_get(tommy_hashtable *tbl, DWORD tid, DWORD pid)
{
        thrd_entry_t *entry = tommy_hashtable_get(tbl, tommy_inthash_u32(tid));
        if (!entry)
                return NULL;

        if (entry->tid == tid && entry->pid == pid)
                return entry;

        return NULL;
}

static int thread_node_rr_affinity_set(DWORD tid, void *data)
{
        supervisor_t *sv = ((struct thrd_aff_set_data *)data)->sv;
        proc_entry_t *proc = ((struct thrd_aff_set_data *)data)->entry;
        thrd_entry_t *thrd_entry = thrd_entry_get(&proc->threads, tid, proc->info.pid);
        wchar_t *proc_name = proc->info.name;
        size_t pid = proc->info.pid;
        GROUP_AFFINITY curr_aff, new_aff = { 0 };
        int delete = 0;

        HANDLE thrd_hdl = OpenThread(THREAD_SET_INFORMATION |
                                     THREAD_QUERY_INFORMATION,
                                     FALSE,
                                     tid);

        if (!thrd_hdl) { // thread might just be closed
                pr_err("OpenThread() failed, tid=%lu pid=%zu name=\"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                if (thrd_entry)
                        delete = 1;

                goto not_exist;
        }

        if (0 == GetThreadGroupAffinity(thrd_hdl, &curr_aff)) {
                pr_err("GetThreadGroupAffinity() failed, tid=%lu pid=%zu name=\"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                if (thrd_entry)
                        delete = 1;

                goto out;
        }

        // new thread
        if (!thrd_entry) {
                thrd_entry = calloc(1, sizeof(thrd_entry_t));
                if (!thrd_entry) {
                        goto out;
                }

                thrd_entry->tid = tid;
                thrd_entry->pid = proc->info.pid;
                tommy_hashtable_insert(&proc->threads, &thrd_entry->node, thrd_entry, tommy_inthash_u32(tid));
        } else { // old thread
                GROUP_AFFINITY *last_aff = &thrd_entry->last_aff;

                if (!proc->is_new && !proc->always_set) {
                        if (last_aff->Group == curr_aff.Group &&
                            last_aff->Mask == curr_aff.Mask) {
                                pr_verbose("tid: %5lu pid: %5zu \"%ls\" affinity did not change\n", tid, pid,
                                           proc_name);
                                goto out;
                        }
                }
        }

        thread_node_map_update(sv, proc, &new_aff);

        pr_rawlvl(DEBUG, "[tid: %5lu pid: %5zu \"%ls\"] set [group: %2hu affinity: 0x%016jx]\n",
                  tid, pid, proc_name, new_aff.Group, new_aff.Mask);

        if (0 == SetThreadGroupAffinity(thrd_hdl, &new_aff, NULL)) {
                pr_err("SetThreadGroupAffinity() failed, tid=%lu pid=%zu \"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                delete = 1;

                goto out;
        }

        memcpy(&thrd_entry->last_aff, &new_aff, sizeof(thrd_entry->last_aff));

out:
        thrd_entry->last_stamp = sv->update_stamp;

        CloseHandle(thrd_hdl);

not_exist:
        if (thrd_entry && delete) {
                tommy_node *n = &thrd_entry->node;

                pr_dbg("[tid: %5lu pid: %5zu \"%ls\"] delete thread\n", tid, pid, proc_name);

                tommy_hashtable_remove_existing(&proc->threads, n);
                free(thrd_entry);
        }

        return 0;
}

static int threads_sched_node_rr(supervisor_t *sv, proc_entry_t *entry)
{
        struct thrd_aff_set_data data = {
                .sv = sv,
                .entry = entry,
        };

        return process_threads_iterate(entry->info.pid, thread_node_rr_affinity_set, &data);
}

static void dead_thread_entry_remove(supervisor_t *sv, proc_entry_t *proc_entry)
{
        tommy_hashtable *thrd_tbl = &proc_entry->threads;

        if (thrd_tbl->count == 0) {
                pr_verbose("pid: %5zu \"%ls\" does not have thread tracked\n",
                           proc_entry->info.pid, proc_entry->info.name);
                return;
        }

        for (size_t i = 0; i < thrd_tbl->bucket_max; i++) {
                tommy_node *n = thrd_tbl->bucket[i];

                while (n) {
                        tommy_node *next = n->next;

                        thrd_entry_t *thrd_entry = n->data;

                        if (thrd_entry->last_stamp != sv->update_stamp) {
                                pr_dbg("remove dead thread: tid: %5zu pid: %5zu \"%ls\"\n",
                                       thrd_entry->tid, thrd_entry->pid, proc_entry->info.name);

                                tommy_hashtable_remove_existing(thrd_tbl, n);
                                free(n->data);
                        }

                        n = next;
                }
        }
}

static int supervisor_threads_sched(supervisor_t *sv, proc_entry_t *entry)
{
        switch (entry->profile->threads.balance) {
        case THRD_BALANCE_CPU_RR:
                break;

        case THRD_BALANCE_NODE_RR:
                threads_sched_node_rr(sv, entry);
                break;

        case THRD_BALANCE_RAND:
                break;

        case THRD_BALANCE_ONLOAD:
        default:
                pr_err("invalid balance mode\n");
                return -EINVAL;
        }

        dead_thread_entry_remove(sv, entry);

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

static int _profile_settings_apply(supervisor_t *sv, proc_entry_t *entry)
{
        proc_info_t *info = &entry->info;
        profile_t *profile = entry->profile;
        wchar_t exe_name[_MAX_FNAME] = { 0 };
        int err = 0;
        DWORD status;
        HANDLE process;

        if (!profile) {
                pr_err("profile == NULL\n");
                return -EINVAL;
        }

        // XXX: some dead processes still can be opened
        process = OpenProcess(PROCESS_ALL_ACCESS |
                              PROCESS_QUERY_INFORMATION |
                              PROCESS_QUERY_LIMITED_INFORMATION,
                              FALSE,
                              info->pid);
        if (!process) {
                pr_info("OpenProcess() failed, pid %zu \"%ls\", err=%lu, maybe dead?\n",
                        info->pid, info->name, GetLastError());
                return -ENOENT;
        }

        if (0 == GetExitCodeProcess(process, &status)) {
                pr_info("GetExitCodeProcess() failed, pid %zu \"%ls\", err=%lu\n",
                        info->pid, info->name, GetLastError());
                err = -EFAULT;
                goto out;
        }

        if (status != STILL_ACTIVE) {
                pr_info("pid %zu \"%ls\" is no longer existed\n", info->pid, info->name);
                err = -ENOENT;
                goto out;
        }

        // allow disabling profile on the fly
        if (!profile->enabled)
                goto out;

        if (image_path_extract_file_name(entry->info.pid, exe_name, _MAX_FNAME))
                goto out;

        if ((err = process_info_update(info, process))) {
                pr_err("failed to update info for pid %zu \"%ls\"\n", info->pid, info->name);
                goto out;
        }

        if (!entry->is_new && !is_wstr_equal(info->name, exe_name)) {
                err = -EINVAL;
                goto out;
        }

        if (profile->oneshot && entry->oneshot)
                goto out;

        if ((err = profile_proc_prio_set(profile, process)))
                goto out;

        if ((err = profile_prio_ioprio_set(profile, process)))
                goto out;

        switch (profile->sched_mode) {
        case SUPERVISOR_PROCESSES:
                err = supervisor_processes_sched(sv, entry, process);
                break;

        case SUPERVISOR_THREADS:
                err = supervisor_threads_sched(sv, entry);
                break;

        default:
                pr_err("invalid sched mode\n");
                err = -EINVAL;
                break;
        }

        // update again after applying settings
        if ((err = process_info_update(info, process)))
                pr_err("failed to update info for pid %zu \"%ls\"\n", info->pid, info->name);

        entry->is_new = 0;
        entry->oneshot = profile->oneshot;
        entry->always_set = profile->always_set;

out:
        entry->last_stamp = sv->update_stamp;

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

                        err = _profile_settings_apply(sv, n->data);
                        if (err) {
                                proc_entry_t *proc = n->data;
                                pr_dbg("pid: %5zu \"%ls\" delete process\n",
                                       proc->info.pid, proc->info.name);

                                tommy_hashtable_remove_existing(tbl, n);
                                proc_entry_free(n->data);
                        }

                        n = next;
                }
        }

        return 0;
}

static int process_list_add_by_handle(tommy_hashtable *tbl, SYSTEM_HANDLE_ENTRY *hdl, wchar_t *exe_name)
{
        profile_t *profile;
        size_t idx;
        DWORD pid;
        int matched = 0;

        for (idx = 0; idx < g_cfg.profile_cnt; idx++) {
                profile = &g_cfg.profiles[idx];
                pid = hdl->OwnerPid;

                if (!profile->enabled)
                        continue;

                for (size_t j = 0; j < profile->id_cnt; j++) {
                        struct proc_identity *id = &profile->id[j];

                        if (id->type != IDENTITY_FILE_HANDLE)
                                continue;

                        if (is_file_handle_matched(hdl, pid, id)) {
                                matched = 1;
                                break;
                        }
                }

                if (matched)
                        break;
        }

        if (matched)
                proc_entry_init_insert(tbl, pid, exe_name, idx);

        return 0;
}

static int file_handle_check_insert(SYSTEM_HANDLE_ENTRY *hdl, va_list ap)
{
        wchar_t exe_name[_MAX_FNAME] = { 0 };
        supervisor_t *sv = va_arg(ap, supervisor_t *);
        tommy_hashtable *processes = &sv->proc_selected;
        DWORD owner_pid = hdl->OwnerPid;
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS |
                                     PROCESS_QUERY_INFORMATION |
                                     PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE,
                                     owner_pid);
        if (!process) {
                pr_verbose("OpenProcess() failed for pid %lu, err=%lu\n", owner_pid, GetLastError());
                return 0;
        }

        if (image_path_extract_file_name(owner_pid, exe_name, _MAX_FNAME))
                goto out;

        if (is_pid_tracked(processes, owner_pid, exe_name))
                goto out;

        process_list_add_by_handle(processes, hdl, exe_name);

out:
        CloseHandle(process);

        return 0;
}

int file_handle_search_insert(supervisor_t *sv)
{
        int err = 0;

        if ((err = system_handle_iterate(file_handle_check_insert, sv)))
                return err;

        return err;
}

int supervisor_loop(supervisor_t *sv)
{
        tommy_hashtable *proc_selected = &sv->proc_selected;
        int err;

        if ((err = process_list_build(sv)))
                return err;

//        if ((err = file_handle_search_insert(sv))
//                return err;

        profile_settings_apply(sv);

        if (g_logprint_level & LOG_LEVEL_DEBUG)
                proc_hashit_iterate(proc_selected);

        // dead processes will be detected and removed in next round

        return 0;
}

void *supervisor_woker(void *data)
{
        struct timespec ts = { 0 };
        supervisor_t *sv = data;

        sv->update_stamp = 1;

        pr_info("START\n");

        while (1) {
                int err;

                if (g_should_exit)
                        break;

                if (sv->paused)
                        goto sleep;

                pr_verbose("update_stamp: %d\n", sv->update_stamp);

                supervisor_loop(sv);

                sv->update_stamp++;
                if (unlikely(sv->update_stamp == 0)) // overflowed
                        sv->update_stamp = 1;

                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += g_cfg.sampling_sec; // set next wake up point

sleep:
                // return -1 on failed with errno set
                if ((err = sem_timedwait(&sv->sleeper, &ts))) {
                        if (errno != ETIMEDOUT) {
                                pr_err("sem_timedwait() failed, err=%d\n", err);
                                usleep(2 * 1000 * 1000);
                        }
                }
        }

        pthread_exit(NULL);

        return NULL;
}

void supervisor_trigger_once(supervisor_t *sv)
{
        if (sv->tid_worker == 0)
                return;

        if (sv->paused)
                return;

        pthread_mutex_lock(&sv->trigger_lck);
        sem_post(&sv->sleeper);
        pthread_mutex_unlock(&sv->trigger_lck);
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

        sem_init(&sv->sleeper, 0, 0);
        pthread_mutex_init(&sv->trigger_lck, NULL);
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
        sem_post(&sv->sleeper);

        if (sv->tid_worker)
                pthread_join(sv->tid_worker, NULL);

        if (sv->vals)
                free(sv->vals);

        tommy_hashtable_foreach(&sv->proc_selected, proc_selected_free);
        tommy_hashtable_done(&sv->proc_selected);

        pthread_mutex_destroy(&sv->trigger_lck);
        sem_destroy(&sv->sleeper);

        return 0;
}
