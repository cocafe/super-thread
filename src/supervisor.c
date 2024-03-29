#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>

#include <windows.h>
#include <winuser.h>
#include <winnls.h>
#include <winternl.h>
#include <fileapi.h>
#include <TlHelp32.h>
#include <processthreadsapi.h>
#include <psapi.h>

#include <tommyds/tommy.h>

#include <libjj/logging.h>
#include <libjj/malloc.h>
#include <libjj/utils.h>
#include <libjj/ffs.h>
#include <libjj/iconv.h>

#include "config.h"
#include "sysinfo.h"
#include "superthread.h"

typedef BOOL (*GetProcessDefaultCpuSetMasks)(HANDLE Process,
                                             PGROUP_AFFINITY CpuSetMasks,
                                             USHORT CpuSetMaskCount,
                                             PUSHORT RequiredMaskCount);

typedef BOOL (*SetProcessDefaultCpuSetMasks)(HANDLE Process,
                                             PGROUP_AFFINITY CpuSetMasks,
                                             USHORT CpuSetMaskCount);

supervisor_t g_sv = { 0 };

static HINSTANCE krnl_dll;

static GetProcessDefaultCpuSetMasks _GetProcessDefaultCpuSetMasks;
static SetProcessDefaultCpuSetMasks _SetProcessDefaultCpuSetMasks;

static uint8_t profile_proc_prio_cls[] = {
        [PROC_PRIO_CLS_UNCHANGED]       = ProcPrioClassUnknown,
        [PROC_PRIO_CLS_IDLE]            = ProcPrioClassIdle,
        [PROC_PRIO_CLS_BELOW_NORMAL]    = ProcPrioClassBelowNormal,
        [PROC_PRIO_CLS_NORMAL]          = ProcPrioClassNormal,
        [PROC_PRIO_CLS_ABOVE_NORMAL]    = ProcPrioClassAboveNormal,
        [PROC_PRIO_CLS_HIGH]            = ProcPrioClassHigh,
        [PROC_PRIO_CLS_REALTIME]        = ProcPrioClassRealtime,
};

static uint8_t proc_prio_cls_profile[] = {
        [ProcPrioClassUnknown]          = PROC_PRIO_CLS_UNCHANGED,
        [ProcPrioClassIdle]             = PROC_PRIO_CLS_IDLE,
        [ProcPrioClassNormal]           = PROC_PRIO_CLS_NORMAL,
        [ProcPrioClassHigh]             = PROC_PRIO_CLS_HIGH,
        [ProcPrioClassRealtime]         = PROC_PRIO_CLS_REALTIME,
        [ProcPrioClassBelowNormal]      = PROC_PRIO_CLS_BELOW_NORMAL,
        [ProcPrioClassAboveNormal]      = PROC_PRIO_CLS_ABOVE_NORMAL,
};

static int32_t profile_ioprio_ntval[] = {
        [IO_PRIO_UNCHANGED]             = 0,
        [IO_PRIO_VERY_LOW]              = IoPriorityVeryLow,
        [IO_PRIO_LOW]                   = IoPriorityLow,
        [IO_PRIO_NORMAL]                = IoPriorityNormal,
        [IO_PRIO_HIGH]                  = IoPriorityHigh,
};

static ULONG profile_page_prio_ntval[] = {
        [PAGE_PRIO_UNCHANGED]           = 0,
        [PAGE_PRIO_NORMAL]              = MEMORY_PRIORITY_NORMAL,
        [PAGE_PRIO_BELOW_NORMAL]        = MEMORY_PRIORITY_BELOW_NORMAL,
        [PAGE_PRIO_MEDIUM]              = MEMORY_PRIORITY_MEDIUM,
        [PAGE_PRIO_LOW]                 = MEMORY_PRIORITY_LOW,
        [PAGE_PRIO_VERY_LOW]            = MEMORY_PRIORITY_VERY_LOW,
        [PAGE_PRIO_LOWEST]              = MEMORY_PRIORITY_LOWEST,
};

static const char *proc_prio_strs[] = {
        [ProcPrioClassUnknown]          = "unknown",
        [ProcPrioClassIdle]             = "idle",
        [ProcPrioClassNormal]           = "normal",
        [ProcPrioClassHigh]             = "high",
        [ProcPrioClassRealtime]         = "rt",
        [ProcPrioClassBelowNormal]      = "normal-",
        [ProcPrioClassAboveNormal]      = "normal+",
};

static const char *io_prio_strs[] = {
        [IoPriorityVeryLow]             = "low-",
        [IoPriorityLow]                 = "low",
        [IoPriorityNormal]              = "normal",
        [IoPriorityHigh]                = "high",
        [IoPriorityCritical]            = "crit",
};

static const char *page_prio_strs[] = {
        [MEMORY_PRIORITY_LOWEST]        = "low--",
        [MEMORY_PRIORITY_VERY_LOW]      = "low-",
        [MEMORY_PRIORITY_LOW]           = "low",
        [MEMORY_PRIORITY_MEDIUM]        = "medium",
        [MEMORY_PRIORITY_BELOW_NORMAL]  = "normal-",
        [MEMORY_PRIORITY_NORMAL]        = "normal",
};

static const char *prio_level_strs[] = {
        [THRD_PRIO_LVL_UNCHANGED]       = "invalid",
        [THRD_PRIO_LVL_IDLE]            = "idle",
        [THRD_PRIO_LVL_LOWEST]          = "lowest",
        [THRD_PRIO_LVL_BELOW_NORMAL]    = "normal-",
        [THRD_PRIO_LVL_NORMAL]          = "normal",
        [THRD_PRIO_LVL_ABOVE_NORMAL]    = "normal+",
        [THRD_PRIO_LVL_HIGHEST]         = "highest",
        [THRD_PRIO_LVL_TIME_CRITICAL]   = "timecrit",
};

static int thread_prio_level_cfgval(int nt_value)
{
        switch (nt_value) {
        case THREAD_PRIORITY_IDLE:
                return THRD_PRIO_LVL_IDLE;

        case THREAD_PRIORITY_LOWEST:
                return THRD_PRIO_LVL_LOWEST;

        case THREAD_PRIORITY_BELOW_NORMAL:
                return THRD_PRIO_LVL_BELOW_NORMAL;

        case THREAD_PRIORITY_NORMAL:
                return THRD_PRIO_LVL_NORMAL;

        case THREAD_PRIORITY_ABOVE_NORMAL:
                return THRD_PRIO_LVL_ABOVE_NORMAL;

        case THREAD_PRIORITY_HIGHEST:
                return THRD_PRIO_LVL_HIGHEST;

        case THREAD_PRIORITY_TIME_CRITICAL:
                return THRD_PRIO_LVL_TIME_CRITICAL;

        case THREAD_PRIORITY_ERROR_RETURN:
        default:
                return -1;
        }
}

static int thread_prio_level_ntval[] = {
        [THRD_PRIO_LVL_UNCHANGED]       = THREAD_PRIORITY_ERROR_RETURN,
        [THRD_PRIO_LVL_IDLE]            = THREAD_PRIORITY_IDLE,
        [THRD_PRIO_LVL_LOWEST]          = THREAD_PRIORITY_LOWEST,
        [THRD_PRIO_LVL_BELOW_NORMAL]    = THREAD_PRIORITY_BELOW_NORMAL,
        [THRD_PRIO_LVL_NORMAL]          = THREAD_PRIORITY_NORMAL,
        [THRD_PRIO_LVL_ABOVE_NORMAL]    = THREAD_PRIORITY_ABOVE_NORMAL,
        [THRD_PRIO_LVL_HIGHEST]         = THREAD_PRIORITY_HIGHEST,
        [THRD_PRIO_LVL_TIME_CRITICAL]   = THREAD_PRIORITY_TIME_CRITICAL,
};

/**
 * https://docs.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities
 *
 * scheduler use thread base priority (0~31[highest]) to determine scheduling.
 *
 * thread base priority is determined by:
 *      o process priority class
 *      o thread priority level
 *
 */
static uint8_t thread_base_priority[NUM_PROC_PRIO_CLASS][NUM_THRD_PRIO_LEVELS] = {
        [PROC_PRIO_CLS_IDLE]    = {
                [THRD_PRIO_LVL_IDLE]            = 1,
                [THRD_PRIO_LVL_LOWEST]          = 2,
                [THRD_PRIO_LVL_BELOW_NORMAL]    = 3,
                [THRD_PRIO_LVL_NORMAL]          = 4,
                [THRD_PRIO_LVL_ABOVE_NORMAL]    = 5,
                [THRD_PRIO_LVL_HIGHEST]         = 6,
                [THRD_PRIO_LVL_TIME_CRITICAL]   = 15,
        },
        [PROC_PRIO_CLS_BELOW_NORMAL]    = {
                [THRD_PRIO_LVL_IDLE]            = 1,
                [THRD_PRIO_LVL_LOWEST]          = 4,
                [THRD_PRIO_LVL_BELOW_NORMAL]    = 5,
                [THRD_PRIO_LVL_NORMAL]          = 6,
                [THRD_PRIO_LVL_ABOVE_NORMAL]    = 7,
                [THRD_PRIO_LVL_HIGHEST]         = 8,
                [THRD_PRIO_LVL_TIME_CRITICAL]   = 15,
        },
        [PROC_PRIO_CLS_NORMAL]  = {
                [THRD_PRIO_LVL_IDLE]            = 1,
                [THRD_PRIO_LVL_LOWEST]          = 6,
                [THRD_PRIO_LVL_BELOW_NORMAL]    = 7,
                [THRD_PRIO_LVL_NORMAL]          = 8,
                [THRD_PRIO_LVL_ABOVE_NORMAL]    = 9,
                [THRD_PRIO_LVL_HIGHEST]         = 10,
                [THRD_PRIO_LVL_TIME_CRITICAL]   = 15,
        },
        [PROC_PRIO_CLS_ABOVE_NORMAL]    = {
                [THRD_PRIO_LVL_IDLE]            = 1,
                [THRD_PRIO_LVL_LOWEST]          = 8,
                [THRD_PRIO_LVL_BELOW_NORMAL]    = 9,
                [THRD_PRIO_LVL_NORMAL]          = 10,
                [THRD_PRIO_LVL_ABOVE_NORMAL]    = 11,
                [THRD_PRIO_LVL_HIGHEST]         = 12,
                [THRD_PRIO_LVL_TIME_CRITICAL]   = 15,
        },
        [PROC_PRIO_CLS_HIGH]    = {
                [THRD_PRIO_LVL_IDLE]            = 1,
                [THRD_PRIO_LVL_LOWEST]          = 11,
                [THRD_PRIO_LVL_BELOW_NORMAL]    = 12,
                [THRD_PRIO_LVL_NORMAL]          = 13,
                [THRD_PRIO_LVL_ABOVE_NORMAL]    = 14,
                [THRD_PRIO_LVL_HIGHEST]         = 15,
                [THRD_PRIO_LVL_TIME_CRITICAL]   = 15,
        },
        [PROC_PRIO_CLS_REALTIME]        = {
                [THRD_PRIO_LVL_IDLE]            = 16,
                [THRD_PRIO_LVL_LOWEST]          = 22,
                [THRD_PRIO_LVL_BELOW_NORMAL]    = 23,
                [THRD_PRIO_LVL_NORMAL]          = 24,
                [THRD_PRIO_LVL_ABOVE_NORMAL]    = 25,
                [THRD_PRIO_LVL_HIGHEST]         = 26,
                [THRD_PRIO_LVL_TIME_CRITICAL]   = 31,
        },
};

static int system_info_query(void **info, SYSTEM_INFORMATION_CLASS type, size_t *size)
{
        void *__info = NULL;
        size_t sz = 0x2000; // sizeof(SYSTEM_HANDLE_INFORMATION)
        unsigned long needed = 0;
        int ret = 0;

        if (info && *info) {
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
        SYSTEM_HANDLE_INFORMATION *hinfo = NULL;
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

// FIXME: what if same hash is inserted into queue
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

void proc_entry_for_each(tommy_hashtable *tbl, void (*cb)(proc_entry_t *, va_list), ...)
{
        va_list ap;
        va_start(ap, cb);

        if (!cb)
                goto out;

        for (size_t i = 0; i < tbl->bucket_max; i++) {
                tommy_node *n = tbl->bucket[i];

                while (n) {
                        proc_entry_t *proc = n->data;
                        tommy_node *next = n->next;

                        cb(proc, ap);

                        n = next;
                }
        }

out:
        va_end(ap);
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
        wchar_t val[128] = { 0 };

        if (is_strptr_not_set(id->value))
                return 0;

        iconv_utf82wc(id->value, sizeof(id->value), val, sizeof(val));

        if (id->filter == STR_FILTER_CONTAIN) {
                if (wcsstr(str, val))
                        return 1;
        }

        if (id->filter == STR_FILTER_IS) {
                if (is_wstr_equal(str, val))
                        return 1;
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

void proc_entry_init(proc_entry_t *entry, DWORD pid, wchar_t *proc_exe, profile_t *profile)
{
        proc_info_t *info = &entry->info;

        entry->is_new = 1;
        entry->last_stamp = 0;

        entry->profile = profile;

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

int proc_entry_init_insert(tommy_hashtable *tbl, DWORD pid, wchar_t *exe, profile_t *profile)
{
        proc_entry_t *entry = NULL;

        entry = proc_entry_alloc();
        if (!entry) {
                pr_err("failed to allocate memory\n");
                return -ENOMEM;
        }

        proc_entry_init(entry, pid, exe, profile);
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

static int process_threads_iterate(DWORD pid, int (*func)(DWORD tid, va_list), ...)
{
        HANDLE snap;
        THREADENTRY32 te32;
        int err = 0;

        va_list ap;

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

        va_start(ap, func);

        do {
                // say pid = 0 to iterate system-wide threads
                if (pid != 0 && pid != te32.th32OwnerProcessID)
                        continue;

                if ((err = func(te32.th32ThreadID, ap)))
                        break;

        } while(Thread32Next(snap, &te32));

        va_end(ap);

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
                                           ProcessBasicInformation,
                                           &pbi,
                                           sizeof(pbi),
                                           &needed);
        if (!NT_SUCCESS(status)) {
                pr_err("failed to query process basic info\n");
                ret = -EFAULT;
                goto out;
        }

        // process is already become threaded
        if (pbi.AffinityMask == 0x00)
                goto write;

        status = NtQueryInformationProcess(process,
                                           ProcessGroupInformation,
                                           pgi,
                                           pgi_sz,
                                           &needed);
        if (!NT_SUCCESS(status)) {
                pr_err("failed to query process group info, err=%lu\n", GetLastError());
                return -EFAULT;
        }

write:
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
                                               NULL);
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
                                             sizeof(PROCESS_PRIORITY_CLASS));
        if (!NT_SUCCESS(status)) {
                pr_err("NtSetInformationProcess(): PriocessPriorityClass failed, status=0x%08x\n", status);
                return -EFAULT;
        }

        return 0;
}

int process_prio_boost_get(HANDLE process, BOOL *prio_boost)
{
        BOOL is_disabled = 0;

        if (0 == GetProcessPriorityBoost(process, &is_disabled)) {
                pr_err("GetProcessPriorityBoost() failed, err=%lu\n", GetLastError());
                return -EFAULT;
        }

        *prio_boost = !is_disabled;

        return 0;
}

int process_prio_boost_set(HANDLE process, BOOL enable)
{
        if (0 == SetProcessPriorityBoost(process, !enable)) {
                pr_err("SetProcessPriorityBoost() failed, err=%lu\n", GetLastError());
                return -EFAULT;
        }

        return 0;
}

int process_page_prio_get(HANDLE process, ULONG *page_prio)
{
        int status = PhGetProcessPagePriority(process, page_prio);
        if (!NT_SUCCESS(status))
                return -EFAULT;

        return 0;
}

int process_page_prio_set(HANDLE process, ULONG page_prio)
{
        int status = PhSetProcessPagePriority(process, page_prio);
        if (!NT_SUCCESS(status))
                return -EFAULT;

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
        int err = 0, nt_ret = 0;

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

int is_profile_matched(PROCESSENTRY32 *pe32, profile_t **ret)
{
        profile_t *p, *s;

        for_each_profile_safe(p, s) {
                proc_id_t *id;

                int matched = 0;

                if (profile_try_lock(p)) {
                        continue;
                }

                if (!p->enabled) {
                        profile_unlock(p);
                        continue;
                }

                for_each_profile_id(id, p) {
                        switch (id->type) {
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
                profile_unlock(p);

                if (matched) {
                        if (ret)
                                *ret = p;

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
                profile_t *profile = NULL;

                if (process_try_open(&pe32))
                        continue;

                if (is_pid_tracked(proc_selected, pe32.th32ProcessID, pe32.szExeFile)) {
                        pr_verbose("pid: %lu \"%ls\" is tracked\n",
                                   pe32.th32ProcessID, pe32.szExeFile);
                        continue;
                }

                if (!is_profile_matched(&pe32, &profile)) {
                        pr_verbose("pid: %lu \"%ls\" did not match any profiles\n",
                                   pe32.th32ProcessID, pe32.szExeFile);
                        continue;
                }

                pr_rawlvl(INFO, "pid: %lu \"%ls\" new process matched profile \"%s\"\n",
                          pe32.th32ProcessID, pe32.szExeFile,
                          profile->name);

                proc_entry_init_insert(proc_selected,
                                       pe32.th32ProcessID,
                                       pe32.szExeFile,
                                       profile);
        } while (Process32Next(hProcessSnap, &pe32));

out:
        CloseHandle(hProcessSnap);

        return err;
}

void proc_info_msg(int header)
{
        if (header) {
                pr_raw("+------------+-------+--------------------+------------------------------------+----------+---------------------------+\n");
                pr_raw("| profile    | pid   | name               | priority info                      | threaded | node | affinity mask      |\n");
                pr_raw("|            |       |                    |---------+---------+--------+-------|          |      |                    |\n");
                pr_raw("|            |       |                    | class   | page    | io     | boost |          |      |                    |\n");
                pr_raw("+------------+-------+--------------------+---------+---------+--------+-------+----------+------+--------------------+\n");

                return;
        }

        pr_raw("+------------+-------+--------------------+---------+---------+--------+-------+----------+------+--------------------+\n");
}

void proc_entry_dump(proc_entry_t *entry, int ignore_oneshot)
{
        proc_info_t *info        = &entry->info;
        profile_t *profile       = profile_hash_get(entry->profile);
        uint8_t page_prio        = info->page_prio;
        uint8_t io_prio          = info->io_prio;
        uint8_t prio_boost       = info->prio_boost;
        uint8_t prio_class       = info->prio_class.PriorityClass;
        char profile_name[11]    = { 0 };
        wchar_t name[18]         = { 0 };
        int curr_grp = info->curr_aff.Group;

        if (NULL == profile) {
                pr_err("profile is not found in hash table\n");
                return;
        }

        if (profile_try_lock(profile))
                return;

        strncpy(profile_name, profile->name, sizeof(profile_name));
        profile_name[sizeof(profile_name) - 1] = L'\0';

        wcsncpy(name, info->name, WCBUF_LEN(name));
        name[WCBUF_LEN(name) - 1] = L'\0';

        if (!ignore_oneshot && entry->oneshot) {
                pr_raw("| %-10s | %-5zu | %-18ls | %-7s | %-7s | %-6s | %-5d | %-8d | %-4d | 0x%016jx |\n",
                       profile_name,
                       info->pid,
                       name,
                       "---",
                       "---",
                       "---",
                       0,
                       0,
                       0,
                       0ULL);

                goto out;
        }

        if (info->is_threaded)
                curr_grp = entry->last_aff.Group;

        pr_raw("| %-10s | %-5zu | %-18ls | %-7s | %-7s | %-6s | %-5d | %-8d | %-4d | 0x%016jx |\n",
               profile_name,
               info->pid,
               name,
               prio_class < MaxProcPrioClasses ? proc_prio_strs[prio_class] : "ERR",
               page_prio > MEMORY_PRIORITY_NORMAL ? "ERR" : page_prio_strs[page_prio],
               io_prio < MaxIoPriorityTypes ? io_prio_strs[io_prio] : "ERR",
               prio_boost,
               info->is_threaded,
               curr_grp,
               info->is_threaded ? 0xdeaddeaddeaddead : info->curr_aff.Mask);

out:
        profile_unlock(profile);
}

void proc_hashit_iterate(tommy_hashtable *tbl)
{
        if (tbl->count == 0)
                return;

        proc_info_msg(1);

        for (size_t i = 0; i < tbl->bucket_max; i++) {
                tommy_node *n = tbl->bucket[i];

                while (n) {
                        proc_entry_t *entry = n->data;

                        if (!entry->is_new)
                                proc_entry_dump(entry, 0);

                        n = n->next;
                }
        }

        proc_info_msg(0);
}

static int profile_proc_prio_class_set(profile_t *profile, proc_entry_t *entry, HANDLE process)
{
        PROCESS_PRIORITY_CLASS prio_class __attribute__((aligned(4))) = { 0 };
        uint32_t prio_cls_cfg = profile->proc_cfg.prio_class;

        if (prio_cls_cfg >= NUM_PROC_PRIO_CLASS)
                return -EINVAL;

        if (prio_cls_cfg == PROC_PRIO_CLS_UNCHANGED)
                return 0;

        prio_class.PriorityClass = profile_proc_prio_cls[prio_cls_cfg];

        if (entry->info.prio_class.PriorityClass == prio_class.PriorityClass) {
                pr_verbose("pid: %zu \"%ls\" nothing to change\n", entry->info.pid, entry->info.name);
                return 0;
        }

        if (process_prio_cls_set(process, &prio_class))
                return -EFAULT;

        pr_rawlvl(DEBUG, "pid: %zu \"%ls\" priority class %s -> %s\n",
                         entry->info.pid,
                         entry->info.name,
                         proc_prio_strs[entry->info.prio_class.PriorityClass],
                         proc_prio_strs[prio_class.PriorityClass]);

        return 0;
}

static int profile_proc_prio_boost_set(profile_t *profile, proc_entry_t *entry, HANDLE process)
{
        BOOL enabled;
        uint32_t prio_boost_cfg = profile->proc_cfg.prio_boost;

        if (prio_boost_cfg >= NUM_TRISTATE_VALS)
                return -EINVAL;

        if (prio_boost_cfg == LEAVE_AS_IS)
                return 0;

        enabled = 0;
        if (prio_boost_cfg == STRVAL_ENABLED)
                enabled = 1;

        if (entry->info.prio_boost == enabled) {
                pr_verbose("pid: %zu \"%ls\" nothing to change\n", entry->info.pid, entry->info.name);
                return 0;
        }

        pr_rawlvl(DEBUG, "pid: %zu \"%ls\" priority boost %d -> %d\n",
                         entry->info.pid,
                         entry->info.name,
                         entry->info.prio_boost,
                         enabled);

        return process_prio_boost_set(process, enabled);
}

static int profile_proc_io_prio_set(profile_t *profile, proc_entry_t *entry, HANDLE process)
{
        IO_PRIORITY_HINT io_prio;
        uint32_t io_prio_cfg = profile->proc_cfg.io_prio;

        if (io_prio_cfg >= NUM_IO_PRIOS)
                return -EINVAL;

        if (io_prio_cfg == IO_PRIO_UNCHANGED)
                return 0;

        io_prio = profile_ioprio_ntval[io_prio_cfg];

        if (entry->info.io_prio == io_prio) {
                pr_verbose("pid: %zu \"%ls\" nothing to change\n", entry->info.pid, entry->info.name);
                return 0;
        }

        pr_rawlvl(DEBUG, "pid: %zu \"%ls\" io priority %s -> %s\n",
                         entry->info.pid,
                         entry->info.name,
                         io_prio_strs[entry->info.io_prio],
                         io_prio_strs[io_prio]);

        if (process_io_prio_set(process, &io_prio))
                return -EFAULT;

        return 0;
}

static int profile_proc_page_prio_set(profile_t *profile, proc_entry_t *entry, HANDLE process)
{
        ULONG page_prio;
        uint32_t page_prio_cfg = profile->proc_cfg.page_prio;

        if (page_prio_cfg > NUM_PAGE_PRIOS)
                return -EINVAL;

        if (page_prio_cfg == PAGE_PRIO_UNCHANGED)
                return 0;

        page_prio = profile_page_prio_ntval[page_prio_cfg];

        if (entry->info.page_prio == page_prio) {
                pr_verbose("pid: %zu \"%ls\" nothing to change\n", entry->info.pid, entry->info.name);
                return 0;
        }

        pr_rawlvl(DEBUG, "pid: %zu \"%ls\" page priority %s -> %s\n",
                         entry->info.pid,
                         entry->info.name,
                         page_prio_strs[entry->info.page_prio],
                         page_prio_strs[page_prio]);

        return process_page_prio_set(process, page_prio);
}

static int process_efficiency_mode_set(HANDLE process, int enable)
{
        PROCESS_POWER_THROTTLING_STATE PowerThrottling = { 0 };
        int ret;

        PowerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
        PowerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;

        if (!enable) {
                PowerThrottling.StateMask = 0;
        } else if (enable > 0) {
                PowerThrottling.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
        } else {
                // let system manage
                PowerThrottling.ControlMask = 0;
                PowerThrottling.StateMask = 0;
        }

        ret = SetProcessInformation(process,
                                    ProcessPowerThrottling,
                                    &PowerThrottling,
                                    sizeof(PowerThrottling));
        if (!ret) {
                pr_getlasterr("SetProcessInformation");
        }

        return ret ? 0 : -EFAULT;
}

static int profile_proc_throttle_set(profile_t *profile, proc_entry_t *entry, HANDLE process)
{
        uint32_t throttle = profile->proc_cfg.power_throttle;

        if (throttle >= NUM_TRISTATE_VALS)
                return -EINVAL;

        if (throttle == LEAVE_AS_IS)
                return 0;

        process_efficiency_mode_set(process, throttle == STRVAL_ENABLED ? 1 : 0);

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

static int process_sched_thread_affinity_set(DWORD tid, va_list ap)
{
        proc_entry_t *proc = va_arg(ap, proc_entry_t *);
        GROUP_AFFINITY *new_aff = va_arg(ap, GROUP_AFFINITY *);
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
                        pr_rawlvl(VERBOSE,
                                  "pid: %5zu \"%ls\" tid: %5lu affinity did not change\n",
                                  pid, proc_name, tid);
                        goto out;
                }
        }

        affinity_mask_limit(new_aff, new_aff->Mask, new_aff->Group);

        pr_rawlvl(DEBUG, "[pid: %5zu \"%ls\" tid: %5lu] [%2hu] [0x%016jx] ==> [%2hu] [0x%016jx]\n",
                  pid, proc_name, tid, curr_aff.Group, curr_aff.Mask, new_aff->Group, new_aff->Mask);

        if (0 == SetThreadGroupAffinity(thread, new_aff, NULL)) {
                pr_err("SetThreadGroupAffinity() failed, tid=%lu pid=%zu \"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
        }

out:
        CloseHandle(thread);

        return 0;
}

static int processes_sched_set_new_affinity(supervisor_t *sv, proc_entry_t *proc,
                                            HANDLE process, GROUP_AFFINITY *new_aff)
{
        proc_info_t *info = &proc->info;
        GROUP_AFFINITY *last_aff = &proc->last_aff;
        int err;

        UNUSED_PARAM(sv);

        if (!info->is_threaded) {
                GROUP_AFFINITY *curr_aff = &info->curr_aff;

                if (!proc->is_new && !proc->always_set) {
                        if (last_aff->Mask == curr_aff->Mask &&
                            last_aff->Group == curr_aff->Group) {
                                pr_verbose("pid: %5zu \"%ls\" group affinity did not change, skip\n",
                                           info->pid, info->name);

                                return 0;
                        }
                }

                affinity_mask_limit(new_aff, new_aff->Mask, new_aff->Group);

                pr_rawlvl(DEBUG, "[pid: %5zu \"%ls\"] [%2hu] [0x%016jx] ==> [%2hu] [0x%016jx]\n",
                          info->pid, info->name,
                          curr_aff->Group, curr_aff->Mask,
                          new_aff->Group, new_aff->Mask);

                err = proc_group_affinity_set(process, new_aff);
        } else {
                err = process_threads_iterate(info->pid, process_sched_thread_affinity_set, proc, new_aff);
        }

        if (proc->is_new) {
                memcpy(last_aff, new_aff, sizeof(GROUP_AFFINITY));
        }

        return err;
}

static int processes_sched_by_map(supervisor_t *sv, proc_entry_t *proc, HANDLE process)
{
        profile_t *profile = proc->profile;
        GROUP_AFFINITY new_aff = { 0 };

        new_aff.Mask = profile->processes.affinity;
        new_aff.Group = find_first_bit((void *)&profile->processes.node_map,
                                       SIZE_TO_BITS(profile->processes.node_map));

        // for win11+, this should set default affinity for new threads
        if (_SetProcessDefaultCpuSetMasks) {
                // this function can't be failed if params are valid
                _SetProcessDefaultCpuSetMasks(process, &new_aff, 1);
        }

        return processes_sched_set_new_affinity(sv, proc, process, &new_aff);
}

static unsigned long node_map_next(unsigned long curr, unsigned long mask)
{
        unsigned long supported_mask = NODE_MAP_SUPPORT_MASK;

        for (int i = 0; i < (MAX_PROC_GROUPS * 2); i++) {
                if (unlikely(curr == 0))
                        curr = 1;
                else
                        curr = curr << 1;

                // overflow, reset
                if ((curr & supported_mask) == 0)
                        curr = 1;

                if ((curr & mask) != 0)
                        break;
        }

        return curr;
}

static uint64_t cpu_map_next(uint64_t curr, uint64_t tgt_mask, uint64_t avail_mask, uint32_t *is_overflowed)
{
        if (is_overflowed)
                *is_overflowed = 0;

        for (unsigned i = 0; i < sizeof(uint64_t) * BITS_PER_BYTE; i++) {
                if (unlikely(curr == 0))
                        curr = 1;
                else
                        curr = curr << 1;

                if ((curr & avail_mask) == 0) {
                        curr = 1;

                        if (is_overflowed)
                                *is_overflowed = 1;
                }

                if ((curr & tgt_mask) != 0)
                        break;
        }

        return curr;
}

static int processes_sched_rr(supervisor_t *sv, proc_entry_t *proc, HANDLE process)
{
        profile_t *profile = proc->profile;
        unsigned long node_map = profile->processes.node_map;
        struct procs_sched *val = &(profile->sv.u.procs_sched);
        GROUP_AFFINITY new_aff = { 0 };
        int err;

        val->node_map_next = node_map_next(val->node_map_next, node_map);

        affinity_mask_limit(&new_aff, profile->processes.affinity,
                            find_first_bit(&val->node_map_next, SIZE_TO_BITS(val->node_map_next)));

        err = processes_sched_set_new_affinity(sv, proc, process, &new_aff);

        return err;
}

static int processes_sched_node_rand(supervisor_t *sv, proc_entry_t *proc, HANDLE process)
{
        profile_t *profile = proc->profile;
        GROUP_AFFINITY new_aff = { 0 };

        new_aff.Mask = profile->processes.affinity;
        new_aff.Group = rand() % g_sys_info.nr_cpu_grp; // 0 <= result < nr_cpu_grp

        return processes_sched_set_new_affinity(sv, proc, process, &new_aff);
}

static int supervisor_processes_sched(supervisor_t *sv, proc_entry_t *proc, HANDLE process)
{
        profile_t *profile = proc->profile;

        if (profile->processes.node_map == 0) {
                pr_dbg("node map of profile [%s] is not set\n", profile->name);
                return 0;
        }

        if (profile->processes.affinity == 0) {
                pr_dbg("affinity of profile [%s] is not set\n", profile->name);
                return 0;
        }

        // DO NOT CHECK ERROR RETURN
        // since there are multiple processes

        switch (proc->profile->processes.balance) {
        case PROC_BALANCE_BY_MAP:
                processes_sched_by_map(sv, proc, process);
                break;

        case PROC_BALANCE_RR:
                processes_sched_rr(sv, proc, process);
                break;

        case PROC_BALANCE_RAND:
                processes_sched_node_rand(sv, proc, process);
                break;

        case PROC_BALANCE_ONLOAD:
        default:
                pr_err("invalid balance mode\n");
                return -EINVAL;
        }

        return 0;
}

static void thread_node_rr_map_update(supervisor_t *sv, proc_entry_t *proc, GROUP_AFFINITY *new_aff)
{
        profile_t *profile = proc->profile;
        unsigned long node_map = profile->threads.node_map;
        struct thrds_sched *val = &(profile->sv.u.thrds_sched);

        val->node_map_next = node_map_next(val->node_map_next, node_map);

        affinity_mask_limit(new_aff, profile->threads.affinity,
                            find_first_bit(&val->node_map_next, SIZE_TO_BITS(val->node_map_next)));

}

static void thread_cpu_rr_map_update(supervisor_t *sv, proc_entry_t *proc, GROUP_AFFINITY *new_aff)
{
        profile_t *profile = proc->profile;
        unsigned long node_map = profile->threads.node_map;
        uint64_t affinity_map = profile->threads.affinity;
        struct thrds_sched *val = &(profile->sv.u.thrds_sched);

        if (unlikely(val->node_map_next == 0))
                val->node_map_next = 1;

        uint32_t curr_grp = find_first_bit(&val->node_map_next, SIZE_TO_BITS(val->node_map_next));
        uint64_t affinity_max = g_sys_info.cpu_grp[curr_grp].grp_mask;
        uint32_t overflowed = 0;

        val->cpu_map_next = cpu_map_next(val->cpu_map_next, affinity_map & affinity_max, affinity_max, &overflowed);

        // move to next group if group mask specified multiple nodes
        if (overflowed) {
                val->node_map_next = node_map_next(val->node_map_next, node_map);
                curr_grp = find_first_bit(&val->node_map_next, SIZE_TO_BITS(val->node_map_next));
        }

        affinity_mask_limit(new_aff, val->cpu_map_next, curr_grp);
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

typedef void (*THRD_AFF_VAL_UPDATE)(supervisor_t *, proc_entry_t *, GROUP_AFFINITY *);

static int thread_supervisor_affinity_set(DWORD tid, va_list ap)
{
        supervisor_t *sv = va_arg(ap, supervisor_t *);
        proc_entry_t *proc = va_arg(ap, proc_entry_t *);
        THRD_AFF_VAL_UPDATE val_update = va_arg(ap, THRD_AFF_VAL_UPDATE);
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
                pr_err("OpenThread() failed, tid: %lu pid: %zu \"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                if (thrd_entry)
                        delete = 1;

                goto not_exist;
        }

        if (0 == GetThreadGroupAffinity(thrd_hdl, &curr_aff)) {
                pr_err("GetThreadGroupAffinity() failed, tid: %lu pid: %zu \"%ls\" err=%lu\n",
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
                                pr_rawlvl(VERBOSE,
                                          "pid: %5zu \"%ls\" tid: %5lu affinity did not change\n",
                                          pid, proc_name, tid);
                                goto out;
                        }
                }
        }

        val_update(sv, proc, &new_aff);

        pr_rawlvl(DEBUG, "[pid: %5zu \"%ls\" tid: %5lu] [%2hu] [0x%016jx] ==> [%2hu] [0x%016jx]\n",
                  pid, proc_name, tid, curr_aff.Group, curr_aff.Mask, new_aff.Group, new_aff.Mask);

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

                pr_dbg("[pid: %5zu \"%ls\" tid: %5lu] delete thread\n", pid, proc_name, tid);

                tommy_hashtable_remove_existing(&proc->threads, n);
                free(thrd_entry);
        }

        return 0;
}

static int threads_sched_node_rr(supervisor_t *sv, proc_entry_t *proc)
{
        return process_threads_iterate(proc->info.pid,
                                       thread_supervisor_affinity_set,
                                       sv,
                                       proc,
                                       thread_node_rr_map_update);
}

static int threads_sched_cpu_rr(supervisor_t *sv, proc_entry_t *proc)
{
        return process_threads_iterate(proc->info.pid,
                                       thread_supervisor_affinity_set,
                                       sv,
                                       proc,
                                       thread_cpu_rr_map_update);
}

static int thread_rand_node_affinity_set(DWORD tid, va_list ap)
{
        proc_entry_t *proc = va_arg(ap, proc_entry_t *);
        profile_t *profile = proc->profile;
        wchar_t *proc_name = proc->info.name;
        size_t pid = proc->info.pid;
        GROUP_AFFINITY curr_aff, new_aff = { 0 };

        HANDLE thrd_hdl = OpenThread(THREAD_SET_INFORMATION |
                                     THREAD_QUERY_INFORMATION,
                                     FALSE,
                                     tid);

        if (!thrd_hdl) { // thread might just be closed
                pr_err("OpenThread() failed, tid=%lu pid=%zu name=\"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                return -EFAULT;
        }

        if (0 == GetThreadGroupAffinity(thrd_hdl, &curr_aff)) {
                pr_err("GetThreadGroupAffinity() failed, tid=%lu pid=%zu name=\"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
                goto out;
        }

        new_aff.Mask = profile->threads.affinity;
        new_aff.Group = rand() % g_sys_info.nr_cpu_grp; // 0 <= result < nr_cpu_grp

        affinity_mask_limit(&new_aff, new_aff.Mask, new_aff.Group);

        pr_rawlvl(DEBUG, "[tid: %5lu pid: %5zu \"%ls\"] [%2hu] [0x%016jx] ==> [%2hu] [0x%016jx]\n",
                  tid, pid, proc_name, curr_aff.Group, curr_aff.Mask, new_aff.Group, new_aff.Mask);

        if (0 == SetThreadGroupAffinity(thrd_hdl, &new_aff, NULL)) {
                pr_err("SetThreadGroupAffinity() failed, tid=%lu pid=%zu \"%ls\" err=%lu\n",
                       tid, pid, proc_name, GetLastError());
        }

out:
        CloseHandle(thrd_hdl);

        return 0;
}

static int threads_sched_node_rand(supervisor_t *sv, proc_entry_t *proc)
{
        UNUSED_PARAM(sv);

        if (!proc->is_new && !proc->profile->always_set)
                return 0;

        return process_threads_iterate(proc->info.pid, thread_rand_node_affinity_set, proc);
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

static int supervisor_threads_sched(supervisor_t *sv, proc_entry_t *proc)
{
        profile_t *profile = proc->profile;

        if (profile->threads.node_map == 0) {
                pr_dbg("node map of profile [%s] is not set\n", profile->name);
                return 0;
        }

        if (profile->threads.affinity == 0) {
                pr_dbg("affinity of profile [%s] is not set\n", profile->name);
                return 0;
        }

        switch (proc->profile->threads.balance) {
        case THRD_BALANCE_CPU_RR:
                threads_sched_cpu_rr(sv, proc);
                break;

        case THRD_BALANCE_NODE_RR:
                threads_sched_node_rr(sv, proc);
                break;

        case THRD_BALANCE_NODE_RAND:
                threads_sched_node_rand(sv, proc);
                break;

        case THRD_BALANCE_ONLOAD:
        default:
                pr_err("invalid balance mode\n");
                return -EINVAL;
        }

        dead_thread_entry_remove(sv, proc);

        return 0;
}

static int proc_info_update(proc_info_t *info, HANDLE process)
{
        int err;

        if ((err = process_io_prio_get(process, &info->io_prio)))
                return err;

        if ((err = process_prio_cls_get(process, &info->prio_class)))
                return err;

        if ((err = process_prio_boost_get(process, &info->prio_boost)))
                return err;

        if ((err = process_page_prio_get(process, &info->page_prio)))
                return err;

        if ((err = proc_group_affinity_get(process, &info->curr_aff)))
                return err;

        info->is_threaded = 0;
        if (info->curr_aff.Mask == 0)
                info->is_threaded = 1;

        return err;
}

static int profile_thrd_io_prio_set(profile_t *profile,
                                    proc_entry_t *proc,
                                    DWORD tid,
                                    HANDLE thrd_hdl)
{
        wchar_t *proc_name = proc->info.name;
        size_t pid = proc->info.pid;
        uint32_t io_prio_cfg = profile->thrd_cfg.io_prio;
        IO_PRIORITY_HINT io_prio, new_prio;

        if (io_prio_cfg == IO_PRIO_UNCHANGED)
                return 0;

        new_prio = profile_ioprio_ntval[io_prio_cfg];

        if (!NT_SUCCESS(PhGetThreadIoPriority(thrd_hdl, &io_prio))) {
                pr_err("pid: %zu \"%ls\" tid: %lu PhGetThreadIoPriority() failed: %lu\n",
                       pid, proc_name, tid, GetLastError());
                return -EFAULT;
        }

        if (io_prio == new_prio) {
                pr_verbose("pid: %zu \"%ls\" tid: %lu nothing to change\n", pid, proc_name, tid);
                return 0;
        }

        pr_rawlvl(DEBUG, "[pid: %5zu \"%ls\" tid: %6lu] set io priority %s -> %s\n",
               pid, proc_name, tid,
               io_prio_strs[io_prio], io_prio_strs[new_prio]);

        if (!NT_SUCCESS(PhSetThreadIoPriority(thrd_hdl, new_prio))) {
                pr_err("pid: %zu \"%ls\" tid: %lu PhSetThreadIoPriority() failed: %lu\n",
                       pid, proc_name, tid, GetLastError());
                return -EFAULT;
        }

        return 0;
}

static int profile_thrd_page_prio_set(profile_t *profile,
                                      proc_entry_t *proc,
                                      DWORD tid,
                                      HANDLE thrd_hdl)
{
        wchar_t *proc_name = proc->info.name;
        size_t pid = proc->info.pid;
        uint32_t page_prio_cfg = profile->thrd_cfg.page_prio;
        ULONG page_prio, new_prio;

        if (page_prio_cfg == PAGE_PRIO_UNCHANGED)
                return 0;

        new_prio = profile_page_prio_ntval[page_prio_cfg];

        if (!NT_SUCCESS(PhGetThreadPagePriority(thrd_hdl, &page_prio))) {
                pr_err("pid: %zu \"%ls\" tid: %lu PhGetThreadPagePriority() failed: %lu\n",
                       pid, proc_name, tid, GetLastError());
                return -EFAULT;
        }

        if (page_prio == new_prio) {
                pr_verbose("pid: %zu \"%ls\" tid: %lu nothing to change\n", pid, proc_name, tid);
                return 0;
        }

        pr_rawlvl(DEBUG, "[pid: %5zu \"%ls\" tid: %6lu] set io priority %s -> %s\n",
               pid, proc_name, tid,
               page_prio_strs[page_prio], page_prio_strs[new_prio]);

        if (!NT_SUCCESS(PhSetThreadPagePriority(thrd_hdl, new_prio))) {
                pr_err("pid: %zu \"%ls\" tid: %lu PhSetThreadPagePriority() failed: %lu\n",
                       pid, proc_name, tid, GetLastError());
                return -EFAULT;
        }

        return 0;
}

static int profile_thrd_prio_boost_set(profile_t *profile,
                                      proc_entry_t *proc,
                                      DWORD tid,
                                      HANDLE thrd_hdl)
{
        wchar_t *proc_name = proc->info.name;
        size_t pid = proc->info.pid;
        uint32_t boost_cfg = profile->thrd_cfg.prio_boost;
        BOOL prio_boost, enable;

        if (boost_cfg == LEAVE_AS_IS)
                return 0;

        enable = boost_cfg == STRVAL_ENABLED ? 1 : 0;

        if (0 == GetThreadPriorityBoost(thrd_hdl, &prio_boost)) {
                pr_err("pid: %zu \"%ls\" tid: %lu GetThreadPriorityBoost() failed, err=%lu\n",
                       pid, proc_name, tid, GetLastError());
                return -EFAULT;
        }

        // GetThreadPriorityBoost() return is_disabled
        prio_boost = !prio_boost;

        if (prio_boost == enable) {
                pr_verbose("pid: %zu \"%ls\" tid: %lu nothing to change\n", pid, proc_name, tid);
                return 0;
        }

        pr_rawlvl(DEBUG, "[pid: %5zu \"%ls\" tid: %6lu] set priority boost %d -> %d\n",
               pid, proc_name, tid,
               prio_boost, enable);

        if (0 == SetThreadPriorityBoost(thrd_hdl, !enable)) {
                pr_err("pid: %zu \"%ls\" tid: %lu SetThreadPriorityBoost() failed, err=%lu\n",
                       pid, proc_name, tid, GetLastError());
                return -EFAULT;
        }

        return 0;
}

static int profile_thrd_prio_level_set(profile_t *profile,
                                       proc_entry_t *proc,
                                       DWORD tid,
                                       HANDLE thrd_hdl)
{
        wchar_t *proc_name = proc->info.name;
        size_t pid = proc->info.pid;
        int prio_cfg = (int)profile->thrd_cfg.prio_level;
        int prio_level, _prio_level, _new_level;

        if (prio_cfg == THRD_PRIO_LVL_UNCHANGED)
                return 0;

        _prio_level = GetThreadPriority(thrd_hdl);
        if (_prio_level == THREAD_PRIORITY_ERROR_RETURN) {
                pr_err("pid: %zu \"%ls\" tid: %lu GetThreadPriority() failed, err=%lu\n",
                       pid, proc_name, tid, GetLastError());
                return -EFAULT;
        }

        prio_level = thread_prio_level_cfgval(_prio_level);
        if (prio_level == -1) {
                pr_err("pid: %zu \"%ls\" tid: %lu unsupported priority value: %d\n",
                       pid, proc_name, tid, _prio_level);
                return -EFAULT;
        }

        if (prio_level == prio_cfg) {
                pr_verbose("pid: %zu \"%ls\" tid: %lu nothing to change\n",
                           pid, proc_name, tid);
                return 0;
        }

        if (profile->thrd_cfg.prio_level_least) {
                if (prio_level > prio_cfg) {
                        pr_verbose("pid: %zu \"%ls\" tid: %lu desired priority is lower than current one\n",
                                   pid, proc_name, tid);
                        return 0;
                }
        }

        pr_rawlvl(DEBUG, "[pid: %5zu \"%ls\" tid: %6lu] set priority level %s -> %s\n",
               pid, proc_name, tid,
               prio_level_strs[prio_level],
               prio_level_strs[prio_cfg]);

        _new_level = thread_prio_level_ntval[prio_cfg];
        if (0 == SetThreadPriority(thrd_hdl, _new_level)) {
                pr_err("pid: %zu \"%ls\" tid: %lu SetThreadPriority() failed, err=%lu\n",
                       pid, proc_name, tid, GetLastError());
                return -EFAULT;
        }

        return 0;
}

static int thread_settings_apply(DWORD tid, va_list ap)
{
        proc_entry_t *proc = va_arg(ap, proc_entry_t *);
        profile_t *profile = proc->profile;
        int err = 0;

        HANDLE thread = OpenThread(THREAD_SET_INFORMATION |
                                   THREAD_QUERY_INFORMATION,
                                   FALSE,
                                   tid);

        if (!thread) { // thread might just be closed
                pr_err("OpenThread() failed, tid=%lu pid=%zu name=\"%ls\" err=%lu\n",
                       tid, proc->info.pid, proc->info.name, GetLastError());
                return -EFAULT;
        }

        if ((err = profile_thrd_io_prio_set(profile, proc, tid, thread)))
                goto out;

        if ((err = profile_thrd_page_prio_set(profile, proc, tid, thread)))
                goto out;

        if ((err = profile_thrd_prio_boost_set(profile, proc, tid, thread)))
                goto out;

        if ((err = profile_thrd_prio_level_set(profile, proc, tid, thread)))
                goto out;

out:
        CloseHandle(thread);

        // continue to apply other threads
        return 0;
}

static int profile_thread_settings_apply(proc_entry_t *proc)
{
        return process_threads_iterate(proc->info.pid, thread_settings_apply, proc);
}

static int process_config_apply(profile_t *profile, proc_entry_t *proc, HANDLE hdl)
{
        int err;

        if ((err = profile_proc_prio_class_set(profile, proc, hdl)))
                return err;

        if ((err = profile_proc_prio_boost_set(profile, proc, hdl)))
                return err;

        if ((err = profile_proc_io_prio_set(profile, proc, hdl)))
                return err;

        if ((err = profile_proc_page_prio_set(profile, proc, hdl)))
                return err;

        if ((err = profile_proc_throttle_set(profile, proc, hdl)))
                return err;

        profile_thread_settings_apply(proc);

        return 0;
}

static int __profile_settings_apply(supervisor_t *sv, proc_entry_t *proc)
{
        proc_info_t *info = &proc->info;
        profile_t *profile = proc->profile;
        wchar_t exe_name[_MAX_FNAME] = { 0 };
        int err = 0;
        DWORD status;
        HANDLE proc_hdl;

        if (!profile) {
                pr_err("profile == NULL\n");
                return -EINVAL;
        }

        // XXX: some dead processes still can be opened
        proc_hdl = OpenProcess(PROCESS_ALL_ACCESS |
                               PROCESS_QUERY_INFORMATION |
                               PROCESS_QUERY_LIMITED_INFORMATION,
                               FALSE,
                               info->pid);
        if (!proc_hdl) {
                pr_info("OpenProcess() failed, pid %zu \"%ls\", err=%lu, maybe dead?\n",
                        info->pid, info->name, GetLastError());
                return -ENOENT;
        }

        if (0 == GetExitCodeProcess(proc_hdl, &status)) {
                pr_info("GetExitCodeProcess() failed, pid %zu \"%ls\", err=%lu\n",
                        info->pid, info->name, GetLastError());
                err = -EFAULT;
                goto out;
        }

        if (status != STILL_ACTIVE) {
                pr_rawlvl(INFO, "pid: %zu \"%ls\" had been terminated\n", info->pid, info->name);
                err = -ENOENT;
                goto out;
        }

        // allow disabling profile on the fly
        if (!profile->enabled)
                goto out;

        if (image_path_extract_file_name(proc->info.pid, exe_name, _MAX_FNAME))
                goto out;

        if (!proc->is_new && !is_wstr_equal(info->name, exe_name)) {
                pr_info("this is rare, process name \"%ls\" \"%ls\" mismatched!\n", info->name, exe_name);
                err = -EINVAL;
                goto out;
        }

        if (proc->is_new) {
                if (profile->delay && (proc->on_stamp == 0)) {
                        proc->on_stamp = sv->update_stamp + profile->delay;
                        goto out;
                }

                if (proc->on_stamp) {
                        if (proc->on_stamp - sv->update_stamp < profile->delay) {
                                pr_rawlvl(DEBUG, "pid: %zu \"%ls\" is delayed, on_stamp:%u curr_stamp:%u\n",
                                          info->pid, info->name, proc->on_stamp, sv->update_stamp);
                                goto out;
                        }

                        // timed out, no more delay
                        proc->on_stamp = 0;
                }
        }

        if ((err = proc_info_update(info, proc_hdl))) {
                pr_err("failed to update info for pid %zu \"%ls\"\n", info->pid, info->name);
                goto out;
        }

        if (profile->oneshot && proc->oneshot)
                goto out;

        if ((err = process_config_apply(profile, proc, proc_hdl)))
                goto out;

        switch (profile->sched_mode) {
        case SUPERVISOR_PROCESSES:
                err = supervisor_processes_sched(sv, proc, proc_hdl);
                break;

        case SUPERVISOR_THREADS:
                err = supervisor_threads_sched(sv, proc);
                break;

        default:
                pr_err("invalid sched mode\n");
                err = -EINVAL;
                break;
        }

        // update again after applying settings
        if ((err = proc_info_update(info, proc_hdl)))
                pr_err("failed to update info for pid %zu \"%ls\"\n", info->pid, info->name);

        proc->is_new = 0;
        proc->oneshot = profile->oneshot;
        proc->always_set = profile->always_set;

out:
        proc->last_stamp = sv->update_stamp;

        CloseHandle(proc_hdl);

        return err;
}

static int _profile_settings_apply(supervisor_t *sv, proc_entry_t *proc)
{
        profile_t *profile = profile_hash_get(proc->profile);
        int err;

        if (!profile) {
                pr_dbg("profile %p is not found in hash table\n", proc->profile);
                return -ENODATA;
        }

        if ((err = profile_try_lock(profile))) {
                pr_dbg("cannot grab profile %s, skipped\n", profile->name);
                return -EBUSY;
        }

        err = __profile_settings_apply(sv, proc);
        profile_unlock(profile);

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
                        if (err && err != -EBUSY) {
                                proc_entry_t *proc = n->data;
                                pr_rawlvl(DEBUG, "pid: %5zu \"%ls\" remove process from list\n",
                                          proc->info.pid, proc->info.name);

                                tommy_hashtable_remove_existing(tbl, n);
                                proc_entry_free(n->data);
                        }

                        n = next;
                }
        }

        return 0;
}

#if 0
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
#endif

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

        sv->update_stamp = 0;

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
        srand(time(NULL));

        krnl_dll = LoadLibrary(L"kernel32.dll");
        if (krnl_dll == NULL) {
                pr_err("failed to load kernel32.dll\n");
                return -EINVAL;
        }

        _SetProcessDefaultCpuSetMasks = (void *)GetProcAddress(krnl_dll, "SetProcessDefaultCpuSetMasks");
        _GetProcessDefaultCpuSetMasks = (void *)GetProcAddress(krnl_dll, "GetProcessDefaultCpuSetMasks");

        if (!_SetProcessDefaultCpuSetMasks || !_GetProcessDefaultCpuSetMasks) {
                pr_info("{Get/Set}ProcessDefaultCpuSetMasks() is not available\n");
        }

        sem_init(&sv->sleeper, 0, 0);
        pthread_mutex_init(&sv->trigger_lck, NULL);
        tommy_hashtable_init(&sv->proc_selected, PROC_HASH_TBL_BUCKET);

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

        tommy_hashtable_foreach(&sv->proc_selected, proc_selected_free);
        tommy_hashtable_done(&sv->proc_selected);

        pthread_mutex_destroy(&sv->trigger_lck);
        sem_destroy(&sv->sleeper);

        if (krnl_dll)
                FreeLibrary(krnl_dll);

        return 0;
}

int thread_info_dump(DWORD tid, va_list ap)
{
        size_t _prio_class = va_arg(ap, size_t);
        size_t prio_class = proc_prio_cls_profile[_prio_class];
        ULONG page_prio;
        IO_PRIORITY_HINT io_prio;
        int _prio_level, prio_level;
        BOOL prio_boost;
        GROUP_AFFINITY curr_aff = { 0 };

        HANDLE thread = OpenThread(THREAD_SET_INFORMATION |
                                   THREAD_QUERY_INFORMATION,
                                   FALSE,
                                   tid);

        if (0 == GetThreadPriorityBoost(thread, &prio_boost)) {
                pr_err("GetThreadPriorityBoost() failed, err=%lu\n", GetLastError());
                goto out;
        }

        prio_boost = !prio_boost;

        _prio_level = GetThreadPriority(thread);
        if (_prio_level == THREAD_PRIORITY_ERROR_RETURN) {
                pr_err("GetThreadPriority() failed, err=%lu\n", GetLastError());
                goto out;
        }

        if (!NT_SUCCESS(PhGetThreadIoPriority(thread, &io_prio))) {
                pr_err("PhGetThreadIoPriority() failed\n");
                goto out;
        }

        if (!NT_SUCCESS(PhGetThreadPagePriority(thread, &page_prio))) {
                pr_err("PhGetThreadPagePriority() failed\n");
                goto out;
        }

        if (0 == GetThreadGroupAffinity(thread, &curr_aff)) {
                pr_err("GetThreadGroupAffinity() failed\n");
                goto out;
        }

        if ((prio_level = thread_prio_level_cfgval(_prio_level)) == -1) {
                pr_err("invalid priority level value: %d\n", _prio_level);
                prio_level = THRD_PRIO_LVL_UNCHANGED;
        }

        if (io_prio > ARRAY_SIZE(io_prio_strs)) {
                pr_err("invalid io priority value: %d\n", io_prio);
                goto out;
        }

        if (page_prio > ARRAY_SIZE(page_prio_strs)) {
                pr_err("invalid page priority value: %lu\n", page_prio);
                goto out;
        }

        pr_rawlvl(INFO, "| %-5lu | %-8s | %-4d | %-7s | %-6s | %-5d | %-4d | 0x%016jx |\n",
                  tid,
                  prio_level_strs[prio_level],
                  thread_base_priority[prio_class][prio_level],
                  page_prio_strs[page_prio],
                  io_prio_strs[io_prio],
                  prio_boost,
                  curr_aff.Group,
                  curr_aff.Mask
                 );

out:
        CloseHandle(thread);

        return 0;
}

void process_info_dump(proc_entry_t *proc)
{
        PROCESS_PRIORITY_CLASS _prio_class __attribute__((aligned(4))) = { 0 };
        size_t pid = proc->info.pid;
        size_t prio_class = 0;
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS |
                                     PROCESS_QUERY_INFORMATION |
                                     PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE,
                                     pid);

        if (!process) {
                pr_err("failed to open process\n");
                return;
        }

        proc_info_msg(1);
        proc_info_update(&proc->info, process);
        proc_entry_dump(proc, 1);
        proc_info_msg(0);

        if (process_prio_cls_get(process, &_prio_class)) {
                pr_err("process_prio_cls_get() failed\n");
                goto out;
        }

        prio_class = _prio_class.PriorityClass;
        if (prio_class >= MaxProcPrioClasses) {
                pr_err("invalid priority class value: %zu\n", prio_class);
                goto out;
        }

        pr_raw("+-------+--------------------------------------------+---------------------------+\n");
        pr_raw("| tid   | priority info                              | node | affinity mask      |\n");
        pr_raw("|       |----------+------+---------+--------+-------|      |                    |\n");
        pr_raw("|       | level    | base | page    | io     | boost |      |                    |\n");
        pr_raw("+-------+----------+------+---------+--------+-------+------+--------------------+\n");

        process_threads_iterate(pid, thread_info_dump, prio_class);

        pr_raw("+-------+----------+------+---------+--------+-------+------+--------------------+\n");

out:
        CloseHandle(process);
}

void profile_proc_info_dump_cb(proc_entry_t *proc, va_list ap)
{
        profile_t *profile = va_arg(ap, profile_t *);

        if (proc->is_new)
                return;

        if (proc->profile != profile)
                return;

        process_info_dump(proc);
}

void proc_entry_list_dump(tommy_hashtable *tbl, profile_t *profile)
{
        proc_entry_for_each(tbl, profile_proc_info_dump_cb, profile);
}
