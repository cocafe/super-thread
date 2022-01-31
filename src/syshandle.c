#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <windows.h>
#include <windowsx.h>
#include <winbase.h>
#include <winternl.h>
#include <fileapi.h>
#include <processthreadsapi.h>

#include "logging.h"

int handle_type_token_get(SYSTEM_HANDLE_ENTRY *hentry, DWORD pid)
{
//        OBJECT_TYPE_INFORMATION *obj = NULL;
//        ULONG sz = 0;
        char path[MAX_PATH] = { 0 };
        int ret = 0;
        int nt_ret = 0;
        int is_remote = pid != GetCurrentProcessId();

        // case for owner is self
        HANDLE hdup = hentry->HandleValue;

        if (is_remote) {
                HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
                if (!process) {
                        pr_err("OpenProcess() failed, pid: %lu\n", pid);
                        return -EFAULT;
                }

                nt_ret = DuplicateHandle(process,
                                      (HANDLE)hentry->HandleValue,
                                      GetCurrentProcess(),
                                      &hdup,
                                      0,
                                      FALSE,
                                      DUPLICATE_SAME_ACCESS);

                CloseHandle(process);

                if (!NT_SUCCESS(nt_ret)) {
                        pr_dbg("DuplicateHandle() failed, err: %lu pid: %lu\n", GetLastError(), pid);
                        return -EFAULT;
                }
        }

#if 1 // FAST PATH

        // return ZERO on failure
        if (0 == GetFinalPathNameByHandle(hdup, path, sizeof(path), VOLUME_NAME_DOS)) {
                ret = -EINVAL;
        } else {
                // the PATH is CODE PAGEd
                pr_dbg("pid: %lu file: %s\n", pid, path);
        }

#else

        NtQueryObject(hdup, ObjectTypeInformation, NULL, 0, &sz);
        if (sz == 0) {
                pr_dbg("NtQueryObject() failed to query size, err = %lu\n", GetLastError());
                ret = -EINVAL;
                goto out_handle;
        }

        obj = malloc(sz);
        if (!obj) {
                pr_dbg("failed to allocate buf, size: %lu\n", sz);
                ret = -ENOMEM;
                goto out_handle;
        }

        nt_ret = NtQueryObject(hdup, ObjectTypeInformation, obj, sz, NULL);
        if (!NT_SUCCESS(nt_ret)) {
                pr_dbg("NtQueryObject() failed, err=%lu\n", GetLastError());
                ret = -EFAULT;
                goto out_free;
        }

//        pr_info("handle type: %.*ls\n", obj->TypeName.Length, obj->TypeName.Buffer);

        if (wcscmp(obj->TypeName.Buffer, L"File") == 0) {
                char path[MAX_PATH] = { 0 };

                if (0 == GetFinalPathNameByHandle(hdup, path, sizeof(path), VOLUME_NAME_DOS)) {
                        pr_dbg("GetFinalPathNameByHandle() failed, err=%lu\n", GetLastError());
                        ret = -EINVAL;
                } else {
                        pr_dbg("%.*ls: %s\n", obj->TypeName.Length, obj->TypeName.Buffer, path);
                }
        }

out_free:
        free(obj);

out_handle:

#endif
        if (hdup && is_remote)
                CloseHandle(hdup);

        return ret;
}

int system_handle_list(SYSTEM_HANDLE_INFORMATION *hinfo, DWORD pid)
{
        for (ULONG i = 0; i < hinfo->Count; i++) {
                SYSTEM_HANDLE_ENTRY *h = &hinfo->Handle[i];

                if (h->OwnerPid != pid)
                        continue;

//                pr_info("handle %lu: pid: %5ld type: %d flag: %d value: 0x%08x addr: 0x%08llx\n",
//                        i, h->OwnerPid, h->ObjectType, h->HandleFlags, h->HandleValue, (size_t)h->ObjectPointer);

                handle_type_token_get(h, pid);
        }

        return 0;
}

int system_info_query(void **info, SYSTEM_INFORMATION_CLASS type, size_t *size)
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

int system_handle_query(void)
{
        SYSTEM_HANDLE_INFORMATION *hinfo;
        size_t sz;
        int err;

        if ((err = system_info_query((void **)&hinfo, SystemHandleInformation, &sz)))
                return err;

        system_handle_list(hinfo, GetCurrentProcessId());

        free(hinfo);

        return 0;
}

int system_process_query(void)
{
        SYSTEM_PROCESS_INFORMATION *pinfo;
        size_t sz;
        int err;

        if ((err = system_info_query((void **)&pinfo, SystemProcessInformation, &sz)))
                return err;

        free(pinfo);

        return 0;
}
