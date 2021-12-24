#include <errno.h>

#include <windows.h>
#include <windowsx.h>

#include "OlsIoctl.h"
#include "logging.h"

#define SERVICE_NAME    "WinRing0_1_2_0"
#define DRIVER_FILE     "WinRing0x64.sys"

static SC_HANDLE g_hmanager;
static SC_HANDLE g_hservice;
static HANDLE g_hdriver;

int winring0_drv_uninstall(SC_HANDLE *hservice)
{
        SERVICE_STATUS svc_status;
        int ret = 0;

        if (!hservice)
                return -EINVAL;

        if (!*hservice)
                return ret;

        if (!ControlService(*hservice, SERVICE_CONTROL_STOP, &svc_status)) {
                pr_err("failed to stop winring0 driver, err = %lu\n", GetLastError());
                ret = -EFAULT;
        }

        if (!DeleteService(*hservice)) {
                pr_err("failed to remove winring0 driver, err = %lu\n", GetLastError());
                ret = -EFAULT;
        }

        CloseServiceHandle(*hservice);
        *hservice = NULL;

        return ret;
}

int winring0_drv_install(SC_HANDLE *hmanager,
                         SC_HANDLE *hservice,
                         HANDLE *hdriver)
{
        char cwd[PATH_MAX] = { 0 };
        size_t pos;
        DWORD err = 0;
        int ret = 0;

        if (!hmanager || !hservice || !hdriver)
                return -EINVAL;

        if (*hdriver) {
                pr_err("winring0 driver handle is not NULL\n");
                return -EINVAL;
        }

        *hmanager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!*hmanager) {
                err = GetLastError();

                if (err == ERROR_ACCESS_DENIED) {
                        pr_err("require administrator privileges to access msr\n");
                        ret = -EPERM;
                        goto err; // TODO: handle error
                }

                pr_err("failed to open service control manager, err = %lu\n", err);
                ret = -EIO;
                goto err;
        }

        if (!GetModuleFileName(NULL, cwd, sizeof(cwd))) {
                pr_err("failed to get current directory path, err = %lu\n", GetLastError());
                goto err;
        }

        pos = strlen(cwd);
        if (pos == 0) {
                pr_err("length of current directory path = 0\n");
                goto err;
        }

        if (pos >= sizeof(cwd)) {
                pr_err("insufficient space to store current directory path\n");
                goto err;
        }

        for (pos--; pos > 0; pos--) {
                char c = cwd[pos];

                if ((c == '\\') || (c == '/')) {
                        cwd[++pos] = '\0';
                        break;
                }
        }

        pr_dbg("cwd: %s pos: %zu\n", cwd, pos);

        if ((pos + strlen(DRIVER_FILE) + 1) >= sizeof(cwd)) {
                pr_err("insufficient space to put driver name into cwd\n");
                goto err;
        }

        strncpy(&cwd[pos], DRIVER_FILE, sizeof(cwd));
        pos += strlen(DRIVER_FILE);

        // check existence of service
        *hservice = OpenService(*hmanager, SERVICE_NAME, SERVICE_ALL_ACCESS);
        if (*hservice && winring0_drv_uninstall(hservice)) {
                goto err;
        }

        *hservice = CreateService(*hmanager,
                                  SERVICE_NAME,
                                  SERVICE_NAME,
                                  SERVICE_ALL_ACCESS,
                                  SERVICE_KERNEL_DRIVER,
                                  SERVICE_DEMAND_START,
                                  SERVICE_ERROR_NORMAL,
                                  cwd,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL);
        if (!*hservice) {
                pr_err("failed to install winring0 driver, err = %lu\n", err);
                ret = -EIO;
                goto err;
        }

        if (!StartService(*hservice, 0, NULL)) {
                err = GetLastError();
                if (err != ERROR_SERVICE_ALREADY_RUNNING) {
                        pr_err("failed to start winring0 driver, err = %lu\n", err);

                        CloseServiceHandle(*hservice);
                        ret = -EIO;
                        goto err;
                }
        }

        *hdriver = CreateFile("\\\\.\\" SERVICE_NAME,
                             GENERIC_READ | GENERIC_WRITE,
                              0,
                              NULL,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
        if (*hdriver == NULL) {
                pr_err("failed to connect to winring0 driver, err = %lu\n", GetLastError());
                ret = -EIO;
                goto err;
        }

        return ret;

err:
        *hdriver = NULL;

        return ret;
}

int WINAPI Wrmsr(DWORD index, DWORD eax, DWORD edx)
{
        DWORD	returnedLength = 0;
        int	result = 0;
        DWORD	outBuf;
        OLS_WRITE_MSR_INPUT inBuf;

        inBuf.Register = index;
        inBuf.Value.HighPart = edx;
        inBuf.Value.LowPart = eax;

        if (!g_hdriver)
                return -ENODATA;

        result = DeviceIoControl(
                g_hdriver,
                IOCTL_OLS_WRITE_MSR,
                &inBuf,
                sizeof(inBuf),
                &outBuf,
                sizeof(outBuf),
                &returnedLength,
                NULL
                                );

        if (result)
                return 0;

        return -EIO;
}

int WINAPI WrmsrTx(DWORD index, DWORD eax, DWORD edx, DWORD_PTR threadAffinityMask)
{
        int		result = FALSE;
        DWORD_PTR	mask = 0;
        HANDLE		hThread = NULL;

        hThread = GetCurrentThread();
        mask = SetThreadAffinityMask(hThread, threadAffinityMask);
        if (mask == 0) {
                return FALSE;
        }

        result = Wrmsr(index, eax, edx);

        SetThreadAffinityMask(hThread, mask);

        return result;
}

int WINAPI WrmsrPx(DWORD index, DWORD eax, DWORD edx, DWORD_PTR processAffinityMask)
{
        int		result = 0;
        DWORD_PTR	processMask = 0;
        DWORD_PTR	systemMask = 0;
        HANDLE		hProcess = NULL;

        hProcess = GetCurrentProcess();
        GetProcessAffinityMask(hProcess, &processMask, &systemMask);
        if (!SetProcessAffinityMask(hProcess, processAffinityMask)) {
                return FALSE;
        }

        result = Wrmsr(index, eax, edx);

        SetProcessAffinityMask(hProcess, processMask);

        return result;
}

int WINAPI Rdmsr(DWORD index, PDWORD eax, PDWORD edx)
{
        DWORD	returnedLength = 0;
        int	result = 0;
        BYTE	outBuf[8] = {0};

        if (!g_hdriver)
                return -ENODATA;

        result = DeviceIoControl(
                g_hdriver,
                IOCTL_OLS_READ_MSR,
                &index,
                sizeof(index),
                &outBuf,
                sizeof(outBuf),
                &returnedLength,
                NULL
                );

        if (result) {
                memcpy(eax, outBuf, 4);
                memcpy(edx, outBuf + 4, 4);
        }

        if (result)
                return 0;

        return -EIO;
}

int WINAPI RdmsrTx(DWORD index, PDWORD eax, PDWORD edx, DWORD_PTR threadAffinityMask)
{
        int		result = 0;
        DWORD_PTR	mask = 0;
        HANDLE		hThread = NULL;

        hThread = GetCurrentThread();
        mask = SetThreadAffinityMask(hThread, threadAffinityMask);
        if (mask == 0) {
                return FALSE;
        }

        result = Rdmsr(index, eax, edx);

        SetThreadAffinityMask(hThread, mask);

        return result;
}

int WINAPI RdmsrPx(DWORD index, PDWORD eax, PDWORD edx, DWORD_PTR processAffinityMask)
{
        int		result = 0;
        DWORD_PTR	processMask = 0;
        DWORD_PTR	systemMask = 0;
        HANDLE		hProcess = NULL;

        hProcess = GetCurrentProcess();
        GetProcessAffinityMask(hProcess, &processMask, &systemMask);
        if (!SetProcessAffinityMask(hProcess, processAffinityMask)) {
                return FALSE;
        }

        result = Rdmsr(index, eax, edx);

        SetProcessAffinityMask(hProcess, processMask);

        return result;
}
