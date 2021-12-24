#include <stdio.h>

#ifdef __WINNT__
#include <fcntl.h>
#include <windows.h>
#endif

#include "logging.h"

uint32_t g_verbose_print = 0;

#ifdef __WINNT__

uint32_t g_console_host_init = 1;

int console_init(void)
{
        if (AllocConsole() == 0) {
                pr_err("AllocConsole(), err = %lu\n", GetLastError());
                return -1;
        }

        return 0;
}

int console_deinit(void)
{
        if (FreeConsole() == 0) {
                pr_err("FreeConsole(), err = %lu\n", GetLastError());
                return -1;
        }

        return 0;
}

void console_stdio_redirect(void)
{
        HANDLE ConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        int SystemOutput = _open_osfhandle((intptr_t)ConsoleOutput, _O_TEXT);
        FILE *COutputHandle = _fdopen(SystemOutput, "w");

        HANDLE ConsoleError = GetStdHandle(STD_ERROR_HANDLE);
        int SystemError = _open_osfhandle((intptr_t)ConsoleError, _O_TEXT);
        FILE *CErrorHandle = _fdopen(SystemError, "w");

        HANDLE ConsoleInput = GetStdHandle(STD_INPUT_HANDLE);
        int SystemInput = _open_osfhandle((intptr_t)ConsoleInput, _O_TEXT);
        FILE *CInputHandle = _fdopen(SystemInput, "r");

        freopen_s(&CInputHandle, "CONIN$", "r", stdin);
        freopen_s(&COutputHandle, "CONOUT$", "w", stdout);
        freopen_s(&CErrorHandle, "CONOUT$", "w", stderr);
}
#endif

int logging_init(void)
{
#ifdef __WINNT__
        if (g_console_host_init) {
                if (console_init())
                        return -1;

                console_stdio_redirect();
        }
#endif

        return 0;
}

int logging_exit(void)
{
#ifdef __WINNT__
        if (g_console_host_init && console_deinit())
                return -1;
#endif

        return 0;
}