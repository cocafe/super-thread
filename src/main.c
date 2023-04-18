#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>

#include <windows.h>
#include <winuser.h>
#include <winternl.h>

#include <libjj/logging.h>
#include <libjj/opts.h>
#include <libjj/utils.h>
#include <libjj/malloc.h>

#include "gui.h"
#include "config.h"
#include "sysinfo.h"
#include "supervisor.h"
#include "superthread.h"

uint32_t g_should_exit;

void superthread_quit(void)
{
        supervisor_trigger_once(&g_sv); // to interrupt sleeping
        g_should_exit = 1;
        PostQuitMessage(0);
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

void wnd_msg_process(int blocking)
{
        MSG msg;

        while (1) {
                if (blocking) {
                        GetMessage(&msg, NULL, 0, 0);
                } else {
                        PeekMessage(&msg, NULL, 0, 0, PM_REMOVE);
                }

                if (msg.message == WM_QUIT)
                        break;

                TranslateMessage(&msg);
                DispatchMessage(&msg);
        }
}

static void sigint_handler(int dummy) {
        UNUSED_PARAM(dummy);

        pr_info("receive SIGINT\n");

        superthread_quit();
}

static BOOL HandlerRoutine(DWORD dwCtrlType)
{
        switch (dwCtrlType) {
        case CTRL_C_EVENT: // ^C event
                console_hide();
                tray_update_post(&g_tray);
                break;

        case CTRL_CLOSE_EVENT: // console is being closed
                // superthread_quit();
                break;

        case CTRL_LOGOFF_EVENT: // user is logging off
        case CTRL_SHUTDOWN_EVENT: // system is shutting down
        case CTRL_BREAK_EVENT: // ^break
        default:
                break;
        }

        return TRUE; // FALSE will pass event to next signal handler
};

extern BOOL SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT value);

int WINAPI wWinMain(HINSTANCE ins, HINSTANCE prev_ins,
                    LPWSTR cmdline, int cmdshow)
{
        UNUSED_PARAM(ins);
        UNUSED_PARAM(prev_ins);
        UNUSED_PARAM(cmdline);
        UNUSED_PARAM(cmdshow);
        int err;

        setbuf(stdout, NULL);

        heap_init();

        // this equals "System(enhanced)" in compatibility setting
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED);

        console_alloc_set(1);

        if ((err = lopts_parse(__argc, __wargv, NULL))) {
                goto out;
        }

        if ((err = logging_init()))
                goto out;

#ifndef UNICODE
        iconv_winnt_locale_init();
#endif

        if ((err = privilege_get())) {
                mb_err("failed to get privileges");
                goto exit_logging;
        }

        if ((err = sysinfo_init(&g_sys_info))) {
                mb_err("failed to get system information");
                goto exit_logging;
        }

        if ((err = usrcfg_init())) {
                mb_err("failed to load config: \"%s\"", g_cfg.json_path);
                goto exit_sysinfo;
        }

        gui_init();

        if (!g_console_show)
                console_hide();

        if ((err = superthread_tray_init(ins))) {
                mb_err("failed to init tray\n");
                goto exit_usrcfg;
        }

        supervisor_init(&g_sv);

        supervisor_run(&g_sv);

        if (g_console_alloc) {
                while (!IsWindowEnabled(g_console_hwnd))
                        Sleep(1);

                // if HANDLER is NULL, and TRUE is set, console will ignore ^C
                // TRUE: add handler
                // FALSE: remove handler
                SetConsoleCtrlHandler(HandlerRoutine, TRUE);

                // XXX: racing with console window initialization
                console_title_set(L"super-thread (^C to hide console)");
        } else {
                signal(SIGINT, sigint_handler);
        }

        wnd_msg_process(1);

        if (profile_wnd_tid)
                pthread_join(profile_wnd_tid, NULL);

        supervisor_deinit(&g_sv);

        superthread_tray_deinit();

        gui_deinit();

exit_usrcfg:
        usrcfg_deinit();

exit_sysinfo:
        sysinfo_deinit(&g_sys_info);

exit_logging:
        logging_exit();

out:
        return err;
}
