#define IDR_SHOW                (12)
#define IDR_QUIT                (13)
#define IDR_START               (14)
#define IDR_STOP                (15)

#define PROGRAM_NAME            "tray demo"

#define mb_info(msg)                                                    \
        do {                                                            \
            MessageBox(NULL, (msg), NULL, MB_ICONINFORMATION | MB_OK);  \
        } while(0)

#define mb_err(msg)                                                     \
        do {                                                            \
            MessageBox(NULL, (msg), NULL, MB_ICONERROR | MB_OK);        \
        } while(0)


struct menu_item {
        UINT item;
        LPCSTR name;
};

HMENU tray_menu;

struct menu_item menuitmes[] = {
        { IDR_START, "start" },
        { IDR_STOP,  "stop"  },
        { IDR_SHOW,  "show"  },
        { IDR_QUIT,  "exit"  },
};

#if 0
LRESULT CALLBACK wnd_cb(HWND wnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
        NOTIFYICONDATA icon;
        UINT event;
        UINT select;
        POINT curpt;

        memset(&icon, 0x00, sizeof(icon));
        memset(&curpt, 0x00, sizeof(curpt));

        printf("%s(): GetWindowLongPtr(): %p\n", __func__, GetWindowLongPtr(wnd, GWLP_USERDATA));

        event = RegisterWindowMessage("TaskbarCreated");

        switch (msg) {
        case WM_CREATE:
                icon.cbSize = sizeof(NOTIFYICONDATA);
                icon.hWnd = wnd;
                icon.uID = 0;
                icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
                icon.uCallbackMessage = WM_USER;
                icon.hIcon = LoadIcon(NULL, IDI_HAND);
                strcpy(icon.szTip, "tray demo tip");

                if (!Shell_NotifyIcon(NIM_ADD, &icon)) {
                        mb_err("failed to init taskbar icon");
                        break;
                }

                tray_menu = CreatePopupMenu();
                if (!tray_menu) {
                        mb_err("failed to create tray menu handle");
                        break;
                }

                for (size_t i = 0; i < ARRAY_SIZE(menuitmes); i++) {
                        AppendMenu(tray_menu, MF_STRING,
                                   menuitmes[i].item, menuitmes[i].name);
                }

                break;

        case WM_USER:
                if (!GetWindowLongPtr(wnd, GWLP_USERDATA))
                        break;

                switch (lparam) {
                case WM_LBUTTONDOWN:
                case WM_RBUTTONDOWN:
                        GetCursorPos(&curpt);
                        SetForegroundWindow(wnd);

                        select = TrackPopupMenu(tray_menu,
                                                TPM_RETURNCMD,
                                                curpt.x, curpt.y,
                                                0,
                                                wnd,
                                                NULL);
                        switch (select) {
                        case IDR_SHOW:
                                mb_info("SHOW");
                                break;

                        case IDR_START:
                                mb_info("START");
                                break;

                        case IDR_STOP:
                                mb_info("STOP");
                                break;

                        case IDR_QUIT:
                                SendMessage(wnd, WM_DESTROY, wparam, lparam);
                                break;

                        default:
                                printf("unknown menu id %d\n", select);
                                break;
                        }

                        break;

                case WM_LBUTTONDBLCLK:
                        SendMessage(wnd, WM_DESTROY, wparam, lparam);
                        break;

                default:
                        break;
                }
                break;

        case WM_DESTROY:
                mb_info("SHELL ICON EXIT");
                Shell_NotifyIcon(NIM_DELETE, &icon);
                PostQuitMessage(EXIT_SUCCESS);
                break;

        default:
                if (msg == event)
                        SendMessage(wnd, WM_CREATE, wparam, lparam);

                break;
        }

        return DefWindowProc(wnd, msg, wparam, lparam);
}

int WINAPI WinMain(HINSTANCE ins, HINSTANCE prev_ins,
                   LPSTR cmdline, int cmdshow)
{
        HWND wnd;
        MSG msg;
        WNDCLASSEX wc;

        int aaa = 233;

        (void)cmdline;
        (void)prev_ins;

//        mb_info("CLICK TO START!");

        console_init();
        console_stdio_redirect();

        printf("%s(): &aaa: %p\n", __func__, &aaa);

        memset(&wc, 0x00, sizeof(wc));

        wc.cbSize = sizeof(WNDCLASSEX);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = wnd_cb;
        wc.hInstance = ins;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
        wc.lpszClassName = "tray demo";

        if (!RegisterClassEx(&wc)) {
                mb_err("failed to init window class");
                return -EFAULT;
        }

        wnd = CreateWindowEx(WS_EX_TOOLWINDOW,
                             PROGRAM_NAME,
                             PROGRAM_NAME,
                             WS_POPUP,
                             CW_USEDEFAULT,
                             CW_USEDEFAULT,
                             CW_USEDEFAULT,
                             CW_USEDEFAULT,
                             NULL,
                             NULL,
                             ins,
                             &aaa);
        if (!wnd) {
                mb_err("failed to create window");
                return -EFAULT;
        }

        SetWindowLongPtr(wnd, GWLP_USERDATA, &aaa);
        ShowWindow(wnd, cmdshow);
        UpdateWindow(wnd);

        while (GetMessage(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
        }

        mb_info("FINISH!");

        console_deinit();

        return 0;
}
#endif