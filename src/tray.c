#include <stdio.h>
#include <errno.h>

#include <windows.h>
#include <shellapi.h>

#include "logging.h"

#define WM_TRAY_CALLBACK_MESSAGE        (WM_USER + 1)
#define WC_TRAY_CLASS_NAME              "TRAY"
#define ID_TRAY_FIRST                   (1000)

struct tray_menu {
        int                     is_end;

        char                   *name;
        UINT                    id;
        int                     disabled;
        int                     checked;
        int                     separator;

        void                    (*cb)(struct tray_menu *);

        void                   *userdata;

        struct tray_menu       *submenu;
};

struct tray_data {
        WNDCLASSEX      wc;
        NOTIFYICONDATA  nid;
        HWND            hwnd;
        HMENU           hmenu;
        char           *icon_path;
        char           *icon_last;
};

struct tray {
        struct tray_data data;
        struct tray_menu *menu;
};

// TODO: thread sync?

static LRESULT CALLBACK tray_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
        struct tray *tray = (void *)GetWindowLongPtr(hwnd, GWLP_USERDATA);

        switch (msg) {
        case WM_CLOSE:
                DestroyWindow(hwnd);
                goto out;

        case WM_DESTROY:
                PostQuitMessage(0);
                goto out;

        case WM_TRAY_CALLBACK_MESSAGE:
                if (!tray)
                        break;

                if (lparam == WM_LBUTTONUP || lparam == WM_RBUTTONUP) {
                        HMENU hmenu = tray->data.hmenu;
                        POINT p;
                        WORD cmd;

                        GetCursorPos(&p);
                        SetForegroundWindow(hwnd);

                        cmd = TrackPopupMenu(hmenu,
                                             TPM_LEFTALIGN |
                                             TPM_RIGHTBUTTON |
                                             TPM_RETURNCMD |
                                             TPM_NONOTIFY,
                                             p.x, p.y,
                                             0,
                                             hwnd,
                                             NULL);
                        SendMessage(hwnd, WM_COMMAND, cmd, 0);

                        goto out;
                }

                break;

        case WM_COMMAND:
                if (!tray)
                        break;

                if (wparam >= ID_TRAY_FIRST) {
                        struct tray_menu *menu = NULL;
                        HMENU hmenu = tray->data.hmenu;
                        MENUITEMINFO item = {
                                .cbSize = sizeof(MENUITEMINFO),
                                .fMask = MIIM_ID | MIIM_DATA,
                        };

                        if (GetMenuItemInfo(hmenu, wparam, FALSE, &item)) {
                                menu = (void *)item.dwItemData;
                                if (menu && menu->cb != NULL)
                                        menu->cb(menu);
                        }

                        goto out;
                }

                break;

        default:
                break;
        }

        return DefWindowProc(hwnd, msg, wparam, lparam);

out:
        return 0;
}

HMENU tray_menu_update(struct tray_menu *m, UINT *id)
{
        HMENU hmenu = CreatePopupMenu();
        MENUITEMINFO item;

        for (; m != NULL; m++, (*id)++) {
                if (m->is_end)
                        break;

                if (m->separator) {
                        InsertMenu(hmenu, *id, MF_SEPARATOR, TRUE, "");
                        m->id = *id;
                        continue;
                }

                if (!m->name)
                        continue;

                memset(&item, 0x00, sizeof(item));
                item.cbSize = sizeof(MENUITEMINFO);
                item.fMask = MIIM_ID | MIIM_TYPE | MIIM_STATE | MIIM_DATA;
                item.fType = 0;
                item.fState = 0;

                if (m->disabled)
                        item.fState |= MFS_DISABLED;

                if (m->checked)
                        item.fState |= MFS_CHECKED;

                if (m->submenu != NULL) {
                        item.fMask |= MIIM_SUBMENU;
                        item.hSubMenu = tray_menu_update(m->submenu, id);
                }

                // @id may change after creating sub menu
                item.wID = *id;
                item.dwTypeData = m->name;
                item.dwItemData = (ULONG_PTR)m;

                InsertMenuItem(hmenu, *id, TRUE, &item);
                m->id = *id;
        }

        return hmenu;
}

void tray_icon_update(struct tray *tray)
{
        NOTIFYICONDATA *nid = &tray->data.nid;
        HICON hicon = NULL;
        int ret;

        if (tray->data.icon_path == tray->data.icon_last)
                return;

        if (!tray->data.icon_path) {
                pr_dbg("icon path is NULL, clear icon\n");
                goto update_icon;
        }

        ret = ExtractIconEx(tray->data.icon_path, 0, NULL, &hicon, 0);
        if (ret == -1) {
                pr_err("failed to load icon: %s\n", tray->data.icon_path);
                hicon = NULL;
        }

update_icon:
        if (nid->hIcon) {
                DestroyIcon(nid->hIcon);
                nid->hIcon = NULL;
        }

        nid->hIcon = hicon;
        Shell_NotifyIcon(NIM_MODIFY, nid);

        tray->data.icon_last = tray->data.icon_path;
}

void tray_update(struct tray *tray)
{
        HMENU prevmenu = tray->data.hmenu;
        HMENU hmenu = prevmenu;
        UINT id = ID_TRAY_FIRST;

        tray->data.hmenu = tray_menu_update(tray->menu, &id);

        SendMessage(tray->data.hwnd, WM_INITMENUPOPUP, (WPARAM)hmenu, 0);

        tray_icon_update(tray);

        if (prevmenu != NULL) {
                DestroyMenu(prevmenu);
        }
}

int tray_init(struct tray *tray)
{
        WNDCLASSEX *wc;
        NOTIFYICONDATA *nid;
        HWND hwnd;

        if (!tray)
                return -EINVAL;

        wc = &tray->data.wc;
        memset(wc, 0, sizeof(WNDCLASSEX));
        wc->cbSize = sizeof(WNDCLASSEX);
        wc->lpfnWndProc = tray_wnd_proc;
        wc->hInstance = GetModuleHandle(NULL);
        wc->lpszClassName = WC_TRAY_CLASS_NAME;
        if (!RegisterClassEx(wc)) {
                // printf()
                return -EFAULT;
        }

        hwnd = CreateWindowEx(0, WC_TRAY_CLASS_NAME, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        if (hwnd == NULL) {
                // printf()
                return -EFAULT;
        }

        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)tray);
        UpdateWindow(hwnd);
        tray->data.hwnd = hwnd;

        nid = &tray->data.nid;
        memset(nid, 0, sizeof(NOTIFYICONDATA));
        nid->cbSize = sizeof(NOTIFYICONDATA);
        nid->hWnd = hwnd;
        nid->uID = 0;
        nid->uFlags = NIF_ICON | NIF_MESSAGE;
        nid->uCallbackMessage = WM_TRAY_CALLBACK_MESSAGE;
        Shell_NotifyIcon(NIM_ADD, nid);

        tray_update(tray);

        return 0;
}

void tray_exit(struct tray *tray)
{
        NOTIFYICONDATA *nid;
        HMENU hmenu;

        if (!tray)
                return;

        nid = &tray->data.nid;
        hmenu = tray->data.hmenu;

        Shell_NotifyIcon(NIM_DELETE, nid);

        if (nid->hIcon) {
                DestroyIcon(nid->hIcon);
                nid->hIcon = NULL;
        }

        if (hmenu != 0) {
                DestroyMenu(hmenu);
                tray->data.hmenu = NULL;
        }

        PostQuitMessage(0);
        UnregisterClass(WC_TRAY_CLASS_NAME, GetModuleHandle(NULL));
}

int tray_loop(int blocking) {
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

        return 0;
}

//
//
//

#define TRAY_ICON1 "icon1.ico"
#define TRAY_ICON2 "icon2.ico"

struct tray tray;

static void toggle_cb(struct tray_menu *item) {
        printf("toggle cb\n");
        item->checked = !item->checked;
        tray_update(&tray);
}

static void hello_cb(struct tray_menu *item) {
        (void)item;

        printf("hello cb: item->name: %s item->id: %d\n", item->name, item->id);

        if (strcmp(tray.data.icon_path, TRAY_ICON1) == 0) {
                tray.data.icon_path = TRAY_ICON2;
        } else {
                tray.data.icon_path = TRAY_ICON1;
        }

        tray_update(&tray);
}

static void quit_cb(struct tray_menu *item) {
        (void)item;
        printf("quit cb\n");

        tray_exit(&tray);
}

static void submenu_cb(struct tray_menu *item) {
        (void)item;

        printf("submenu: clicked on %s, id: %d\n", item->name, item->id);

        item->checked = !item->checked;

        tray_update(&tray);
}

struct tray tray = {
        .data = {
                .icon_path = TRAY_ICON1,
        },
        .menu = (struct tray_menu[]) {
                { .name = "\xb9\xfe\xb9\xfe", .cb = hello_cb },
                { .name = "Checked", .checked = 1, .cb = toggle_cb },
                { .name = "Disabled", .disabled = 1 },
                { .separator = 1 },
                {
                        .name = "Sub Menu",
                        .submenu = (struct tray_menu[]) {
                                { .name = "I", .checked = 1, .cb = submenu_cb },
                                {
                                        .name = "II",
                                        .submenu = (struct tray_menu[]) {
                                                {
                                                        .name = "III",
                                                        .cb = submenu_cb
                                                },
                                                { .is_end = 1 },
                                        },
                                },
                                { .is_end = 1 },
                        },
                },
                { .separator = 1 },
                { .name = "Quit", .cb = quit_cb },
                { .is_end = 1 }
        }
};

//void console_init(void);
//void console_deinit(void);
//void console_stdio_redirect(void);
//
//#include <OlsApi.h>
//#include <OlsDef.h>
//
//int WINAPI WinMain(HINSTANCE ins, HINSTANCE prev_ins,
//                   LPSTR cmdline, int cmdshow)
//{
//        (void)ins;
//        (void)prev_ins;
//        (void)cmdline;
//        (void)cmdshow;
//
//        console_init();
//        console_stdio_redirect();
//
//        if (InitializeOls() == FALSE) {
//                printf("failed to init winring0\n");
//                return 2;
//        }
//
//        {
//                switch (GetDllStatus()) {
//                case OLS_DLL_NO_ERROR:
//                        break;
//
//                case OLS_DLL_UNSUPPORTED_PLATFORM:
//                        printf("DLL Status Error!! UNSUPPORTED_PLATFORM\n");
//                        goto winring0_free;
//
//                case OLS_DLL_DRIVER_NOT_LOADED:
//                        printf("DLL Status Error!! DRIVER_NOT_LOADED\n");
//                        goto winring0_free;
//
//                case OLS_DLL_DRIVER_NOT_FOUND:
//                        printf("DLL Status Error!! DRIVER_NOT_FOUND\n");
//                        goto winring0_free;
//
//                case OLS_DLL_DRIVER_UNLOADED:
//                        printf("DLL Status Error!! DRIVER_UNLOADED\n");
//                        goto winring0_free;
//
//                case OLS_DLL_DRIVER_NOT_LOADED_ON_NETWORK:
//                        printf("DLL Status Error!! DRIVER_NOT_LOADED_ON_NETWORK\n");
//                        goto winring0_free;
//
//                case OLS_DLL_UNKNOWN_ERROR:
//                default:
//                        printf("DLL Status Error!! UNKNOWN_ERROR\n");
//                        goto winring0_free;
//                }
//        }
//
//        {
//                DWORD eax = 0, edx = 0;
//                if (Rdmsr(0x620, &eax, &edx) == FALSE)
//                        printf("rdmsr() failed\n");
//
//                printf("msr 0x620: 0x%08lx 0x%08lx\n", eax, edx);
//        }
//
//        {
//                DWORD eax = 0, edx = 0;
//                if (Wrmsr(0xe2, eax, edx) == FALSE)
//                        printf("wrmsr() failed\n");
//        }
//
////        GetCurrentDirectory();
////        OpenProcess()
//
//        if (tray_init(&tray)) {
//                return 1;
//        }
//
//        tray_loop(1);
//
//        console_deinit();
//
//winring0_free:
//        DeinitializeOls();
//
//        return 0;
//}
