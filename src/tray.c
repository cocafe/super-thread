#include <stdio.h>
#include <errno.h>

#include <windows.h>
#include <winuser.h>
#include <shellapi.h>

#include <resource.h>
#include "logging.h"
#include "tray.h"

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
                        InsertMenu(hmenu, *id, MF_SEPARATOR, TRUE, L"");
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

        if (tray->icon.id > 0) {
                if (tray->icon.id == tray->icon.id_last)
                        return;

                hicon = LoadIcon(tray->data.ins, MAKEINTRESOURCE(tray->icon.id));
                if (hicon == NULL) {
                        pr_err("LoadIcon() failed, err=%lu\n", GetLastError());
                        goto update_icon;
                }

                tray->icon.id_last = tray->icon.id;
        } else if (tray->icon.path != NULL) {
                int ret;

                if (!wcsncmp(tray->icon.path, tray->icon.path_last, wcslen(tray->icon.path_last)))
                        return;

                ret = ExtractIconEx(tray->icon.path, 0, NULL, &hicon, 0);
                if (ret == -1) {
                        pr_err("ExtractIconEx() failed for path: %ls, err=%lu\n", tray->icon.path, GetLastError());
                        goto update_icon;
                }

                wcsncpy(tray->icon.path_last, tray->icon.path, WCBUF_LEN(tray->icon.path_last));
        } else {
                pr_verbose("neither icon path or id are defined\n");
        }

update_icon:
        if (nid->hIcon) {
                DestroyIcon(nid->hIcon);
                nid->hIcon = NULL;
        }

        nid->hIcon = hicon;
        Shell_NotifyIcon(NIM_MODIFY, nid);
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

int tray_init(struct tray *tray, HINSTANCE ins)
{
        WNDCLASSEX *wc;
        NOTIFYICONDATA *nid;
        HWND hwnd;

        if (!tray)
                return -EINVAL;

        wc = &tray->data.wc;
        memset(wc, 0x00, sizeof(WNDCLASSEX));
        wc->cbSize              = sizeof(WNDCLASSEX);
        wc->lpfnWndProc         = tray_wnd_proc;
        wc->hInstance           = GetModuleHandle(NULL);
        wc->lpszClassName       = WC_TRAY_CLASS_NAME;
        if (!RegisterClassEx(wc)) {
                pr_err("RegisterClassEx() failed\n");
                return -EFAULT;
        }

        hwnd = CreateWindowEx(0, WC_TRAY_CLASS_NAME, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        if (hwnd == NULL) {
                pr_err("CreateWindowEx() failed\n");
                return -EFAULT;
        }

        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)tray);
        UpdateWindow(hwnd);
        tray->data.hwnd = hwnd;

        tray->data.ins = ins;

        nid = &tray->data.nid;
        memset(nid, 0, sizeof(NOTIFYICONDATA));
        nid->cbSize             = sizeof(NOTIFYICONDATA);
        nid->hWnd               = hwnd;
        nid->uID                = 0;
        nid->uFlags             = NIF_ICON | NIF_MESSAGE;
        nid->uCallbackMessage   = WM_TRAY_CALLBACK_MESSAGE;
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
