#ifndef TRAY_H
#define TRAY_H

#define WM_TRAY_CALLBACK_MESSAGE        (WM_USER + 1)
#define WC_TRAY_CLASS_NAME              L"TRAY"
#define ID_TRAY_FIRST                   (1000)

struct tray_menu {
        int                     is_end;

        wchar_t                *name;
        UINT                    id;
        int                     disabled;
        int                     checked;
        int                     separator;

        void                    (*cb)(struct tray_menu *);

        void                   *userdata;

        struct tray_menu       *submenu;
};

struct tray_data {
        HINSTANCE       ins;
        WNDCLASSEX      wc;
        NOTIFYICONDATA  nid;
        HWND            hwnd;
        HMENU           hmenu;
};

struct tray_icon {
        wchar_t        *path;
        wchar_t         path_last[_MAX_PATH];
        int             id;     // icon id is preferred, id > 0
        int             id_last;
};

struct tray {
        struct tray_data data;
        struct tray_icon icon;
        struct tray_menu *menu;
};

int tray_init(struct tray *tray, HINSTANCE ins);
int tray_loop(int blocking);
void tray_update(struct tray *tray);
void tray_exit();

#endif /* TRAY_H */