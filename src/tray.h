#ifndef TRAY_H
#define TRAY_H

#define WM_TRAY_CALLBACK_MESSAGE        (WM_USER + 1)
#define WC_TRAY_CLASS_NAME              L"TRAY"
#define ID_TRAY_FIRST                   (1000)

struct tray_menu {
        int                     is_end;         // menu end mark
        int                     is_separator;

        wchar_t                *name;           // must have
        UINT                    id;
        int                     disabled;       // item disabled (grey out)
        int                     checked;        // item checked

        // item click cb
        void                    (*on_click)(struct tray_menu *);
        // pre-update cb before showing menu
        void                    (*pre_show)(struct tray_menu *);

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
        struct tray_data        data;
        struct tray_icon        icon;
        struct tray_menu       *menu;
};

int tray_init(struct tray *tray, HINSTANCE ins);
int tray_loop(int blocking);
void tray_update(struct tray *tray);
void tray_exit(struct tray *tray);

#endif /* TRAY_H */