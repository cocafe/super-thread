#ifndef TRAY_H
#define TRAY_H

#include <pthread.h>

#include <windows.h>
#include <winuser.h>

#define WM_TRAY_CALLBACK_MSG            (WM_USER + 1)
#define WM_TRAY_UPDATE_MSG              (WM_USER + 2)

#define WC_TRAY_CLASS_NAME              L"TRAY"

#define MENU_ITEM_ID_BEGIN              (1000)

#define TRAY_UPDATE_MAGIC               (0x5aa1)

struct tray;

typedef void (*tray_click_cb)(struct tray *tray, void *userdata);

struct tray_menu {
        int                     is_end;         // menu end mark
        int                     is_separator;

        wchar_t                *name;           // must have
        UINT                    id;
        int                     disabled;       // item disabled (grey out)
        int                     checked;        // item checked
        int                     highlighted;

        // item click cb
        void                    (*on_click)(struct tray_menu *);
        // pre-update cb before showing menu
        void                    (*pre_show)(struct tray_menu *);

        void                   *userdata;
        void                   *userdata2;

        struct tray_menu       *submenu;
};

struct tray_data {
        pthread_mutex_t update_lck;

        HINSTANCE       ins;

        WNDCLASSEX      wc;

        NOTIFYICONDATA  nid;

        HWND            hwnd;
        HMENU           hmenu;
        UINT            max_menu_id;

        void           *userdata;

        struct timespec last_click;
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

        // tray icon click callback
        tray_click_cb           lbtn_click;
        tray_click_cb           lbtn_dblclick;
};

int tray_init(struct tray *tray, HINSTANCE ins);
void tray_exit(struct tray *tray);

void tray_update_post(struct tray *tray);
void tray_update(struct tray *tray);

int tray_loop(int blocking);

int tray_click_cb_set(struct tray *tray, void *userdata,
                      tray_click_cb lbtn_click, tray_click_cb lbtn_dblclick);

struct tray_menu *tray_menu_alloc_copy(struct tray_menu *src);
void tray_menu_recursive_free(struct tray_menu *m);
#endif /* TRAY_H */