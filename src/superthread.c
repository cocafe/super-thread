#include <windows.h>

#include <resource.h>

#include <libjj/utils.h>
#include <libjj/logging.h>
#include <libjj/opts.h>

#include "tray.h"
#include "config.h"
#include "supervisor.h"
#include "superthread.h"

#define TRAY_MENU_PROFILES                      L"Profile"

struct config g_cfg = {
        .sampling_sec = SAMPLING_SEC_DEF,
        .json_path = JSON_CFG_PATH_DEF,
};

struct tray_menu *g_profile_menu;
uint32_t g_should_exit;
jbuf_t jbuf_usrcfg;

lsopt_strbuf(c, json_path, g_cfg.json_path, sizeof(g_cfg.json_path), "JSON config path");

void superthread_quit(void)
{
        supervisor_trigger_once(&g_sv); // to interrupt sleeping
        g_should_exit = 1;
        PostQuitMessage(0);
}

//
// tray gui
//

static void quit_cb(struct tray_menu *m) {
        UNUSED_PARAM(m);
        superthread_quit();
}

static void trigger_click(struct tray_menu *m) {
        UNUSED_PARAM(m);

        supervisor_trigger_once(&g_sv);

        pr_raw("TRIGGERED ONCE\n");
}

static void pause_click(struct tray_menu *m) {
        struct tray *t = m->userdata;

        m->checked = !m->checked;
        g_sv.paused = m->checked;

        if (g_sv.paused)
                t->icon.id = IDI_APP_ICON_DISABLED;
        else
                t->icon.id = IDI_APP_ICON;

        pr_raw("<!> %s <!>\n", m->checked ? "PAUSED" : "CONTINUE");
}

static void pause_update(struct tray_menu *m)
{
        if (g_sv.paused)
                m->checked = 1;
        else
                m->checked = 0;
}

static void console_show_click(struct tray_menu *m)
{
        if (!g_console_alloc)
                return;

        m->checked = !m->checked;

        if (m->checked) {
                g_console_show = 1;
                console_show(1);

                pr_raw("====================================================================\n");
                pr_raw("=== CLOSE THIS LOGGING WINDOW WILL TERMINATE PROGRAM, ^C TO HIDE ===\n");
                pr_raw("====================================================================\n");

                return;
        }

        g_console_show = 0;
        console_hide();
}

static void console_show_update(struct tray_menu *m)
{
        if (!g_console_alloc) {
                m->checked = 0;
                m->disabled = 1;
                return;
        }

        if (is_console_hid())
                m->checked = 0;
        else
                m->checked = 1;
}

static void loglvl_click(struct tray_menu *m)
{
        uint32_t level = (size_t)m->userdata;

        m->checked = !m->checked;

        if (m->checked) {
                g_logprint_level |= level;
        } else {
                g_logprint_level &= ~level;
        }
}

static void loglvl_update(struct tray_menu *m)
{
        uint32_t level = (size_t)m->userdata;

        if (g_logprint_level & level)
                m->checked = 1;
        else
                m->checked = 0;
}

static void save_click(struct tray_menu *m)
{
        char *path = g_cfg.json_path;
        UNUSED_PARAM(m);

        if (usrcfg_save()) {
                mb_err("usrcfg_save() failed\n");
                return;
        }

        if (jbuf_save(&jbuf_usrcfg, path)) {
                mb_err("failed to save json to \"%s\"", path);
                return;
        }

        pr_raw("saved json config: %s\n", path);
}

void tray_lbtn_click(struct tray *tray, void *data)
{
        UNUSED_PARAM(data);

        if (is_console_hid())
                console_show(1);
        else
                console_hide();

        tray_update_post(tray);
}

struct tray g_tray = {
        .icon = {
                .path = NULL,
                .id = IDI_APP_ICON,
        },
        .menu = (struct tray_menu[]) {
                { .name = L"Trigger Once", .on_click = trigger_click },
                { .name = L"Pause", .pre_show = pause_update, .on_click = pause_click, .userdata = &g_tray },
                { .is_separator = 1 },
                { .name = TRAY_MENU_PROFILES, .disabled = 1, .submenu = NULL },
                { .is_separator = 1 },
                {
                        .name = L"Logging",
                        .submenu = (struct tray_menu[]) {
                                { .name = L"Show", .pre_show = console_show_update, .on_click = console_show_click },
                                { .is_separator = 1 },
                                { .name = L"Verbose", .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_VERBOSE },
                                { .name = L"Debug",   .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_DEBUG   },
                                { .name = L"Info",    .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_INFO    },
                                { .name = L"Notice",  .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_NOTICE  },
                                { .name = L"Warning", .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_WARN    },
                                { .name = L"Error",   .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_ERROR   },
                                { .name = L"Fatal",   .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_FATAL   },
                                { .is_end = 1 },
                        },
                },
                { .is_separator = 1 },
                { .name = L"Save", .on_click = save_click },
                { .is_separator = 1 },
                { .name = L"Quit", .on_click = quit_cb },
                { .is_end = 1 }
        },
        .lbtn_click = tray_lbtn_click,
        .lbtn_dblclick = NULL,
};

struct tray_menu *profile_menu_find(struct tray_menu *top_menu)
{
        struct tray_menu *m = top_menu;
        int found = 0;

        for (size_t i = 0; !m->is_end; i++, m = &top_menu[i]) {
                if (m->name && is_wstr_equal(TRAY_MENU_PROFILES, m->name)) {
                        found = 1;
                        break;
                }
        }

        if (!found)
                return NULL;

        return m;
}

#define PROFILE_BOOL_SWITCH(name, type, offset) \
static void profile_##name##_update(struct tray_menu *m)        \
{                                                               \
        profile_t *profile = m->userdata;                       \
        type *val = (void *)((uint8_t *)profile + offset);      \
                                                                \
        if (*val)                                               \
                m->checked = 1;                                 \
        else                                                    \
                m->checked = 0;                                 \
}                                                               \
static void profile_##name##_click(struct tray_menu *m)         \
{                                                               \
        profile_t *profile = m->userdata;                       \
        type *val = (void *)((uint8_t *)profile + offset);      \
                                                                \
        m->checked = !m->checked;                               \
                                                                \
        if (m->checked)                                         \
                *val = 1;                                       \
        else                                                    \
                *val = 0;                                       \
}

#define PROFILE_VALUE_SWITCH(name, type, offset)                \
static void profile_##name##_update(struct tray_menu *m)        \
{                                                               \
        profile_t *profile = m->userdata;                       \
        type value = (type)((size_t)m->userdata2);              \
        type *target = (void *)((uint8_t *)profile + offset);   \
                                                                \
        m->checked = *target == value;                          \
}                                                               \
static void profile_##name##_click(struct tray_menu *m)         \
{                                                               \
        profile_t *profile = m->userdata;                       \
        type value = (type)((size_t)m->userdata2);              \
        type *target = (void *)((uint8_t *)profile + offset);   \
                                                                \
        if (*target == value)                                   \
                return;                                         \
                                                                \
        *target = value;                                        \
}

PROFILE_BOOL_SWITCH(enabled,    uint32_t, offsetof(profile_t, enabled));
PROFILE_BOOL_SWITCH(oneshot,    uint32_t, offsetof(profile_t, oneshot));
PROFILE_BOOL_SWITCH(always_set, uint32_t, offsetof(profile_t, always_set));

PROFILE_VALUE_SWITCH(sched_mode,          uint32_t, offsetof(profile_t, sched_mode));

PROFILE_VALUE_SWITCH(proc_cfg_prio_class, uint32_t, offsetof(profile_t, proc_cfg.prio_class));
PROFILE_VALUE_SWITCH(proc_cfg_prio_boost, uint32_t, offsetof(profile_t, proc_cfg.prio_boost));
PROFILE_VALUE_SWITCH(proc_cfg_io_prio,    uint32_t, offsetof(profile_t, proc_cfg.io_prio));
PROFILE_VALUE_SWITCH(proc_cfg_page_prio,  uint32_t, offsetof(profile_t, proc_cfg.page_prio));

PROFILE_BOOL_SWITCH(thrd_cfg_prio_least,  uint32_t, offsetof(profile_t, thrd_cfg.prio_level_least));

PROFILE_VALUE_SWITCH(thrd_cfg_prio_level, uint32_t, offsetof(profile_t, thrd_cfg.prio_level));
PROFILE_VALUE_SWITCH(thrd_cfg_prio_boost, uint32_t, offsetof(profile_t, thrd_cfg.prio_boost));
PROFILE_VALUE_SWITCH(thrd_cfg_io_prio,    uint32_t, offsetof(profile_t, thrd_cfg.io_prio));
PROFILE_VALUE_SWITCH(thrd_cfg_page_prio,  uint32_t, offsetof(profile_t, thrd_cfg.page_prio));

static void profile_delayed_update(struct tray_menu *m)
{
        profile_t *profile = m->userdata;

        if (profile->delay)
                m->checked = 1;
        else
                m->checked = 0;
}

static void profile_sub_menu_update(struct tray_menu *m) {
        for (struct tray_menu *sub = m->submenu; sub; sub++) {
                if (sub->is_end)
                        break;

                if (sub->name && sub->name[0] != L'\0')
                        sub->userdata = m->userdata;
        }
}

static void profile_proc_thread_dump(struct tray_menu *m)
{
        profile_t *profile = m->userdata;

        // FIXME: not thread-safe, need lock

        profile_processes_info_dump(&g_sv.proc_selected, profile);
}

static struct tray_menu profile_menu_template[] = {
        { .name = L"Enabled", .pre_show = profile_enabled_update, .on_click = profile_enabled_click },
        { .is_separator = 1 },
        {
                .name = L"Mode",
                .pre_show = profile_sub_menu_update,
                .submenu = (struct tray_menu[]) {
                        {
                                .name = L"Processes",
                                .pre_show = profile_sched_mode_update,
                                .on_click = profile_sched_mode_click,
                                .userdata2 = (void *)SUPERVISOR_PROCESSES,
                        },
                        {
                                .name = L"Threads",
                                .pre_show = profile_sched_mode_update,
                                .on_click = profile_sched_mode_click,
                                .userdata2 = (void *)SUPERVISOR_THREADS,
                        },
                        { .is_end = 1 },
                },
        },
        {
                .name = L"Process",
                .pre_show = profile_sub_menu_update,
                .submenu = (struct tray_menu[]) {
                        {
                                .name = L"Priority Boost",
                                .pre_show = profile_sub_menu_update,
                                .submenu = (struct tray_menu[]) {
                                        {
                                                .name = L"Leave as-is",
                                                .pre_show = profile_proc_cfg_prio_boost_update,
                                                .on_click = profile_proc_cfg_prio_boost_click,
                                                .userdata2 = (void *)LEAVE_AS_IS,
                                        },
                                        {
                                                .is_separator = 1
                                        },
                                        {
                                                .name = L"Enabled",
                                                .pre_show = profile_proc_cfg_prio_boost_update,
                                                .on_click = profile_proc_cfg_prio_boost_click,
                                                .userdata2 = (void *)STRVAL_ENABLED,
                                        },
                                        {
                                                .name = L"Disabled",
                                                .pre_show = profile_proc_cfg_prio_boost_update,
                                                .on_click = profile_proc_cfg_prio_boost_click,
                                                .userdata2 = (void *)STRVAL_DISABLED,
                                        },
                                        {.is_end = 1},
                                },
                        },
                        {
                                .name = L"Priority Class",
                                .pre_show = profile_sub_menu_update,
                                .submenu = (struct tray_menu[]) {
                                        {
                                                .name = L"Leave as-is",
                                                .pre_show = profile_proc_cfg_prio_class_update,
                                                .on_click = profile_proc_cfg_prio_class_click,
                                                .userdata2 = (void *)PROC_PRIO_CLS_UNCHANGED,
                                        },
                                        {
                                                .is_separator = 1
                                        },
                                        {
                                                .name = L"Idle",
                                                .pre_show = profile_proc_cfg_prio_class_update,
                                                .on_click = profile_proc_cfg_prio_class_click,
                                                .userdata2 = (void *)PROC_PRIO_CLS_IDLE,
                                        },
                                        {
                                                .name = L"Normal -",
                                                .pre_show = profile_proc_cfg_prio_class_update,
                                                .on_click = profile_proc_cfg_prio_class_click,
                                                .userdata2 = (void *)PROC_PRIO_CLS_BELOW_NORMAL,
                                        },
                                        {
                                                .name = L"Normal",
                                                .pre_show = profile_proc_cfg_prio_class_update,
                                                .on_click = profile_proc_cfg_prio_class_click,
                                                .userdata2 = (void *)PROC_PRIO_CLS_NORMAL,
                                        },
                                        {
                                                .name = L"Normal +",
                                                .pre_show = profile_proc_cfg_prio_class_update,
                                                .on_click = profile_proc_cfg_prio_class_click,
                                                .userdata2 = (void *)PROC_PRIO_CLS_ABOVE_NORMAL,
                                        },
                                        {
                                                .name = L"High",
                                                .pre_show = profile_proc_cfg_prio_class_update,
                                                .on_click = profile_proc_cfg_prio_class_click,
                                                .userdata2 = (void *)PROC_PRIO_CLS_HIGH,
                                        },
                                        {
                                                .name = L"Realtime",
                                                .pre_show = profile_proc_cfg_prio_class_update,
                                                .on_click = profile_proc_cfg_prio_class_click,
                                                .userdata2 = (void *)PROC_PRIO_CLS_REALTIME,
                                        },
                                        {.is_end = 1},
                                },
                        },
                        {
                                .name = L"IO Priority",
                                .pre_show = profile_sub_menu_update,
                                .submenu = (struct tray_menu[]) {
                                        {
                                                .name = L"Leave as-is",
                                                .pre_show = profile_proc_cfg_io_prio_update,
                                                .on_click = profile_proc_cfg_io_prio_click,
                                                .userdata2 = (void *)IO_PRIO_UNCHANGED,
                                        },
                                        {
                                                .is_separator = 1
                                        },
                                        {
                                                .name = L"Very Low",
                                                .pre_show = profile_proc_cfg_io_prio_update,
                                                .on_click = profile_proc_cfg_io_prio_click,
                                                .userdata2 = (void *)IO_PRIO_VERY_LOW,
                                        },
                                        {
                                                .name = L"Low",
                                                .pre_show = profile_proc_cfg_io_prio_update,
                                                .on_click = profile_proc_cfg_io_prio_click,
                                                .userdata2 = (void *)IO_PRIO_LOW,
                                        },
                                        {
                                                .name = L"Normal",
                                                .pre_show = profile_proc_cfg_io_prio_update,
                                                .on_click = profile_proc_cfg_io_prio_click,
                                                .userdata2 = (void *)IO_PRIO_NORMAL,
                                        },
                                        {
                                                .name = L"High",
                                                .pre_show = profile_proc_cfg_io_prio_update,
                                                .on_click = profile_proc_cfg_io_prio_click,
                                                .userdata2 = (void *)IO_PRIO_HIGH,
                                        },
                                        {.is_end = 1},
                                },
                        },
                        {
                                .name = L"Page Priority",
                                .pre_show = profile_sub_menu_update,
                                .submenu = (struct tray_menu[]) {
                                        {
                                                .name = L"Leave as-is",
                                                .pre_show = profile_proc_cfg_page_prio_update,
                                                .on_click = profile_proc_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_UNCHANGED,
                                        },
                                        {
                                                .is_separator = 1
                                        },
                                        {
                                                .name = L"Lowest",
                                                .pre_show = profile_proc_cfg_page_prio_update,
                                                .on_click = profile_proc_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_LOWEST,
                                        },
                                        {
                                                .name = L"Very Low",
                                                .pre_show = profile_proc_cfg_page_prio_update,
                                                .on_click = profile_proc_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_VERY_LOW,
                                        },
                                        {
                                                .name = L"Low",
                                                .pre_show = profile_proc_cfg_page_prio_update,
                                                .on_click = profile_proc_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_LOW,
                                        },
                                        {
                                                .name = L"Medium",
                                                .pre_show = profile_proc_cfg_page_prio_update,
                                                .on_click = profile_proc_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_MEDIUM,
                                        },
                                        {
                                                .name = L"Normal-",
                                                .pre_show = profile_proc_cfg_page_prio_update,
                                                .on_click = profile_proc_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_BELOW_NORMAL,
                                        },
                                        {
                                                .name = L"Normal",
                                                .pre_show = profile_proc_cfg_page_prio_update,
                                                .on_click = profile_proc_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_NORMAL,
                                        },
                                        { .is_end = 1 },
                                },
                        },
                        { .is_end = 1 },
                },
        }, // "Process"
        {
                .name = L"Thread",
                .pre_show = profile_sub_menu_update,
                .submenu = (struct tray_menu[]) {
                        {
                                .name = L"Priority Boost",
                                .pre_show = profile_sub_menu_update,
                                .submenu = (struct tray_menu[]) {
                                        {
                                                .name = L"Leave as-is",
                                                .pre_show = profile_thrd_cfg_prio_boost_update,
                                                .on_click = profile_thrd_cfg_prio_boost_click,
                                                .userdata2 = (void *)LEAVE_AS_IS,
                                        },
                                        {
                                                .is_separator = 1
                                        },
                                        {
                                                .name = L"Enabled",
                                                .pre_show = profile_thrd_cfg_prio_boost_update,
                                                .on_click = profile_thrd_cfg_prio_boost_click,
                                                .userdata2 = (void *)STRVAL_ENABLED,
                                        },
                                        {
                                                .name = L"Disabled",
                                                .pre_show = profile_thrd_cfg_prio_boost_update,
                                                .on_click = profile_thrd_cfg_prio_boost_click,
                                                .userdata2 = (void *)STRVAL_DISABLED,
                                        },
                                        {.is_end = 1},
                                },
                        },
                        {
                                .name = L"Priority Level",
                                .pre_show = profile_sub_menu_update,
                                .submenu = (struct tray_menu[]) {
                                        {
                                                .name = L"Leave as-is",
                                                .pre_show = profile_thrd_cfg_prio_level_update,
                                                .on_click = profile_thrd_cfg_prio_level_click,
                                                .userdata2 = (void *)THRD_PRIO_LVL_UNCHANGED,
                                        },
                                        {
                                                .name = L"At-least",
                                                .pre_show = profile_thrd_cfg_prio_least_update,
                                                .on_click = profile_thrd_cfg_prio_least_click,
                                        },
                                        {
                                                .is_separator = 1
                                        },
                                        {
                                                .name = L"Idle",
                                                .pre_show = profile_thrd_cfg_prio_level_update,
                                                .on_click = profile_thrd_cfg_prio_level_click,
                                                .userdata2 = (void *)THRD_PRIO_LVL_IDLE,
                                        },
                                        {
                                                .name = L"Lowest",
                                                .pre_show = profile_thrd_cfg_prio_level_update,
                                                .on_click = profile_thrd_cfg_prio_level_click,
                                                .userdata2 = (void *)THRD_PRIO_LVL_LOWEST,
                                        },
                                        {
                                                .name = L"Normal -",
                                                .pre_show = profile_thrd_cfg_prio_level_update,
                                                .on_click = profile_thrd_cfg_prio_level_click,
                                                .userdata2 = (void *)THRD_PRIO_LVL_BELOW_NORMAL,
                                        },
                                        {
                                                .name = L"Normal",
                                                .pre_show = profile_thrd_cfg_prio_level_update,
                                                .on_click = profile_thrd_cfg_prio_level_click,
                                                .userdata2 = (void *)THRD_PRIO_LVL_NORMAL,
                                        },
                                        {
                                                .name = L"Normal +",
                                                .pre_show = profile_thrd_cfg_prio_level_update,
                                                .on_click = profile_thrd_cfg_prio_level_click,
                                                .userdata2 = (void *)THRD_PRIO_LVL_ABOVE_NORMAL,
                                        },
                                        {
                                                .name = L"Highest",
                                                .pre_show = profile_thrd_cfg_prio_level_update,
                                                .on_click = profile_thrd_cfg_prio_level_click,
                                                .userdata2 = (void *)THRD_PRIO_LVL_HIGHEST,
                                        },
                                        {
                                                .name = L"Time Critical",
                                                .pre_show = profile_thrd_cfg_prio_level_update,
                                                .on_click = profile_thrd_cfg_prio_level_click,
                                                .userdata2 = (void *)THRD_PRIO_LVL_TIME_CRITICAL,
                                        },
                                        {.is_end = 1},
                                },
                        },
                        {
                                .name = L"IO Priority",
                                .pre_show = profile_sub_menu_update,
                                .submenu = (struct tray_menu[]) {
                                        {
                                                .name = L"Leave as-is",
                                                .pre_show = profile_thrd_cfg_io_prio_update,
                                                .on_click = profile_thrd_cfg_io_prio_click,
                                                .userdata2 = (void *)IO_PRIO_UNCHANGED,
                                        },
                                        {
                                                .is_separator = 1
                                        },
                                        {
                                                .name = L"Very Low",
                                                .pre_show = profile_thrd_cfg_io_prio_update,
                                                .on_click = profile_thrd_cfg_io_prio_click,
                                                .userdata2 = (void *)IO_PRIO_VERY_LOW,
                                        },
                                        {
                                                .name = L"Low",
                                                .pre_show = profile_thrd_cfg_io_prio_update,
                                                .on_click = profile_thrd_cfg_io_prio_click,
                                                .userdata2 = (void *)IO_PRIO_LOW,
                                        },
                                        {
                                                .name = L"Normal",
                                                .pre_show = profile_thrd_cfg_io_prio_update,
                                                .on_click = profile_thrd_cfg_io_prio_click,
                                                .userdata2 = (void *)IO_PRIO_NORMAL,
                                        },
                                        {
                                                .name = L"High",
                                                .pre_show = profile_thrd_cfg_io_prio_update,
                                                .on_click = profile_thrd_cfg_io_prio_click,
                                                .userdata2 = (void *)IO_PRIO_HIGH,
                                        },
                                        {.is_end = 1},
                                },
                        },
                        {
                                .name = L"Page Priority",
                                .pre_show = profile_sub_menu_update,
                                .submenu = (struct tray_menu[]) {
                                        {
                                                .name = L"Leave as-is",
                                                .pre_show = profile_thrd_cfg_page_prio_update,
                                                .on_click = profile_thrd_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_UNCHANGED,
                                        },
                                        {
                                                .is_separator = 1
                                        },
                                        {
                                                .name = L"Lowest",
                                                .pre_show = profile_thrd_cfg_page_prio_update,
                                                .on_click = profile_thrd_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_LOWEST,
                                        },
                                        {
                                                .name = L"Very Low",
                                                .pre_show = profile_thrd_cfg_page_prio_update,
                                                .on_click = profile_thrd_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_VERY_LOW,
                                        },
                                        {
                                                .name = L"Low",
                                                .pre_show = profile_thrd_cfg_page_prio_update,
                                                .on_click = profile_thrd_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_LOW,
                                        },
                                        {
                                                .name = L"Medium",
                                                .pre_show = profile_thrd_cfg_page_prio_update,
                                                .on_click = profile_thrd_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_MEDIUM,
                                        },
                                        {
                                                .name = L"Normal-",
                                                .pre_show = profile_thrd_cfg_page_prio_update,
                                                .on_click = profile_thrd_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_BELOW_NORMAL,
                                        },
                                        {
                                                .name = L"Normal",
                                                .pre_show = profile_thrd_cfg_page_prio_update,
                                                .on_click = profile_thrd_cfg_page_prio_click,
                                                .userdata2 = (void *)PAGE_PRIO_NORMAL,
                                        },
                                        { .is_end = 1 },
                                },
                        },
                        { .is_end = 1 },
                },
        }, // "Thread"
        { .is_separator = 1 },
        { .name = L"Oneshot", .pre_show = profile_oneshot_update, .on_click = profile_oneshot_click },
        { .name = L"Always Set", .pre_show = profile_always_set_update, .on_click = profile_always_set_click },
        { .name = L"Delayed", .pre_show = profile_delayed_update, },
        { .is_separator = 1 },
        { .name = L"Info Dump", .on_click = profile_proc_thread_dump, },
        { .is_end = 1 },
};

int profile_menu_create(struct tray_menu *menu)
{
        struct tray_menu *sub;
        size_t profile_cnt = g_cfg.profile_cnt;
        size_t menu_cnt = profile_cnt + 1;

        if (!menu)
                return 0;

        if (g_cfg.profile_cnt == 0)
                return 0;

        sub = calloc(menu_cnt, sizeof(struct tray_menu));
        if (!sub) {
                pr_err("failed to allocate memory for profile top menu");
                return -ENOMEM;
        }

        menu->disabled = 0;
        menu->submenu = sub;

        for (size_t i = 0; i < profile_cnt; i++) {
                struct tray_menu *m = &sub[i];
                profile_t *profile = &g_cfg.profiles[i];

                m->name = profile->name;
                m->userdata = profile;
                m->submenu = tray_menu_alloc_copy(profile_menu_template);
                if (!m->submenu) {
                        pr_err("failed to copy profile menu template\n");
                        return -ENOMEM;
                }

                for (size_t j = 0; j < ARRAY_SIZE(profile_menu_template); j++) {
                        struct tray_menu *mm = &m->submenu[j];

                        if (mm->name && mm->name[0] != L'\0')
                                mm->userdata = profile;
                }
        }

        // mark end
        sub[menu_cnt - 1].is_end = 1;

        return 0;
}

void profile_menu_free(struct tray_menu *menu)
{
        if (!menu)
                return;

        if (!menu->submenu)
                return;

        for (size_t i = 0; i < g_cfg.profile_cnt; i++) {
                struct tray_menu *m = &menu->submenu[i];

                tray_menu_recursive_free(m->submenu);
        }

        free(menu->submenu);
}

int superthread_tray_init(HINSTANCE ins)
{
        struct tray *tray = &g_tray;
        int err;

        if ((err = tray_init(tray, ins)))
                return err;

        g_profile_menu = profile_menu_find(tray->menu);

        if ((err = profile_menu_create(g_profile_menu)))
                return err;

        tray_update_post(tray);

        return 0;
}

void superthread_tray_deinit(void)
{
        struct tray *tray = &g_tray;

        profile_menu_free(g_profile_menu);

        tray_exit(tray);
}
