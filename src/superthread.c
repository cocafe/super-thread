#include <windows.h>

#include <resource.h>

#include "utils.h"
#include "logging.h"
#include "tray.h"
#include "config.h"
#include "config_opts.h"
#include "supervisor.h"
#include "superthread.h"

#define TRAY_MENU_PROFILES              L"Profile"

struct config g_cfg;
uint32_t g_should_exit = 0;
struct tray_menu *g_profile_menu;

optdesc_t opt_help = {
        .short_opt = 'h',
        .long_opt  = "help",
        .has_arg   = no_argument,
        .to_set    = 0,
        .data      = NULL,
        .min       = 0,
        .max       = 0,
        .parse     = NULL,
        .help      = {
                "This help message",
                NULL,
        },
};

optdesc_t opt_verbose = {
        .short_opt = 0,
        .long_opt  = "verbose",
        .has_arg   = no_argument,
        .to_set    = 1,
        .data      = &g_logprint_level,
        .data_sz   = sizeof(g_logprint_level),
        .data_def  = &(typeof(g_logprint_level)){0 },
        .data_type = D_UNSIGNED,
        .min       = 0,
        .max       = 0,
        .parse     = NULL,
        .help      = {
                "Verbose debug message",
                NULL,
        },
};

optdesc_t opt_console = {
        .short_opt = 0,
        .long_opt  = "console",
        .has_arg   = no_argument,
        .to_set    = 1,
        .data      = &g_console_host_init,
        .data_sz   = sizeof(g_console_host_init),
        .data_def  = &(typeof(g_console_host_init)){ 0 },
        .data_type = D_UNSIGNED,
        .min       = 0,
        .max       = 0,
        .parse     = NULL,
        .help      = {
                "Show debug console",
                NULL,
        },
};

optdesc_t opt_json_path = {
        .short_opt = 'c',
        .long_opt  = "config",
        .has_arg   = required_argument,
        .to_set    = 0,
        .data      = g_cfg.json_path,
        .data_sz   = sizeof(g_cfg.json_path),
        .data_def  = "config.json",
        .data_type = D_STRING,
        .min       = 0,
        .max       = 0,
        .parse     = optarg_to_str,
        .help      = {
                "JSON config path",
                NULL,
        },
};

optdesc_t *g_opt_list[] = {
        &opt_help,
        &opt_verbose,
        &opt_console,
        &opt_json_path,
        NULL,
};

static void quit_cb(struct tray_menu *m) {
        UNUSED_PARAM(m);

        g_should_exit = 1;
        PostQuitMessage(0);
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
        m->checked = !m->checked;

        if (m->checked) {
                console_show();
                pr_raw("<!> CLOSE THIS LOGGING WINDOW WILL TERMINATE PROGRAM <!>\n");

                return;
        }

        console_hide();
}

static void console_show_update(struct tray_menu *m)
{
        if (g_console_is_hide)
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

struct tray g_tray = {
        .icon = {
                .path = NULL,
                .id = IDI_APP_ICON,
        },
        .menu = (struct tray_menu[]) {
                { .name = L"Pause", .checked = 0, .pre_show = pause_update, .on_click = pause_click, .userdata = &g_tray },
                { .separator = 1 },
                { .name = TRAY_MENU_PROFILES, .disabled = 1, .submenu = NULL },
                { .separator = 1 },
                {
                        .name = L"Logging",
                        .submenu = (struct tray_menu[]) {
                                { .name = L"Show", .checked = 1, .pre_show = console_show_update, .on_click = console_show_click },
                                { .separator = 1 },
                                { .name = L"Verbose", .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_VERBOSE },
                                { .name = L"Debug",   .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_DBG     },
                                { .name = L"Info",    .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_INFO    },
                                { .name = L"Notice",  .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_NOTICE  },
                                { .name = L"Warning", .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_WARN    },
                                { .name = L"Error",   .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_ERR     },
                                { .name = L"Fatal",   .pre_show = loglvl_update, .on_click = loglvl_click, .userdata = (void *)LOG_LEVEL_FATAL   },
                                { .is_end = 1 },
                        },
                },
                { .separator = 1 },
                { .name = L"Save", .disabled = 1 }, // TODO
                { .separator = 1 },
                { .name = L"Quit", .on_click = quit_cb },
                { .is_end = 1 }
        }
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

static void profile_enabled_update(struct tray_menu *m)
{
        profile_t *profile = m->userdata;

        if (profile->enabled)
                m->checked = 1;
        else
                m->checked = 0;
}

static void profile_enabled_click(struct tray_menu *m)
{
        profile_t *profile = m->userdata;

        m->checked = !m->checked;

        if (m->checked)
                profile->enabled = 1;
        else
                profile->enabled = 0;
}

static void profile_oneshot_update(struct tray_menu *m)
{
        profile_t *profile = m->userdata;

        if (profile->oneshot)
                m->checked = 1;
        else
                m->checked = 0;
}

static void profile_oneshot_click(struct tray_menu *m)
{
        profile_t *profile = m->userdata;

        m->checked = !m->checked;

        if (m->checked)
                profile->oneshot = 1;
        else
                profile->oneshot = 0;
}

static struct tray_menu profile_menu_template[] = {
        { .name = L"Enabled", .pre_show = profile_enabled_update, .on_click = profile_enabled_click },
        { .name = L"Oneshot", .pre_show = profile_oneshot_update, .on_click = profile_oneshot_click },
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
                m->submenu = calloc(1, sizeof(profile_menu_template));
                if (!m->submenu) {
                        pr_err("failed to allocate memory for profile menu\n");
                        return -ENOMEM;
                }

                memcpy(m->submenu, profile_menu_template, sizeof(profile_menu_template));

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

                if (m->submenu)
                        free(m->submenu);
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

        tray_update(tray);

        return 0;
}

void superthread_tray_deinit(void)
{
        struct tray *tray = &g_tray;

        profile_menu_free(g_profile_menu);

        tray_exit(tray);
}
