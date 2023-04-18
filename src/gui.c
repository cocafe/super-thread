#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>

#include <windows.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>

#define NK_INCLUDE_FIXED_TYPES
#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_STANDARD_VARARGS
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#define NK_IMPLEMENTATION
#define NK_GDI_IMPLEMENTATION
#define NK_BUTTON_TRIGGER_ON_RELEASE // to fix touch input

#include <nuklear/nuklear.h>
#include <nuklear/nuklear_gdi.h>

// #define NKGDI_UPDATE_FOREGROUND_ONLY
#define NKGDI_IMPLEMENT_WINDOW
#include <nuklear/nuklear_gdiwnd.h>

#include <libjj/ffs.h>
#include <libjj/iconv.h>
#include <libjj/logging.h>

#include "config.h"
#include "sysinfo.h"
#include "resource.h"
#include "superthread.h"

struct proc_sel_info {
        char name[256];
        int pid;
};

struct profile_wnd_data {
        int ready;

        int do_save;
        int do_apply;

        int proc_affinity_popup;
        int thrd_affinity_popup;

        int proc_sel_popup;
        int *proc_list_sel;
        struct proc_sel_info *proc_list_info;
        size_t proc_list_cnt;

        struct {
                profile_t *t;
                int cnt;
                int sel;
        } profile;
};

static float widget_h = 40.0f;
pthread_t profile_wnd_tid;

static inline int list_is_null(const struct list_head *head)
{
        return (head->next == NULL) && (head->prev == NULL);
}

void profile_wnd_data_init(struct profile_wnd_data *data)
{
        memset(data, 0x00, sizeof(struct profile_wnd_data));

        data->ready = 0;
}

void proc_id_delete(proc_id_t *id)
{
        if (!list_empty(&id->node) && !list_is_null(&id->node)) {
                list_del(&id->node);
        }

        if (id->cmdl) {
                proc_id_delete(id->cmdl);
                free(id->cmdl);
        }

        if (id->file_hdl) {
                proc_id_delete(id->file_hdl);
                free(id->file_hdl);
        }
}

void proc_id_init(proc_id_t *id)
{
        memset(id, 0x00, sizeof(proc_id_t));
        id->type = IDENTITY_NONE;
        INIT_LIST_HEAD(&id->node);
}

proc_id_t *proc_id_new(int type)
{
        proc_id_t *t = malloc(sizeof(proc_id_t));
        if (!t)
                return NULL;

        proc_id_init(t);
        t->type = type;

        return t;
}

int wnd_cfg_on_draw(struct nkgdi_window *wnd, struct nk_context *ctx)
{
        {
                static int sample_secs = 0;

                nk_layout_row_dynamic(ctx, widget_h, 2);
                nk_label(ctx, "Sampling Interval:", NK_TEXT_LEFT);
                nk_property_int(ctx, "#Secs", 0, &sample_secs, INT_MAX, 1, 1);
        }

        {
                static char *loglvl[] = {
                        "verbose", "debug", "info", "error", "notice", "warning", "fatal"};
                static int loglvl_checked[7] = {0};

                if (nk_tree_push(ctx, NK_TREE_TAB, "Logging Level", NK_MAXIMIZED)) {
                        nk_layout_row_dynamic(ctx, widget_h, NK_LEN(loglvl));

                        for (size_t i = 0; i < NK_LEN(loglvl); i++) {
                                nk_checkbox_label(ctx, loglvl[i], &loglvl_checked[i]);
                        }

                        nk_tree_pop(ctx);
                }
        }

        {
                static int console_on_start = 0;

                nk_layout_row_dynamic(ctx, widget_h, 2);
                nk_label(ctx, "Console on Startup: ", NK_TEXT_LEFT);
                nk_checkbox_label(ctx, "", &console_on_start);
        }

        {
                nk_layout_row_begin(ctx, NK_DYNAMIC, widget_h, 3);
                nk_layout_row_push(ctx, 0.8f);
                nk_label(ctx, "", NK_TEXT_LEFT);
                nk_layout_row_push(ctx, 0.2f);
                nk_button_label(ctx, "Save");
                nk_layout_row_end(ctx);
        }

        return 1;
}

int profile_id_filter_draw(struct nk_context *ctx, proc_id_t *id, const char *name)
{
        char buf[PROC_ID_VALUE_LEN] = { 0 };
        int buf_len = strlen(id->value);

        nk_layout_row_dynamic(ctx, widget_h, 3);
        nk_label(ctx, name, NK_TEXT_LEFT);
        id->filter = nk_combo(ctx, cfg_identity_filter_strs, NUM_PROC_ID_STR_FILTERS, id->filter, widget_h, nk_vec2(200, 200));
        nk_edit_string(ctx, NK_EDIT_FIELD, id->value, &buf_len, sizeof(id->value), nk_filter_default);

        strncpy(buf, id->value, sizeof(id->value));
        snprintf(id->value, sizeof(id->value), "%.*s", buf_len, buf);

        nk_layout_row_dynamic(ctx, widget_h, 1);

        if (nk_button_label(ctx, "Delete")) {
                proc_id_delete(id);
                free(id);

                return 1;
        }

        return 0;
}

int wnd_profile_reload(struct profile_wnd_data *data)
{
        int i = 0, err;
        profile_t *t;

        data->profile.cnt = 0;

        for_each_profile(t) {
                if (i == data->profile.sel) {
                        if (data->profile.t)
                                profile_unlock(data->profile.t);

                        data->profile.t = t;
                        if ((err = profile_lock(t))) {
                                pr_err("failed to grab profile %d, err = %d %s\n", i, err, strerror(err));
                                return 1;
                        }
                }

                data->profile.cnt++;
                i++;
        }

        data->ready = 1;

        return 0;
}

int wnd_profile_menubar_draw(struct nk_context *ctx)
{
        nk_menubar_begin(ctx);

        nk_layout_row_begin(ctx, NK_STATIC, widget_h, 1);
        nk_layout_row_push(ctx, 45);
        if (nk_menu_begin_label(ctx, "File", NK_TEXT_ALIGN_LEFT, nk_vec2(120, 200))) {
                nk_layout_row_dynamic(ctx, widget_h, 1);

                if (nk_menu_item_label(ctx, "Save", NK_TEXT_ALIGN_LEFT)) {
                        usrcfg_save();
                }

                if (nk_menu_item_label(ctx, "Close", NK_TEXT_ALIGN_LEFT)) {
                        return 1;
                }

                nk_menu_end(ctx);
        }

        nk_menubar_end(ctx);

        return 0;
}

void wnd_profile_delete(struct profile_wnd_data *data)
{
        int new_sel = data->profile.sel - 1;
        profile_t *p = data->profile.t;

        if (!p)
                return;

        profile_list_delete(p);
        profile_unlock(p);
        profile_deinit(p);
        profile_free(p);

        data->profile.sel = new_sel < 0 ? 0 : new_sel;
        data->profile.t = NULL;
        data->ready = 0;
}

int wnd_profile_add(struct profile_wnd_data *data)
{
        profile_t *p = data->profile.t;
        profile_t *n = calloc(1, sizeof(profile_t));
        if (!n)
                return -ENOMEM;

        profile_init(n);
        n->processes.node_map = 0x01;
        n->processes.affinity = UINT64_MAX;
        n->threads.node_map = 0x01;
        n->threads.affinity = UINT64_MAX;
        snprintf(n->name, sizeof(n->name), "new profile");

        if (p)
                profile_unlock(p);

        profile_list_add(n);

        data->profile.t = NULL;
        data->profile.sel = 0;
        data->ready = 0;

        return 0;
}

int __wnd_profile_selection_draw(struct nk_context *ctx, struct profile_wnd_data *data)
{
        profile_t *p;
        char **profile_names;
        size_t profile_cnt = data->profile.cnt;
        int new_sel;
        int i = 0;

        profile_names = calloc(profile_cnt, sizeof(char *));
        if (!profile_names)
                return -ENOMEM;

        for_each_profile(p) {
                profile_names[i] = p->name;
                i++;
        }

        nk_layout_row_begin(ctx, NK_DYNAMIC, widget_h, 3);

        nk_layout_row_push(ctx, 0.8f);
        new_sel = nk_combo(ctx, (const char **)profile_names, (int)profile_cnt, data->profile.sel, widget_h, nk_vec2(nk_widget_width(ctx), 400));

        nk_layout_row_push(ctx, 0.1f);
        if (nk_button_label(ctx, "+")) {
                wnd_profile_add(data);
                return 1;
        }

        nk_layout_row_push(ctx, 0.1f);
        if (nk_button_label(ctx, "-")) {
                wnd_profile_delete(data);
                return 1;
        }

        nk_layout_row_end(ctx);

        free(profile_names);

        if (new_sel >= 0 && new_sel != data->profile.sel) {
                data->profile.sel = new_sel;
                data->ready = 0;

                return 1;
        }

        return 0;
}

int wnd_profile_selection_draw(struct nk_context *ctx, struct profile_wnd_data *data)
{
        const char *empty[] = { "" };

        if (data->profile.cnt && data->profile.t)
                return __wnd_profile_selection_draw(ctx, data);

        nk_layout_row_begin(ctx, NK_DYNAMIC, widget_h, 3);

        nk_layout_row_push(ctx, 0.8f);
        nk_combo(ctx, empty, ARRAY_SIZE(empty), 0, widget_h, nk_vec2(nk_widget_width(ctx), 400));

        nk_layout_row_push(ctx, 0.1f);
        if (nk_button_label(ctx, "+")) {
                wnd_profile_add(data);
                return 1;
        }

        nk_layout_row_push(ctx, 0.1f);
        nk_button_label_disabled(ctx, "-", 1);
        nk_layout_row_end(ctx);

        return 0;
}

int wnd_profile_name_draw(struct nk_context *ctx, struct profile_wnd_data *data, profile_t *profile)
{
        char field_buf[PROFILE_NAME_LEN] = { 0 };
        int field_len;

        strncpy(field_buf, profile->name, sizeof(profile->name));
        field_len = strlen(field_buf);

        nk_layout_row_begin(ctx, NK_DYNAMIC, widget_h, 2);
        nk_layout_row_push(ctx, 0.6f);
        nk_label(ctx, "Profile Name:", NK_TEXT_LEFT);
        nk_layout_row_push(ctx, 0.4f);
        nk_edit_string(ctx, NK_EDIT_FIELD, field_buf, &field_len, sizeof(field_buf), nk_filter_default);
        nk_layout_row_end(ctx);

        memset(profile->name, '\0', sizeof(profile->name));
        snprintf(profile->name, sizeof(profile->name), "%.*s", field_len, field_buf);

        return 0;
}

void wnd_identify_proc_list_free(struct profile_wnd_data *data)
{
        if (data->proc_list_info) {
                free(data->proc_list_info);
                data->proc_list_info = NULL;
        }

        if (data->proc_list_sel) {
                free(data->proc_list_sel);
                data->proc_list_sel = NULL;
        }

        data->proc_list_cnt = 0;
}

int wnd_identity_proc_list_build(struct profile_wnd_data *data)
{
        HANDLE hProcessSnap;
        PROCESSENTRY32 pe32;
        size_t i = 0;
        int err = 0;

        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
                pr_err("CreateToolhelp32Snapshot() failed: %lu\n", GetLastError());
                return -EINVAL;
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hProcessSnap, &pe32)) {
                err = -EFAULT;
                goto out;
        }

        do {
                i++;
        } while (Process32Next(hProcessSnap, &pe32));

        data->proc_list_info = calloc(i, sizeof(struct proc_sel_info));
        if (!data->proc_list_info) {
                err = -ENOMEM;
                goto out;
        }

        data->proc_list_sel = calloc(i, sizeof(int));
        if (!data->proc_list_sel) {
                err = -ENOMEM;

                goto out;
        }

        data->proc_list_cnt = i;

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hProcessSnap, &pe32)) {
                err = -EFAULT;
                goto out;
        }

        i = 0;

        do {
                data->proc_list_info[i].pid = pe32.th32ProcessID;
                iconv_wc2utf8(pe32.szExeFile, WCSLEN_BYTE(pe32.szExeFile),
                              data->proc_list_info[i].name, sizeof(data->proc_list_info[i].name));
                i++;
        } while (Process32Next(hProcessSnap, &pe32));

out:
        CloseHandle(hProcessSnap);

        if (err)
                wnd_identify_proc_list_free(data);

        return err;
}

int wnd_identity_process_list_select(struct nk_context *ctx, struct profile_wnd_data *data)
{
        static char filter_buf[128] = { 0 };
        static int filter_len = 0;
        char _filter[128];
        char buf[256 + 8] = { 0 };
        int ret = 0;

        if (!data->proc_list_info && !data->proc_list_sel) {
                wnd_identity_proc_list_build(data);
        }

        nk_layout_row_dynamic(ctx, widget_h, 1);
        nk_edit_string(ctx, NK_EDIT_FIELD, filter_buf, &filter_len, sizeof(buf), nk_filter_default);

        snprintf(_filter, sizeof(_filter), "%.*s", filter_len, filter_buf);
        _filter[sizeof(_filter) - 1] = '\0';

        nk_layout_row_dynamic(ctx, 12 * widget_h, 1);

        if (nk_group_begin(ctx, "", NK_WINDOW_BORDER)) {
                nk_layout_row_dynamic(ctx, widget_h, 1);

                for (size_t i = 0; i < data->proc_list_cnt; ++i) {
                        snprintf(buf, sizeof(buf),"%s (pid: %d)", data->proc_list_info[i].name, data->proc_list_info[i].pid);

                        if (!is_strptr_set(filter_buf) || strstr(data->proc_list_info[i].name, _filter) ) {
                                nk_selectable_label(ctx, buf, NK_TEXT_LEFT, &data->proc_list_sel[i]);
                        }
                }

                nk_group_end(ctx);
        }

        nk_layout_row_dynamic(ctx, widget_h, 2);

        if (nk_button_label(ctx, "Add")) {
                ret = 1;
                goto close;
        }

        if (nk_button_label(ctx, "Cancel")) {
                ret = 0;
                goto close;
        }

        return 0;

close:
        filter_len = 0;
        memset(filter_buf, '\0', sizeof(filter_buf));
        data->proc_sel_popup = 0;
        nk_popup_close(ctx);

        return ret;
}

int wnd_identity_process_list_add(struct profile_wnd_data *data, profile_t *profile)
{
        for (size_t i = 0; i < data->proc_list_cnt; i++) {
                proc_id_t *t;

                if (!data->proc_list_sel[i])
                        continue;

                t = proc_id_new(IDENTITY_PROCESS_EXE);
                if (!t)
                        return -ENOMEM;

                t->filter = STR_FILTER_IS;
                strncpy(t->value, data->proc_list_info[i].name, sizeof(t->value));
                list_add_tail(&t->node, &profile->id_list);
        }

        return 0;
}

int wnd_profile_identity_draw(struct nk_context *ctx, struct profile_wnd_data *data, profile_t *profile)
{
        static const char *id_type_strs[] = {
                [IDENTITY_PROCESS_EXE]          = "Process",
                [IDENTITY_FILE_HANDLE]          = "System-wide File Handle",
                [IDENTITY_CMDLINE]              = "System-wide Process Cmdline",
        };
        static int new_id_type = IDENTITY_PROCESS_EXE;
        proc_id_t *id, *s;
        int i = 0;

        for_each_profile_id_safe(id, s, profile) {
                if (nk_tree_push_id(ctx, NK_TREE_NODE, id_type_strs[id->type], NK_MAXIMIZED, __LINE__ + i)) {
                        switch (id->type) {
                        case IDENTITY_PROCESS_EXE:
                                if (profile_id_filter_draw(ctx, id, "Process Name"))
                                        break;

                                if (nk_tree_push_id(ctx, NK_TREE_NODE, "Cmdline", id->cmdl ? NK_MAXIMIZED : NK_MINIMIZED, __LINE__ + i)) {
                                        if (id->cmdl) {
                                                if (profile_id_filter_draw(ctx, id->cmdl, "Process Cmdline")) {
                                                        id->cmdl = NULL;
                                                }
                                        } else {
                                                nk_layout_row_dynamic(ctx, widget_h, 1);
                                                if (nk_button_label(ctx, "Add")) {
                                                        id->cmdl = proc_id_new(IDENTITY_NONE);
                                                }
                                        }

                                        nk_tree_pop(ctx);
                                }

                                if (nk_tree_push_id(ctx, NK_TREE_NODE, "File Handle", id->file_hdl ? NK_MAXIMIZED : NK_MINIMIZED, __LINE__ + i)) {
                                        if (id->file_hdl) {
                                                if (profile_id_filter_draw(ctx, id->file_hdl, "Handle Path")) {
                                                        id->file_hdl = NULL;
                                                }
                                        } else {
                                                nk_layout_row_dynamic(ctx, widget_h, 1);
                                                if (nk_button_label(ctx, "Add")) {
                                                        id->file_hdl = proc_id_new(IDENTITY_NONE);
                                                }
                                        }

                                        nk_tree_pop(ctx);
                                }

                                break;

                        case IDENTITY_CMDLINE:
                                profile_id_filter_draw(ctx, id, "Any Process Cmdline");
                                break;

                        case IDENTITY_FILE_HANDLE:
                                profile_id_filter_draw(ctx, id, "Any Process Handle Path");
                                break;

                        default:
                                nk_layout_row_dynamic(ctx, widget_h, 1);
                                nk_label_colored(ctx, "⚠ Invalid Identify Type", NK_TEXT_LEFT, nk_rgb(255, 0, 0));
                                break;

                        }

                        nk_tree_pop(ctx);
                }

                i++;
        }

        nk_layout_row_dynamic(ctx, widget_h, 0);
        nk_layout_row_begin(ctx, NK_DYNAMIC, widget_h, 3);
        nk_layout_row_push(ctx, 0.4f);
        nk_label(ctx, "New Identity: ", NK_TEXT_LEFT);
        nk_layout_row_push(ctx, 0.4f);
        new_id_type = nk_combo(ctx, id_type_strs, NUM_PROC_ID_TYPES, new_id_type, widget_h, nk_vec2(nk_widget_width(ctx), 400));
        nk_layout_row_push(ctx, 0.2f);
        if (nk_button_label(ctx, "Add")) {
                proc_id_t *n = proc_id_new(new_id_type);
                list_add_tail(&n->node, &profile->id_list);
        }

        nk_layout_row_dynamic(ctx, widget_h, 1);
        if (nk_button_label(ctx, "Add From Process List...")) {
                data->proc_sel_popup = 1;
        }

        if (data->proc_sel_popup) {
                if (nk_popup_begin(ctx, NK_POPUP_STATIC,
                                   "Select Processes...",
                                   NK_WINDOW_CLOSABLE,
                                   nk_rect(20, 20, 700, 16 * widget_h))) {
                        if (wnd_identity_process_list_select(ctx, data)) {
                                wnd_identity_process_list_add(data, profile);
                        }

                        nk_popup_end(ctx);
                } else {
                        data->proc_sel_popup = 0;
                }
        } else {
                wnd_identify_proc_list_free(data);
        }

        nk_tree_pop(ctx);

        return 0;
}

int wnd_profile_process_settings_draw(struct nk_context *ctx, profile_t *profile)
{
        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_label(ctx, "Priority Class:", NK_TEXT_LEFT);
        profile->proc_cfg.prio_class = nk_combo(ctx, cfg_prio_cls_strs, NUM_PROC_PRIO_CLASS, profile->proc_cfg.prio_class, widget_h, nk_vec2(nk_widget_width(ctx), 400));

        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_label(ctx, "IO Priority:", NK_TEXT_LEFT);
        profile->proc_cfg.io_prio = nk_combo(ctx, cfg_io_prio_strs, NUM_IO_PRIOS, profile->proc_cfg.io_prio, widget_h, nk_vec2(nk_widget_width(ctx), 400));

        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_label(ctx, "Page Priority:", NK_TEXT_LEFT);
        profile->proc_cfg.page_prio = nk_combo(ctx, cfg_page_prio_strs, NUM_PAGE_PRIOS, profile->proc_cfg.page_prio, widget_h, nk_vec2(nk_widget_width(ctx), 400));

        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_label(ctx, "Priority Boost:", NK_TEXT_LEFT);
        profile->proc_cfg.prio_boost = nk_combo(ctx, cfg_tristate_strs, NUM_TRISTATE_VALS, profile->proc_cfg.prio_boost, widget_h, nk_vec2(nk_widget_width(ctx), 400));

        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_label(ctx, "Power Throttle:", NK_TEXT_LEFT);
        profile->proc_cfg.power_throttle = nk_combo(ctx, cfg_tristate_strs, NUM_TRISTATE_VALS, profile->proc_cfg.power_throttle, widget_h, nk_vec2(nk_widget_width(ctx), 400));

        nk_tree_pop(ctx);

        return 0;
}

int wnd_profile_thread_settings_draw(struct nk_context *ctx, profile_t *profile)
{
        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_label(ctx, "IO Priority:", NK_TEXT_LEFT);
        profile->thrd_cfg.io_prio = nk_combo(ctx, cfg_io_prio_strs, NUM_IO_PRIOS, profile->thrd_cfg.io_prio, widget_h, nk_vec2(nk_widget_width(ctx), 400));

        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_label(ctx, "Page Priority:", NK_TEXT_LEFT);
        profile->thrd_cfg.page_prio = nk_combo(ctx, cfg_page_prio_strs, NUM_PAGE_PRIOS, profile->thrd_cfg.page_prio, widget_h, nk_vec2(nk_widget_width(ctx), 400));

        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_label(ctx, "Priority Boost:", NK_TEXT_LEFT);
        profile->thrd_cfg.prio_boost = nk_combo(ctx, cfg_tristate_strs, NUM_TRISTATE_VALS, profile->thrd_cfg.prio_boost, widget_h, nk_vec2(nk_widget_width(ctx), 400));

        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_label(ctx, "Priority Level:", NK_TEXT_LEFT);
        profile->thrd_cfg.prio_level = nk_combo(ctx, cfg_prio_lvl_strs, NUM_THRD_PRIO_LEVELS, profile->thrd_cfg.prio_level, widget_h, nk_vec2(nk_widget_width(ctx), 400));

        nk_tree_pop(ctx);

        return 0;
}

void wnd_supervisor_nodemap_draw(struct nk_context *ctx, struct supervisor_cfg *cfg)
{
        uint32_t t = 0;
        int map[MAX_PROC_GROUPS] = { 0 };

        if (nk_tree_push(ctx, NK_TREE_NODE, "Node Map", NK_MAXIMIZED)) {
                nk_layout_row_dynamic(ctx, widget_h, MAX_PROC_GROUPS);

                for (int i = MAX_PROC_GROUPS - 1; i >= 0; i--) {
                        char b[4] = { 0 };
                        snprintf(b, sizeof(b), "%d", i);

                        map[i] = cfg->node_map & BIT_ULL(i) ? 1 : 0;
                        nk_checkbox_label(ctx, b, &map[i]);

                        if (i >= (int)g_sys_info.nr_cpu_grp)
                                map[i] = 0;

                        t |= map[i] ? BIT(i) : 0;
                }

                cfg->node_map = t;

                nk_tree_pop(ctx);
        }
}

void wnd_supervisor_affinity_draw(struct nk_context *ctx, int *popup, struct supervisor_cfg *cfg)
{
        if (nk_tree_push(ctx, NK_TREE_NODE, "Affinity Mask", NK_MAXIMIZED)) {
                char b[64] = { 0 };

                snprintf(b, sizeof(b), "0x%016jx", cfg->affinity);
                nk_layout_row_dynamic(ctx, widget_h, 1);

                nk_widget_tooltip(ctx, "Click to edit affinity");
                if (nk_button_label(ctx, b))
                        *popup = 1;

                if (*popup) {
                        static char buf[16 + 4] = { 0 };
                        static int buflen = -1;

                        cfg->affinity &= BIT_ULL(g_sys_info.cpu_grp[0].cpu_cnt) - 1;

                        if (nk_popup_begin(ctx, NK_POPUP_STATIC,
                                           "Set Affinity Mask...",
                                           NK_WINDOW_CLOSABLE,
                                           nk_rect(20, 20, 700, 10 * widget_h))) {
                                uint64_t last = cfg->affinity;
                                uint64_t t;
                                int map[BITS_PER_LONG_LONG] = { 0 };

                                if (buflen < 0) {
                                        memset(buf, '\0', sizeof(buf));
                                        buflen = snprintf(buf, sizeof(buf), "%016jx", cfg->affinity);
                                }

                                nk_layout_row_dynamic(ctx, widget_h, 1);
                                nk_edit_string(ctx, NK_EDIT_SIMPLE, buf, &buflen, 16 + 1, nk_filter_hex);

                                if (buflen > 16) {
                                        buflen = 16;
                                }

                                {
                                        char b[16 + 2] = { 0 };

                                        snprintf(b, sizeof(b), "%.*s", buflen, buf);

                                        t = strtoull(b, NULL, 16);
                                        if (errno != ERANGE) {
                                                if (t != cfg->affinity) {
                                                        cfg->affinity = t;
                                                        last = t; // do not update text input box
                                                }
                                        }
                                }

                                t = 0;

                                for (int i = 63; i >= 0; i -= 16) {
                                        nk_layout_row_dynamic(ctx, widget_h, 16);

                                        for (int j = i; (i - j) < 16; j--) {
                                                char b[3] = { 0 };
                                                snprintf(b, sizeof(b), "%d", j);

                                                map[j] = (cfg->affinity & BIT_ULL(j)) ? 1 : 0;
                                                nk_checkbox_label(ctx, b,  &map[j]);
                                                t |= map[j] ? BIT_ULL(j) : 0;
                                        }
                                }

                                if (t != cfg->affinity) {
                                        cfg->affinity = t;
                                }

                                nk_layout_row_dynamic(ctx, widget_h, 3);

                                if (nk_button_label(ctx, "Clear All")) {
                                        cfg->affinity = 0;
                                }

                                if (nk_button_label(ctx, "Select All")) {
                                        cfg->affinity = ~0ULL;
                                }

                                if (nk_button_label(ctx, "Invert All")) {
                                        cfg->affinity = ~(cfg->affinity);
                                }

                                // FIXME: only one group available assumed below

                                nk_layout_row_dynamic(ctx, widget_h, 5);
                                if (nk_button_label(ctx, "Select HT")) {
                                        struct cpu_grp_info *cpu_grp = &g_sys_info.cpu_grp[0];
                                        static uint64_t selection = 0x1;
                                        uint64_t mask = 0;

                                        // start over
                                        if (0 == (selection & cpu_grp->cpu[0].relation_mask))
                                                selection = 0x1;

                                        for (size_t i = 0; i < cpu_grp->cpu_cnt; i++) {
                                                struct cpu_info *cpu = &cpu_grp->cpu[i];
                                                uint32_t shift;

                                                if (cpu->relation_mask == 0)
                                                        continue;

                                                shift = find_first_bit_u64(&cpu->relation_mask);
                                                mask |= selection << shift;
                                        }

                                        selection <<= 1;
                                        cfg->affinity |= mask;
                                }

                                if (nk_button_label(ctx, "Select CCD")) {
                                        struct cpu_grp_info *cpu_grp = &g_sys_info.cpu_grp[0];
                                        static uint64_t mask = 0;
                                        size_t i = find_first_bit_u64(&mask);

                                        if (i >= 64)
                                                i = 0;

                                        // start over from ccd 0
                                        if (mask & BIT_ULL(cpu_grp->cpu_cnt - 1))
                                                i = 0;

                                        for (; i < cpu_grp->cpu_cnt; i++) {
                                                struct cpu_info *cpu = &cpu_grp->cpu[i];
                                                struct cache_info *l3_cache = &(cpu->cache[3]._[CACHE_UNIFIED]);
                                                uint64_t new_mask = l3_cache->relation_mask;

                                                if (mask != new_mask) {
                                                        mask = new_mask;
                                                        break;
                                                }
                                        }

                                        cfg->affinity |= mask;
                                }

                                if (nk_button_label(ctx, "Select V-Cache")) {
                                        struct cpu_grp_info *cpu_grp = &g_sys_info.cpu_grp[0];
                                        size_t largest = 0;
                                        uint64_t mask = 0;

                                        for (size_t i = 0; i < cpu_grp->cpu_cnt; i++) {
                                                struct cpu_info *cpu = &cpu_grp->cpu[i];
                                                struct cache_info *l3_cache = &(cpu->cache[3]._[CACHE_UNIFIED]);

                                                if (l3_cache->size > largest) {
                                                        largest = l3_cache->size;
                                                        mask = l3_cache->relation_mask;
                                                }
                                        }

                                        cfg->affinity |= mask;
                                }

                                if (g_sys_info.is_heterogeneous && nk_button_label(ctx, "Select P-Core")) {
                                        struct cpu_grp_info *cpu_grp = &g_sys_info.cpu_grp[0];
                                        uint64_t mask = 0;

                                        for (size_t i = 0; i < cpu_grp->cpu_cnt; i++) {
                                                struct cpu_info *cpu = &cpu_grp->cpu[i];
                                                if (cpu->efficiency_cls) {
                                                        mask |= BIT_ULL(i);
                                                }
                                        }

                                        cfg->affinity |= mask;
                                } else {
                                        nk_button_label_disabled(ctx, "Select P-Core", 1);
                                }

                                if (g_sys_info.is_heterogeneous && nk_button_label(ctx, "Select E-Core")) {
                                        struct cpu_grp_info *cpu_grp = &g_sys_info.cpu_grp[0];
                                        uint64_t mask = 0;

                                        for (size_t i = 0; i < cpu_grp->cpu_cnt; i++) {
                                                struct cpu_info *cpu = &cpu_grp->cpu[i];
                                                if (cpu->efficiency_cls == 0) {
                                                        mask |= BIT_ULL(i);
                                                }
                                        }

                                        cfg->affinity |= mask;
                                } else {
                                        nk_button_label_disabled(ctx, "Select E-Core", 1);
                                }

                                if (cfg->affinity != last)
                                        buflen = -1;

                                nk_layout_row_dynamic(ctx, widget_h, 1);
                                if (nk_button_label(ctx, "OK")) {
                                        buflen = -1;
                                        *popup = 0;

                                        nk_popup_close(ctx);
                                }

                                nk_popup_end(ctx);
                        } else {
                                buflen = -1;
                                *popup = 0;
                        }
                }

                nk_tree_pop(ctx);
        }
}

void wnd_supervisor_balance_draw(struct nk_context *ctx, struct supervisor_cfg *cfg, const char **strval, const int cnt)
{
        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_label(ctx, "Mode", NK_TEXT_LEFT);
        cfg->balance = nk_combo(ctx, strval, cnt, cfg->balance, widget_h, nk_vec2(nk_widget_width(ctx), 400));
}

int wnd_profile_supervisor_draw(struct nk_context *ctx, struct profile_wnd_data *data, profile_t *profile)
{
        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_checkbox_label(ctx, "OneShot", (int *)&profile->oneshot);
        nk_checkbox_label(ctx, "Always Set", (int *)&profile->always_set);

        nk_layout_row_dynamic(ctx, widget_h, 3);
        nk_label(ctx, "Granularity:", NK_TEXT_LEFT);
        if (nk_option_label(ctx, "Processes", profile->sched_mode == SUPERVISOR_PROCESSES ? 1 : 0))
                profile->sched_mode = SUPERVISOR_PROCESSES;
        if (nk_option_label(ctx, "Threads", profile->sched_mode == SUPERVISOR_THREADS ? 1 : 0))
                profile->sched_mode = SUPERVISOR_THREADS;

        nk_layout_row_dynamic(ctx, widget_h, 2);
        nk_label(ctx, "Delay:", NK_TEXT_LEFT);
        nk_property_int(ctx, "#Ticks", 0, (int *)&profile->delay, INT_MAX, 1, 1);

        if (nk_tree_push(ctx, NK_TREE_NODE, "Processes", NK_MAXIMIZED)) {
                wnd_supervisor_nodemap_draw(ctx, &profile->processes);
                wnd_supervisor_affinity_draw(ctx, &data->proc_affinity_popup, &profile->processes);
                wnd_supervisor_balance_draw(ctx, &profile->processes, cfg_proc_balance_strs, NUM_PROC_BALANCE); // TODO: make check box with tooltip
                nk_tree_pop(ctx);
        }

        if (nk_tree_push(ctx, NK_TREE_NODE, "Threads", NK_MAXIMIZED)) {
                wnd_supervisor_nodemap_draw(ctx, &profile->threads);
                wnd_supervisor_affinity_draw(ctx, &data->thrd_affinity_popup, &profile->threads);
                wnd_supervisor_balance_draw(ctx, &profile->threads, cfg_thrd_balance_strs, NUM_THRD_BALANCE);
                nk_tree_pop(ctx);
        }

        nk_tree_pop(ctx);

        return 0;
}

int wnd_profile_on_draw(struct nkgdi_window *wnd, struct nk_context *ctx)
{
        struct profile_wnd_data *data = nkgdi_window_userdata_get(wnd);
        profile_t *selected;

        if (READ_ONCE(in_saving)) {
                if (data->profile.t) {
                        profile_unlock(data->profile.t);
                        data->profile.t = NULL;
                        data->ready = 0;
                }

                return 1;
        }

        if (!data->ready) {
                if (wnd_profile_reload(data))
                        return 1;
        }

        if (g_should_exit)
                return 0;

        selected = data->profile.t;

        if (wnd_profile_menubar_draw(ctx))
                return 0;

        if (wnd_profile_selection_draw(ctx, data))
                return 1;

        if (selected == NULL)
                return 1;

        nk_layout_row_begin(ctx, NK_DYNAMIC, widget_h, 2);
        nk_layout_row_push(ctx, 0.6f);
        nk_label(ctx, "Enabled:", NK_TEXT_LEFT);
        nk_layout_row_push(ctx, 0.4f);
        nk_checkbox_label(ctx, "", (int *)&selected->enabled);

        wnd_profile_name_draw(ctx, data, selected);

        if (nk_tree_push(ctx, NK_TREE_NODE, "Identity", NK_MINIMIZED)) {
                wnd_profile_identity_draw(ctx, data, selected);
        }

        if (nk_tree_push(ctx, NK_TREE_NODE, "Process Settings", NK_MINIMIZED)) {
                wnd_profile_process_settings_draw(ctx, selected);
        }

        if (nk_tree_push(ctx, NK_TREE_NODE, "Process Thread Settings", NK_MINIMIZED)) {
                wnd_profile_thread_settings_draw(ctx, selected);
        }

        if (nk_tree_push(ctx, NK_TREE_NODE, "Supervisor", NK_MAXIMIZED)) {
                wnd_profile_supervisor_draw(ctx, data, selected);
        }

        return 1;
}

int wnd_profile_on_close(struct nkgdi_window *wnd)
{
        struct profile_wnd_data *data = nkgdi_window_userdata_get(wnd);

        if (data->profile.t)
                profile_unlock(data->profile.t);

        return 1;
}

void *profile_wnd_thread_worker(void *data)
{
        struct nkgdi_window wnd = { 0 };
        struct profile_wnd_data wnd_data = { 0 };

        profile_wnd_data_init(&wnd_data);

        wnd.allow_sizing = 1;
        wnd.allow_maximize = 1;
        wnd.allow_move = 1;
        wnd.has_titlebar = 1;
        wnd.font_name = "ubuntu mono mod";
        wnd.cb_on_draw = wnd_profile_on_draw;
        wnd.cb_on_close = wnd_profile_on_close;

        nkgdi_window_create(&wnd, 800, 1000, "Profile", 0, 0);
        nkgdi_window_icon_set(&wnd, LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_APP_ICON)));
        nkgdi_window_userdata_set(&wnd, &wnd_data);
        nkgdi_window_set_center(&wnd);
        nk_set_style(nkgdi_window_nkctx_get(&wnd), THEME_DARK);

        nkgdi_window_blocking_update(&wnd);

        nkgdi_window_destroy(&wnd);

        WRITE_ONCE(profile_wnd_tid, 0);

        pthread_exit(NULL);

        return NULL;
}

int gui_profile_wnd_create(void)
{
        pthread_t tid = 0;

        if (READ_ONCE(profile_wnd_tid) != 0)
                return -EALREADY;

        if (pthread_create(&tid, NULL, profile_wnd_thread_worker, NULL)) {
                pr_err("failed to create window worker\n");
                return -EFAULT;
        }

        WRITE_ONCE(profile_wnd_tid, tid);

        return 0;
}

void gui_init(void)
{
        nkgdi_window_init();
}

void gui_deinit(void)
{
        nkgdi_window_shutdown();
}
