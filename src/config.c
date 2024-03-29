#include <stdlib.h>

#include <libjj/jkey.h>
#include <libjj/malloc.h>

#include "config.h"
#include "sysinfo.h"
#include "superthread.h"

#define STR_LEAVE_AS_IS                 "leave_as-is"

const char *cfg_identity_type_strs[] = {
        [IDENTITY_NONE]                 = "none",
        [IDENTITY_PROCESS_EXE]          = "process",
        [IDENTITY_FILE_HANDLE]          = "file_handle",
        [IDENTITY_CMDLINE]              = "cmdline",
};

const char *cfg_identity_filter_strs[] = {
        [STR_FILTER_IS]                 = "is",
        [STR_FILTER_CONTAIN]            = "contains",
};

const char *cfg_prio_cls_strs[] = {
        [PROC_PRIO_CLS_UNCHANGED]       = STR_LEAVE_AS_IS,
        [PROC_PRIO_CLS_IDLE]            = "idle",
        [PROC_PRIO_CLS_NORMAL]          = "normal",
        [PROC_PRIO_CLS_HIGH]            = "high",
        [PROC_PRIO_CLS_REALTIME]        = "realtime",
        [PROC_PRIO_CLS_BELOW_NORMAL]    = "normal-",
        [PROC_PRIO_CLS_ABOVE_NORMAL]    = "normal+",
};

const char *cfg_prio_lvl_strs[] = {
        [THRD_PRIO_LVL_UNCHANGED]       = STR_LEAVE_AS_IS,
        [THRD_PRIO_LVL_IDLE]            = "idle",
        [THRD_PRIO_LVL_LOWEST]          = "lowest",
        [THRD_PRIO_LVL_BELOW_NORMAL]    = "normal-",
        [THRD_PRIO_LVL_NORMAL]          = "normal",
        [THRD_PRIO_LVL_ABOVE_NORMAL]    = "normal+",
        [THRD_PRIO_LVL_HIGHEST]         = "highest",
        [THRD_PRIO_LVL_TIME_CRITICAL]   = "time_critical",
};

const char *cfg_page_prio_strs[] = {
        [PAGE_PRIO_UNCHANGED]           = STR_LEAVE_AS_IS,
        [PAGE_PRIO_NORMAL]              = "normal",
        [PAGE_PRIO_BELOW_NORMAL]        = "normal-",
        [PAGE_PRIO_MEDIUM]              = "medium",
        [PAGE_PRIO_LOW]                 = "low",
        [PAGE_PRIO_VERY_LOW]            = "very_low",
        [PAGE_PRIO_LOWEST]              = "lowest",
};

const char *cfg_io_prio_strs[] = {
        [IO_PRIO_UNCHANGED]             = STR_LEAVE_AS_IS,
        [IO_PRIO_VERY_LOW]              = "very_low",
        [IO_PRIO_LOW]                   = "low",
        [IO_PRIO_NORMAL]                = "normal",
        [IO_PRIO_HIGH]                  = "high",
};

const char *cfg_proc_balance_strs[] = {
        [PROC_BALANCE_BY_MAP]           = "by_map",
        [PROC_BALANCE_RAND]             = "node_random",
        [PROC_BALANCE_RR]               = "node_rr",
        [PROC_BALANCE_ONLOAD]           = "onload",
};

const char *cfg_thrd_balance_strs[] = {
        [THRD_BALANCE_NODE_RAND]        = "node_random",
        [THRD_BALANCE_NODE_RR]          = "node_rr",
        [THRD_BALANCE_CPU_RR]           = "cpu_rr",
        [THRD_BALANCE_ONLOAD]           = "onload",
};

const char *cfg_supervisor_mode_strs[] = {
        [SUPERVISOR_PROCESSES]          = "processes",
        [SUPERVISOR_THREADS]            = "threads",
};

const char *cfg_tristate_strs[] = {
        [LEAVE_AS_IS]                   = STR_LEAVE_AS_IS,
        [STRVAL_ENABLED]                = "enabled",
        [STRVAL_DISABLED]               = "disabled",
};

struct config g_cfg = {
        .sampling_sec = SAMPLING_SEC_DEF,
        .json_path = JSON_CFG_PATH_DEF,
};

lsopt_strbuf(c, json_path, g_cfg.json_path, sizeof(g_cfg.json_path), "JSON config path");

static pthread_mutex_t save_lck = PTHREAD_MUTEX_INITIALIZER;
uint32_t in_saving;
jbuf_t jbuf_usrcfg;

int usrcfg_root_key_create(jbuf_t *b)
{
        void *root;
        int err;

        if (!b || b->base) {
                pr_err("jbuf is not cleaned\n");
                return -EINVAL;
        }

        if ((err = jbuf_init(b, JBUF_INIT_ALLOC_KEYS))) {
                pr_err("jbuf_init() failed, err=%d\n", err);
                return err;
        }

        root = jbuf_obj_open(b, NULL);

        jbuf_u32_add(b, "sampling_sec", &g_cfg.sampling_sec);

        {
                void *logging = jbuf_obj_open(b, "logging");

                jbuf_bool_add(b, "console", &g_console_show);
                jbuf_bool_add(b, "verbose", &g_cfg.loglvl[_LOG_LEVEL_VERBOSE]);
                jbuf_bool_add(b, "debug",   &g_cfg.loglvl[_LOG_LEVEL_DEBUG]);
                jbuf_bool_add(b, "info",    &g_cfg.loglvl[_LOG_LEVEL_INFO]);
                jbuf_bool_add(b, "error",   &g_cfg.loglvl[_LOG_LEVEL_NOTICE]);
                jbuf_bool_add(b, "notice",  &g_cfg.loglvl[_LOG_LEVEL_WARN]);
                jbuf_bool_add(b, "warning", &g_cfg.loglvl[_LOG_LEVEL_ERROR]);
                jbuf_bool_add(b, "fatal",   &g_cfg.loglvl[_LOG_LEVEL_FATAL]);

                jbuf_obj_close(b, logging);
        }

        {
                void *profile_arr = jbuf_list_arr_open(b, "profiles");

                jbuf_list_arr_setup(b, profile_arr, &g_cfg.profile_list, sizeof(profile_t), offsetof(profile_t, node), 0, 0);

                void *profile_obj = jbuf_offset_obj_open(b, NULL, 0);

                jbuf_offset_strbuf_add(b, "name", offsetof(profile_t, name), sizeof(((profile_t *)(0))->name));
                jbuf_offset_add(b, bool, "enabled", offsetof(profile_t, enabled));

                {
                        void *id_arr = jbuf_list_arr_open(b, "identity");

                        jbuf_offset_list_arr_setup(b, id_arr, offsetof(profile_t, id_list), sizeof(struct proc_identity), offsetof(struct proc_identity, node), 0, 0);

                        {
                                void *id_obj = jbuf_offset_obj_open(b, NULL, 0);

                                jbuf_offset_strval_add(b, "type", offsetof(struct proc_identity, type), cfg_identity_type_strs, NUM_PROC_ID_TYPES);
                                jbuf_offset_strval_add(b, "filter", offsetof(struct proc_identity, filter), cfg_identity_filter_strs, NUM_PROC_ID_STR_FILTERS);
                                jbuf_offset_strbuf_add(b, "value", offsetof(struct proc_identity, value), sizeof(((proc_id_t *)(0))->value));

                                {
                                        void *cmdl_obj = jbuf_offset_objptr_open(b, "cmdline", sizeof(struct proc_identity), offsetof(struct proc_identity, cmdl));

                                        jbuf_offset_strval_add(b, "filter", offsetof(struct proc_identity, filter), cfg_identity_filter_strs, NUM_PROC_ID_STR_FILTERS);
                                        jbuf_offset_strbuf_add(b, "value", offsetof(struct proc_identity, value), sizeof(((proc_id_t *)(0))->value));

                                        jbuf_obj_close(b, cmdl_obj);
                                }

                                {
                                        void *hdl_obj = jbuf_offset_objptr_open(b, "file_handle", sizeof(struct proc_identity), offsetof(struct proc_identity, file_hdl));

                                        jbuf_offset_strval_add(b, "filter", offsetof(struct proc_identity, filter), cfg_identity_filter_strs, NUM_PROC_ID_STR_FILTERS);
                                        jbuf_offset_strbuf_add(b, "value", offsetof(struct proc_identity, value), sizeof(((proc_id_t *)(0))->value));

                                        jbuf_obj_close(b, hdl_obj);
                                }

                                jbuf_obj_close(b, id_obj);
                        }

                        jbuf_arr_close(b, id_arr);
                }

                {
                        void *process_cfg = jbuf_offset_obj_open(b, "process", offsetof(profile_t, proc_cfg));

                        jbuf_offset_strval_add(b, "prio_class", offsetof(struct proc_cfg, prio_class), cfg_prio_cls_strs, NUM_PROC_PRIO_CLASS);
                        jbuf_offset_strval_add(b, "prio_boost", offsetof(struct proc_cfg, prio_boost), cfg_tristate_strs, NUM_TRISTATE_VALS);
                        jbuf_offset_strval_add(b, "io_prio", offsetof(struct proc_cfg, io_prio), cfg_io_prio_strs, NUM_IO_PRIOS);
                        jbuf_offset_strval_add(b, "page_prio", offsetof(struct proc_cfg, page_prio), cfg_page_prio_strs, NUM_PAGE_PRIOS);
                        jbuf_offset_strval_add(b, "throttle", offsetof(struct proc_cfg, power_throttle), cfg_tristate_strs, NUM_TRISTATE_VALS);

                        jbuf_obj_close(b, process_cfg);
                }

                {
                        void *thread_cfg = jbuf_offset_obj_open(b, "thread", offsetof(profile_t, thrd_cfg));

                        {
                                void *prio_level_obj = jbuf_offset_obj_open(b, "prio_level", 0);

                                jbuf_offset_add(b, bool, "at_least", offsetof(struct thrd_cfg, prio_level_least));
                                jbuf_offset_strval_add(b, "level", offsetof(struct thrd_cfg, prio_level), cfg_prio_lvl_strs, NUM_THRD_PRIO_LEVELS);

                                jbuf_obj_close(b, prio_level_obj);
                        }

                        jbuf_offset_strval_add(b, "io_prio", offsetof(struct thrd_cfg, io_prio), cfg_io_prio_strs, NUM_IO_PRIOS);
                        jbuf_offset_strval_add(b, "page_prio", offsetof(struct thrd_cfg, page_prio), cfg_page_prio_strs, NUM_PAGE_PRIOS);
                        jbuf_offset_strval_add(b, "prio_boost", offsetof(struct thrd_cfg, prio_boost), cfg_tristate_strs, NUM_TRISTATE_VALS);

                        jbuf_obj_close(b, thread_cfg);
                }

                {
                        void *supervisor_obj = jbuf_offset_obj_open(b, "supervisor", 0);

                        jbuf_offset_strval_add(b, "mode", offsetof(profile_t, sched_mode), cfg_supervisor_mode_strs, NUM_SUPERVISOR_GRANS);
                        jbuf_offset_add(b, bool, "oneshot", offsetof(profile_t, oneshot));
                        jbuf_offset_add(b, bool, "always_set", offsetof(profile_t, always_set));
                        jbuf_offset_add(b, u32, "delay", offsetof(profile_t, delay));

                        {
                                void *processes_obj = jbuf_offset_obj_open(b, "processes", offsetof(profile_t, processes));

                                jbuf_offset_add(b, hex_u32, "node_map", offsetof(struct supervisor_cfg, node_map));
                                jbuf_offset_strval_add(b, "balance", offsetof(struct supervisor_cfg, balance), cfg_proc_balance_strs, NUM_PROC_BALANCE);
                                jbuf_offset_add(b, hex_u64, "affinity", offsetof(struct supervisor_cfg, affinity));

                                jbuf_obj_close(b, processes_obj);
                        }

                        {
                                void *threads_obj = jbuf_offset_obj_open(b, "threads", offsetof(profile_t, threads));

                                jbuf_offset_add(b, hex_u32, "node_map", offsetof(struct supervisor_cfg, node_map));
                                jbuf_offset_strval_add(b, "balance", offsetof(struct supervisor_cfg, balance), cfg_thrd_balance_strs, NUM_THRD_BALANCE);
                                jbuf_offset_add(b, hex_u64, "affinity", offsetof(struct supervisor_cfg, affinity));

                                jbuf_obj_close(b, threads_obj);
                        }

                        jbuf_obj_close(b, supervisor_obj);
                }

                jbuf_obj_close(b, profile_obj);
                jbuf_arr_close(b, profile_arr);
        }

        jbuf_obj_close(b, root);

        return 0;
}

int usrcfg_validate(void)
{
        struct list_head *t;
        int err;

        list_for_each(t, &g_cfg.profile_list) {
                profile_t *profile = container_of(t, profile_t, node);

                if ((err = profile_validate(profile)))
                        return err;
        }

        return 0;
}

void usrcfg_loglvl_apply(void)
{
        for (size_t i = 0; i < NUM_LOG_LEVELS; i++) {
                if (g_cfg.loglvl[i])
                        g_logprint_level |= BIT(i);
                else
                        g_logprint_level &= ~BIT(i);
        }
}

void usrcfg_loglvl_write(void)
{
        for (size_t i = 0; i < NUM_LOG_LEVELS; i++) {
                if (g_logprint_level & BIT(i))
                        g_cfg.loglvl[i] = 1;
                else
                        g_cfg.loglvl[i] = 0;
        }
}

int usrcfg_write(void)
{
        usrcfg_loglvl_write();

        return 0;
}

int usrcfg_apply(void)
{
        usrcfg_loglvl_apply();
        return 0;
}

int usrcfg_save(void)
{
        char *path = g_cfg.json_path;
        profile_t *p, *s;
        int err = 0;

        if ((err = pthread_mutex_lock(&save_lck))) {
                pr_err("failed to grab save_lck, err = %d %s\n", err, strerror(err));
                return err;
        }

        WRITE_ONCE(in_saving, 1);

        if (usrcfg_write()) {
                mb_err("usrcfg_write() failed\n");
                err = -EINVAL;
                goto unlock;
        }

        for_each_profile_safe(p, s) {
                profile_lock(p);
        }

        if ((err = jbuf_save(&jbuf_usrcfg, path))) {
                mb_err("failed to save json to \"%s\", err = %d", path, err);
        } else {
                pr_raw("saved json config: %s\n", path);
        }

        for_each_profile_safe(p, s) {
                profile_unlock(p);
        }

unlock:
        WRITE_ONCE(in_saving, 0);

        pthread_mutex_unlock(&save_lck);

        return err;
}

int usrcfg_init(void)
{
        jbuf_t *jbuf = &jbuf_usrcfg;
        int err;

        if ((err = usrcfg_root_key_create(jbuf)))
                return err;

        pr_info("load json config: %s\n", g_cfg.json_path);

        if (jbuf_load(jbuf, g_cfg.json_path)) {
                pr_mb_err("failed to load config, continue with default values\n");
                return 0;
        }

        pr_info("loaded config:\n");

        jbuf_traverse_print(jbuf);

        if ((err = usrcfg_validate()))
                return err;

        usrcfg_apply();
        loaded_profiles_init();

        return 0;
}

int usrcfg_deinit(void)
{
        // sync, in case
        pthread_mutex_lock(&save_lck);
        pthread_mutex_unlock(&save_lck);

        jbuf_deinit(&jbuf_usrcfg);

        return 0;
}
