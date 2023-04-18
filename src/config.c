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

int profile_validate(profile_t *profile)
{
        size_t nr_cpu_grp = g_sys_info.nr_cpu_grp;
        uint32_t avail_node_map = GENMASK(nr_cpu_grp - 1, 0);

        if (profile->enabled == 0)
                pr_info("profile [%s] is disabled\n", profile->name);

        if (profile->sched_mode == SUPERVISOR_PROCESSES) {
                profile->processes.node_map &= avail_node_map;

                switch (profile->processes.balance) {
                case PROC_BALANCE_BY_MAP:
                case PROC_BALANCE_RAND:
                case PROC_BALANCE_RR:
                        if (profile->processes.node_map == 0) {
                                pr_err("profile [%s] process [node_map] matches none of processor groups on this system\n",
                                       profile->name);
                                return -EINVAL;
                        }

                        if (profile->processes.affinity == 0) {
                                pr_err("profile [%s] affinity is not set\n", profile->name);
                                return -EINVAL;
                        }

                        break;

                case PROC_BALANCE_ONLOAD:
                        pr_info("onload balance algorithm is not implemented\n");
                        break;

                default:
                        pr_err("invalid balance mode\n");
                        return -EINVAL;
                }

        } else if (profile->sched_mode == SUPERVISOR_THREADS) {
                profile->threads.node_map &= avail_node_map;

                switch (profile->threads.balance) {
                case THRD_BALANCE_NODE_RAND:
                case THRD_BALANCE_NODE_RR:
                case THRD_BALANCE_CPU_RR:
                        if (profile->threads.node_map == 0) {
                                pr_err("profile [%s] thread [node_map] matches none of processor groups on this system\n",
                                       profile->name);
                                return -EINVAL;
                        }

                        if (profile->threads.affinity == 0) {
                                pr_err("profile [%s] affinity is not set\n", profile->name);
                                return -EINVAL;
                        }

                        break;

                case THRD_BALANCE_ONLOAD:
                        pr_info("algorithm is not implemented\n");
                        break;

                default:
                        pr_err("invalid balance mode\n");
                        return -EINVAL;
                }
        }

        return 0;
}

void __profile_init(profile_t *profile)
{
        pthread_mutex_init(&profile->lock, NULL);
        INIT_HLIST_NODE(&profile->hnode);
}

int profile_init(profile_t *profile)
{
        profile->enabled = 0;
        INIT_LIST_HEAD(&profile->node);
        INIT_LIST_HEAD(&profile->id_list);
        __profile_init(profile);

        return 0;
}

int profile_deinit(profile_t *profile)
{
        pthread_mutex_destroy(&profile->lock);

        return 0;
}

void profile_free(profile_t *profile)
{
        proc_id_t *t, *s;

        for_each_profile_id_safe(t, s, profile) {
                free(t);
        }

        free(profile);
}

int profile_try_lock(profile_t *profile)
{
        return pthread_mutex_trylock(&profile->lock);
}

int profile_lock(profile_t *profile)
{
        return pthread_mutex_lock(&profile->lock);
}

int profile_unlock(profile_t *profile)
{
        return pthread_mutex_unlock(&profile->lock);
}

void profile_hash_rebuild(void)
{
        profile_t *p, *s;

        pthread_mutex_lock(&g_cfg.profile_hlist.lck);

        memset(g_cfg.profile_hlist.tbl, 0, sizeof(g_cfg.profile_hlist.tbl));
        hash_init(g_cfg.profile_hlist.tbl);

        for_each_profile_safe(p, s) {
                if (profile_try_lock(p))
                        continue;

                INIT_HLIST_NODE(&p->hnode);
                hash_add(g_cfg.profile_hlist.tbl, &p->hnode, (intptr_t)p);

                profile_unlock(p);
        }

        pthread_mutex_unlock(&g_cfg.profile_hlist.lck);
}

// to check profile is deleted or not
profile_t *profile_hash_get(profile_t *ptr)
{
        profile_t *p, *s;
        int valid = 0;

        pthread_mutex_lock(&g_cfg.profile_hlist.lck);

        hash_for_each_possible_safe(g_cfg.profile_hlist.tbl, p, s, hnode, (intptr_t)ptr) {
                if (p == ptr) {
                        valid = 1;
                        break;
                }
        }

        pthread_mutex_unlock(&g_cfg.profile_hlist.lck);

        return valid ? p : NULL;
}

void profile_hash_del(profile_t *profile)
{
        pthread_mutex_lock(&g_cfg.profile_hlist.lck);

        hash_del(&profile->hnode);

        pthread_mutex_unlock(&g_cfg.profile_hlist.lck);
}

void profiles_add(profile_t *profile)
{
        list_add(&profile->node, &g_cfg.profile_list);
        profile_hash_rebuild();
}

void profiles_delete(profile_t *profile)
{
        list_del(&profile->node);
        profile_hash_rebuild();
}

static int profiles_init(void)
{
        struct list_head *t;

        list_for_each(t, &g_cfg.profile_list) {
                __profile_init(container_of(t, profile_t, node));
        }

        pthread_mutex_init(&g_cfg.profile_hlist.lck, NULL);
        profile_hash_rebuild();

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

int usrcfg_init(void)
{
        jbuf_t *jbuf = &jbuf_usrcfg;
        int err;

        if ((err = usrcfg_root_key_create(jbuf)))
                return err;

        pr_info("load json config: %s\n", g_cfg.json_path);

        if ((err = jbuf_load(jbuf, g_cfg.json_path)))
                return err;

        pr_info("loaded config:\n");

        jbuf_traverse_print(jbuf);

        if ((err = usrcfg_validate()))
                return err;

        usrcfg_apply();
        profiles_init();

        return 0;
}

int usrcfg_deinit(void)
{
        jbuf_deinit(&jbuf_usrcfg);

        return 0;
}
