#include <stdlib.h>

#include "jkey.h"
#include "config.h"
#include "logging.h"
#include "sysinfo.h"
#include "superthread.h"

static char *proc_identity_type_strs[] = {
        [IDENTITY_NONE]                 = "none",
        [IDENTITY_PROCESS_EXE]          = "process",
        [IDENTITY_FILE_HANDLE]          = "file_handle",
        [IDENTITY_CMDLINE]              = "cmdline",
};

static char *proc_identity_filter_strs[] = {
        [STR_FILTER_IS]                 = "is",
        [STR_FILTER_CONTAIN]            = "contains",
};

static char *proc_prio_strs[] = {
        [PROC_PRIO_UNCHANGED]           = "unchanged",
        [PROC_PRIO_IDLE]                = "idle",
        [PROC_PRIO_NORMAL]              = "normal",
        [PROC_PRIO_HIGH]                = "high",
        [PROC_PRIO_REALTIME]            = "realtime",
        [PROC_PRIO_BELOW_NORMAL]        = "normal-",
        [PROC_PRIO_ABOVE_NORMAL]        = "normal+",
};

static char *io_prio_strs[] = {
        [IO_PRIO_UNCHANGED]             = "unchanged",
        [IO_PRIO_VERY_LOW]              = "very_low",
        [IO_PRIO_LOW]                   = "low",
        [IO_PRIO_NORMAL]                = "normal",
        [IO_PRIO_HIGH]                  = "high",
};

static char *proc_balance_strs[] = {
        [PROC_BALANCE_BY_MAP]           = "by_map",
        [PROC_BALANCE_RAND]             = "random",
        [PROC_BALANCE_RR]               = "round_robin",
        [PROC_BALANCE_ONLOAD]           = "onload",
};

static char *thrd_balance_strs[] = {
        [THRD_BALANCE_RAND]             = "random",
        [THRD_BALANCE_NODE_RR]          = "node_rr",
        [THRD_BALANCE_CPU_RR]           = "cpu_rr",
        [THRD_BALANCE_ONLOAD]           = "onload",
};

static char *supervisor_mode_strs[] = {
        [SUPERVISOR_PROCESSES]          = "processes",
        [SUPERVISOR_THREADS]            = "threads",
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
                void *profile_arr = jbuf_grow_arr_open(b, "profiles");
                void *profile_obj;

                jbuf_grow_arr_setup(b, profile_arr, (void *)&g_cfg.profiles, &g_cfg.profile_cnt, sizeof(profile_t));
                jbuf_offset_obj_open(b, profile_obj, NULL, 0);

                jbuf_offset_add(b, wstrptr, "name", offsetof(profile_t, name));
                jbuf_offset_add(b, bool, "enabled", offsetof(profile_t, enabled));
                jbuf_offset_strval_add(b, "proc_prio", offsetof(profile_t, proc_prio), proc_prio_strs, NUM_PROC_PRIOS);
                jbuf_offset_strval_add(b, "io_prio", offsetof(profile_t, io_prio), io_prio_strs, NUM_IO_PRIOS);

                {
                        void *id_arr = jbuf_grow_arr_open(b, "identity");

                        jbuf_offset_grow_arr_setup(b,
                                                   id_arr,
                                                   offsetof(profile_t, id),
                                                   offsetof(profile_t, id_cnt),
                                                   sizeof(struct proc_identity));

                        {
                                void *id_obj;

                                jbuf_offset_obj_open(b, id_obj, NULL, 0);

                                jbuf_offset_strval_add(b, "type", offsetof(struct proc_identity, type), proc_identity_type_strs, NUM_PROC_ID_TYPES);
                                jbuf_offset_strval_add(b, "filter", offsetof(struct proc_identity, filter), proc_identity_filter_strs, NUM_PROC_ID_STR_FILTERS);
                                jbuf_offset_add(b, wstrptr, "value", offsetof(struct proc_identity, value));

                                jbuf_obj_close(b, id_obj);
                        }

                        jbuf_arr_close(b, id_arr);
                }

                {
                        void *supervisor_obj;

                        jbuf_offset_obj_open(b, supervisor_obj, "supervisor", 0);

                        jbuf_offset_strval_add(b, "mode", offsetof(profile_t, sched_mode), supervisor_mode_strs, NUM_SUPERVISOR_GRANS);
                        jbuf_offset_add(b, bool, "oneshot", offsetof(profile_t, oneshot));

                        {
                                void *processes_obj;

                                jbuf_offset_obj_open(b, processes_obj, "processes", offsetof(profile_t, processes));

                                jbuf_offset_add(b, hex_u32, "node_map", offsetof(struct supervisor_cfg, node_map));
                                jbuf_offset_strval_add(b, "balance", offsetof(struct supervisor_cfg, balance), proc_balance_strs, NUM_PROC_BALANCE);
                                jbuf_offset_add(b, hex_u64, "affinity", offsetof(struct supervisor_cfg, affinity));

                                jbuf_obj_close(b, processes_obj);
                        }

                        {
                                void *threads_obj;

                                jbuf_offset_obj_open(b, threads_obj, "threads", offsetof(profile_t, threads));

                                jbuf_offset_add(b, hex_u32, "node_map", offsetof(struct supervisor_cfg, node_map));
                                jbuf_offset_strval_add(b, "balance", offsetof(struct supervisor_cfg, balance), thrd_balance_strs, NUM_THRD_BALANCE);
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
                pr_info("profile [%ls] is disabled\n", profile->name);

        if (profile->sched_mode == SUPERVISOR_PROCESSES) {
                profile->processes.node_map &= avail_node_map;

                switch (profile->processes.balance) {
                case PROC_BALANCE_BY_MAP:
                case PROC_BALANCE_RR:
                        if (profile->processes.node_map == 0) {
                                pr_err("profile [%ls] node_map is not set which is needed for by_map\n",
                                       profile->name);
                                return -EINVAL;
                        }

                        if (profile->processes.affinity == 0) {
                                pr_err("profile [%ls] affinity is not set\n", profile->name);
                                return -EINVAL;
                        }

                        break;

                case PROC_BALANCE_RAND:
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
        }

        return 0;
}

int usrcfg_validate(void)
{
        int err;

        if (g_cfg.profile_cnt == 0) {
                pr_err("did not define any profiles\n");
                return -ENODATA;
        }

        for (size_t i = 0; i < g_cfg.profile_cnt; i++) {
                profile_t *profile = &g_cfg.profiles[i];

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

void usrcfg_loglvl_save(void)
{
        for (size_t i = 0; i < NUM_LOG_LEVELS; i++) {
                if (g_logprint_level & BIT(i))
                        g_cfg.loglvl[i] = 1;
                else
                        g_cfg.loglvl[i] = 0;
        }
}

int usrcfg_save(void)
{
        int err = 0;

        usrcfg_loglvl_save();

        return err;
}

int usrcfg_apply(void)
{
        int err = 0;

        usrcfg_loglvl_apply();

        return err;
}

int usrcfg_init(void)
{
        jbuf_t *jbuf = &jbuf_usrcfg;
        int err;

        // TODO: init default config values

        if ((err = usrcfg_root_key_create(jbuf)))
                return err;

        pr_info("load json config: %s\n", g_cfg.json_path);

        if ((err = jbuf_load(jbuf, g_cfg.json_path)))
                return err;

        pr_info("loaded config:\n");

        jbuf_traverse_print(jbuf);

        if ((err = usrcfg_validate()))
                return err;

        if ((err = usrcfg_apply()))
                return err;

        return 0;
}

int usrcfg_deinit(void)
{
        jbuf_deinit(&jbuf_usrcfg);

        return 0;
}
