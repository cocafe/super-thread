#include <stdlib.h>

#include "jkey.h"
#include "config.h"
#include "logging.h"

struct config g_cfg;

static char *proc_identity_type_strs[] = {
        [IDENTITY_NONE]                 = "none",
        [IDENTITY_PROCESS_EXE]          = "process",
        [IDENTITY_FILE_HANDLE]          = "file_handle",
        [IDENTITY_CMDLINE]              = "cmdline",
};

static char *proc_identity_filter_strs[] = {
        [STR_FILTER_IS]                 = "is",
        [STR_FILTER_CONTAIN]            = "contain",
};

static char *proc_prio_strs[] = {
        [PROC_PRIO_UNCHANGED]           = "unchanged",
        [PROC_PRIO_REALTIME]            = "realtime",
        [PROC_PRIO_HIGH]                = "high",
        [PROC_PRIO_ABOVE_NORMAL]        = "normal+",
        [PROC_PRIO_NORMAL]              = "normal",
        [PROC_PRIO_BELOW_NORMAL]        = "normal-",
        [PROC_PRIO_LOW]                 = "low",
        [PROC_PRIO_IDLE]                = "idle",
};

static char *io_prio_strs[] = {
        [IO_PRIO_UNCHANGED]             = "unchanged",
        [IO_PRIO_HIGH]                  = "high",
        [IO_PRIO_NORMAL]                = "normal",
        [IO_PRIO_LOW]                   = "low",
        [IO_PRIO_VERY_LOW]              = "very_low",
};

static char *proc_grp_scheme_strs[] = {
        [PROC_GROUP_STATIC]             = "static",
        [PROC_GROUP_BALANCE]            = "balance",
        [PROC_GROUP_RANDOM]             = "random",
        [PROC_GROUP_ROUND_ROBIN]        = "round_robin",
};

static char *thread_scheme_strs[] = {
        [THRD_AFFINITY_STATIC]          = "static",
        [THRD_AFFINITY_BALANCE]         = "balance",
        [THRD_AFFINITY_RANDOM]          = "random",
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

        jbuf_u32_add(b, "sampling_ms", &g_cfg.sampling_ms);

        {
                void *arr = jbuf_grow_arr_open(b, "profiles");
                void *obj;

                jbuf_grow_arr_setup(b, arr, (void *)&g_cfg.profiles, &g_cfg.profile_cnt, sizeof(profile_t));
                jbuf_offset_obj_open(b, obj, NULL, 0);

                jbuf_offset_add(b, strptr, "name", offsetof(profile_t, name));
                jbuf_offset_add(b, bool, "enabled", offsetof(profile_t, enabled));
                jbuf_offset_strval_add(b, "proc_prio", offsetof(profile_t, proc_prio), proc_prio_strs, NUM_PROC_PRIOS);
                jbuf_offset_strval_add(b, "io_prio", offsetof(profile_t, io_prio), io_prio_strs, NUM_IO_PRIOS);

                {
                        void *proc_grp;

                        jbuf_offset_obj_open(b, proc_grp, "processor_group", 0);

                        jbuf_offset_add(b, s32, "node", (size_t)&(((profile_t *)0)->proc_grp.node));
                        jbuf_offset_strval_add(b, "scheme",
                                               (size_t)&(((profile_t *)0)->proc_grp.scheme),
                                               proc_grp_scheme_strs, NUM_PROC_GRP_SCHEMES);

                        jbuf_obj_close(b, proc_grp);
                }

                {
                        void *thrd_obj;

                        jbuf_offset_obj_open(b, thrd_obj, "thread", 0);

                        jbuf_offset_add(b, hex_u64, "affinity",
                                        (size_t) &(((profile_t *)0)->thread.affinity));
                        jbuf_offset_strval_add(b, "scheme",
                                               (size_t) &(((profile_t *)0)->thread.scheme),
                                               thread_scheme_strs, NUM_THREAD_SCHEMES);

                        jbuf_obj_close(b, thrd_obj);
                }

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

                                jbuf_offset_strval_add(b, "type",
                                                       offsetof(struct proc_identity, type),
                                                       proc_identity_type_strs,
                                                       NUM_PROC_ID_TYPES);
                                jbuf_offset_strval_add(b, "filter",
                                                       offsetof(struct proc_identity, filter),
                                                       proc_identity_filter_strs,
                                                       NUM_PROC_ID_STR_FILTERS);
                                jbuf_offset_add(b, strptr, "value", offsetof(struct proc_identity, value));

                                jbuf_obj_close(b, id_obj);
                        }

                        jbuf_arr_close(b, id_arr);
                }

                jbuf_obj_close(b, obj);
                jbuf_arr_close(b, arr);
        }

        jbuf_obj_close(b, root);

        return 0;
}

int usrcfg_test(void)
{
        jbuf_t jbuf = { 0 };
        const char *json = "../config/config.json";

        usrcfg_root_key_create(&jbuf);

        json_print(json);

        jbuf_load(&jbuf, json);

        jbuf_traverse_print(&jbuf);

        jbuf_deinit(&jbuf);

        return 0;
}
