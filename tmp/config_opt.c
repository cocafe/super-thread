#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>

#include "voip_phone.h"
#include "config_opt.h"
#include "utils.h"
#include "logging.h"

static const int pjval_sip_proto[] = {
        [SIP_PROTO_UDP]         = PJSIP_TRANSPORT_UDP,
        [SIP_PROTO_TCP]         = PJSIP_TRANSPORT_TCP,
        [SIP_PROTO_TLS]         = PJSIP_TRANSPORT_TLS,
        [SIP_PROTO_UDP6]        = PJSIP_TRANSPORT_UDP6,
        [SIP_PROTO_TCP6]        = PJSIP_TRANSPORT_TCP6,
        [SIP_PROTO_TLS6]        = PJSIP_TRANSPORT_TLS6,
};

// DTMF cid pattern may vary from different areas
// refer [http://what-when-how.com/voip/dtmf-based-caller-id-voip/]
dtmf_cid_cfg dtmf_presets[] = {
        [DTMF_PRESET_A_C] = {
                .preamble       = 'A',  // China, Brazil...
                .markout        = 'C',
                .tone_ms        = 70,   // 50 ~ 70 suggested
                .idle_ms        = 50,
        },
        [DTMF_PRESET_D_C] = {
                .preamble       = 'D',  // Taiwan...
                .markout        = 'C',
                .tone_ms        = 48,
                .idle_ms        = 48,
        },
        [DTMF_PRESET_SPECIAL] = {
                // Special purpose for nonavailability
                // or restriction information
                .preamble       = 'B',
                .markout        = 'C',
                .tone_ms        = 48,
                .idle_ms        = 48,
        },
};

uint8_t g_verbose_print = 0;

struct config g_cfg;
struct pj_cfg *g_pj_cfg = &g_cfg.pj;

//
// help text format:
//      for description for option: aligned to \t
//      for option values:          aligned to \t\t
//

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
        .data      = &g_verbose_print,
        .data_sz   = sizeof(g_verbose_print),
        .data_def  = &(typeof(g_verbose_print)){ 0 },
        .data_type = D_UNSIGNED,
        .min       = 0,
        .max       = 0,
        .parse     = NULL,
        .help      = {
                        "Verbose debug message",
                        NULL,
        },
};

optdesc_t opt_json_print = {
        .short_opt = 0,
        .long_opt  = "json_print",
        .has_arg   = no_argument,
        .to_set    = 1,
        .data      = &g_cfg.json_print,
        .data_sz   = sizeof(g_cfg.json_print),
        .data_def  = &(typeof(g_cfg.json_print)){ 0 },
        .data_type = D_UNSIGNED,
        .min       = 0,
        .max       = 0,
        .parse     = NULL,
        .help      = {
                "Pretty print json contents",
                NULL,
        },
};

optdesc_t opt_stdin_dbg = {
        .short_opt = 0,
        .long_opt  = "stdin_dbg",
        .has_arg   = no_argument,
        .to_set    = 1,
        .data      = &g_cfg.stdin_dbg,
        .data_sz   = sizeof(g_cfg.stdin_dbg),
        .data_def  = &(typeof(g_cfg.stdin_dbg)){ 0 },
        .data_type = D_UNSIGNED,
        .min       = 0,
        .max       = 0,
        .parse     = NULL,
        .help      = {
                "Enable debugging in stdin input",
                NULL,
        },
};

optdesc_t opt_no_slic = {
        .short_opt = 0,
        .long_opt  = "no_slic",
        .has_arg   = no_argument,
        .to_set    = 1,
        .data      = &g_cfg.slic.no_slic,
        .data_sz   = sizeof(g_cfg.slic.no_slic),
        .data_def  = &(typeof(g_cfg.slic.no_slic)){ 0 },
        .data_type = D_UNSIGNED,
        .min       = 0,
        .max       = 0,
        .parse     = NULL,
        .help      = {
                "Run without slic chip, debug only",
                NULL,
        },
};

optdesc_t opt_pj_loglvl = {
        .short_opt = 0,
        .long_opt  = "pj_loglvl",
        .has_arg   = required_argument,
        .to_set    = 0,
        .data      = &g_cfg.pj.log_lvl,
        .data_sz   = sizeof(g_cfg.pj.log_lvl),
        .data_def  = &(typeof(g_cfg.pj.log_lvl)){ 2 },
        .data_type = D_UNSIGNED,
        .min       = 0,
        .max       = BIT(sizeof(g_cfg.pj.log_lvl) * BITS_PER_BYTE) - 1,
        .parse     = optarg_to_int,
        .help      = {
                        "PJSIP log level",
                        "\t4 for a reasonable debug experience",
                        "\t7 for debugging sip messages, etc",
                        NULL,
        },
};

optdesc_t opt_zlog_conf = {
        .short_opt = 0,
        .long_opt  = "zlog_conf",
        .has_arg   = required_argument,
        .to_set    = 0,
        .data      = g_cfg.zlog_conf,
        .data_sz   = sizeof(g_cfg.zlog_conf),
        .data_def  = ZLOG_CONF_DEF,
        .data_type = D_STRING,
        .min       = 0,
        .max       = 0,
        .parse     = optarg_to_str,
        .help      = {
                        "Path of zlog config",
                        NULL,
        },
};

optdesc_t opt_json_cfg = {
        .short_opt = 'c',
        .long_opt  = "config",
        .has_arg   = required_argument,
        .data      = g_cfg.json_cfg,
        .data_sz   = sizeof(g_cfg.json_cfg),
        .data_def  = JSON_CFG_PATH_DEF,
        .data_type = D_STRING,
        .parse     = optarg_to_str,
        .help      = {
                        "Path of json config",
                        "\tMost configs have been moved to json",
                        NULL,
        },
};

optdesc_t opt_call_stats = {
        .short_opt = 0,
        .long_opt  = "call_stats",
        .has_arg   = required_argument,
        .data      = g_cfg.call_stats,
        .data_sz   = sizeof(g_cfg.call_stats),
        .data_def  = CALL_STATS_PATH_DEF,
        .data_type = D_STRING,
        .parse     = optarg_to_str,
        .help      = {
                "Path of call stats json",
                NULL,
        },
};

optdesc_t opt_sip_stats = {
        .short_opt = 0,
        .long_opt  = "sip_stats",
        .has_arg   = required_argument,
        .data      = g_cfg.sip_stats,
        .data_sz   = sizeof(g_cfg.sip_stats),
        .data_def  = NULL,
        .data_type = D_STRING,
        .parse     = optarg_to_str,
        .help      = {
                "Path of sip stats json",
                NULL,
        },
};

optdesc_t opt_slic_reset = {
        .short_opt = 0,
        .long_opt  = "slic_reset",
        .has_arg   = no_argument,
        .to_set    = 1,
        .data      = &g_cfg.slic.force_reset,
        .data_sz   = sizeof(g_cfg.slic.force_reset),
        .data_def  = &(typeof(g_cfg.slic.force_reset)){ 0 },
        .data_type = D_UNSIGNED,
        .min       = 0,
        .max       = 1,
        .parse     = NULL,
        .help      = {
                        "Force ProSLIC reset during startup",
                        NULL,
        },
};

optdesc_t opt_cell_lock = {
        .short_opt = 0,
        .long_opt  = "cell_lock",
        .has_arg   = no_argument,
        .to_set    = 1,
        .data      = &g_cfg.call_opt.cell_lock,
        .data_sz   = sizeof(g_cfg.call_opt.cell_lock),
        .data_def  = &(typeof(g_cfg.call_opt.cell_lock)){ 0 },
        .data_type = D_UNSIGNED,
        .min       = 0,
        .max       = 1,
        .parse     = NULL,
        .help      = {
                "Only emergency call allowed",
                "\t...via VoLTE/VoCS",
                NULL,
        },
};


optdesc_t opt_cell_unlock_flag = {
        .short_opt = 0,
        .long_opt  = "cell_unlock_flag",
        .has_arg   = required_argument,
        .to_set    = 0,
        .data      = g_cfg.call_opt.cell_unlock_flag,
        .data_sz   = sizeof(g_cfg.call_opt.cell_unlock_flag),
        .data_def  = CELL_UNLOCK_FLAG_PATH,
        .data_type = D_STRING,
        .min       = 0,
        .max       = 0,
        .parse     = optarg_to_str,
        .help      = {
                        "Path of cell unlocked flag",
                        "\tsecret code can unlock it",
                        NULL,
        },
};

//
// this flag should be parsed as soon as possible
// if program exits due to invalid arguments and this param
// is not being parsed yet, the flag will not be set
//
optdesc_t opt_init_flag = {
        .short_opt = 0,
        .long_opt  = "init_flag",
        .has_arg   = required_argument,
        .to_set    = 0,
        .data      = g_cfg.init_flag,
        .data_sz   = sizeof(g_cfg.init_flag),
        .data_def  = NULL,
        .data_type = D_STRING,
        .min       = 0,
        .max       = 0,
        .parse     = optarg_to_str,
        .help      = {
                        "Path of successfully initialized flag",
                        NULL,
        },
};

optdesc_t opt_voip_enabled = {
        .short_opt = 0,
        .long_opt  = "voip_enabled",
        .has_arg   = required_argument,
        .to_set    = 0,
        .data      = &g_cfg.voip_enabled,
        .data_sz   = sizeof(g_cfg.voip_enabled),
        .data_def  = &(typeof(g_cfg.voip_enabled)){ 1 },
        .data_type = D_UNSIGNED,
        .min       = 0,
        .max       = 1,
        .parse     = optarg_to_int,
        .help      = {
                        "VoIP feature",
                        "\tIf disabled, SIP will not register",
                        "\t\t0 Disabled",
                        "\t\t1 Enabled",
                        NULL,
        },
};

optdesc_t opt_volte_enabled = {
        .short_opt = 0,
        .long_opt  = "volte_enabled",
        .has_arg   = required_argument,
        .to_set    = 0,
        .data      = &g_cfg.volte_enabled,
        .data_sz   = sizeof(g_cfg.volte_enabled),
        .data_def  = &(typeof(g_cfg.volte_enabled)){ 1 },
        .data_type = D_UNSIGNED,
        .min       = 0,
        .max       = 1,
        .parse     = optarg_to_int,
        .help      = {
                        "VoLTE feature",
                        "\tIf disabled, VoLTE stack will not register",
                        "\t\t0 Disabled",
                        "\t\t1 Enabled",
                        NULL,
        },
};

optdesc_t *opt_list[] = {
        &opt_help,
        &opt_zlog_conf,
        &opt_json_cfg,
        &opt_call_stats,
        &opt_sip_stats,
        &opt_init_flag,
        &opt_cell_unlock_flag,
        &opt_cell_lock,
        &opt_verbose,
        &opt_stdin_dbg,
        &opt_no_slic,
        &opt_json_print,
        &opt_pj_loglvl,
        &opt_slic_reset,
        &opt_voip_enabled,
        &opt_volte_enabled,
};

int optarg_to_int(void *data, char *optarg,
                  size_t vargc, ... /* uint32_t data_type, size_t data_sz,
 *                                     int64_t min, int64_t max */
                  ) {
        int64_t min, max, val;
        uint32_t tp;
        size_t sz;
        va_list ap;
        int err;

        va_start(ap, vargc);
        tp = va_arg(ap, uint32_t);
        sz = va_arg(ap, size_t);
        min = va_arg(ap, int64_t);
        max = va_arg(ap, int64_t);
        va_end(ap);

        errno = 0;
        val = strtoll(optarg, NULL, 10);

        if ((errno == ERANGE &&
             (val == LONG_MAX || val == LONG_MIN))
            || (errno != 0 && val == 0)) {
                pr_err("failed to convert string to num: %s\n", strerror(errno));
                return -errno;
        }

        if (val < min || val > max) {
                pr_err("invalid argument, proper range in: [ %jd ~ %jd ]\n",
                       min, max);
                return -EINVAL;
        }

        if (tp == D_UNSIGNED && val < 0) {
                pr_err("unsigned value does not accept negative input\n");
                return -EINVAL;
        }

        if ((err = ptr_word_write(data, sz, val)) == -EINVAL)
                pr_err("invalid word size: %zu\n", sz);

        return err;
}

int optarg_to_str(void *data, char *optarg,
                  size_t vargc, ... /* size_t len */)
{
        va_list ap;
        size_t len;

        va_start(ap, vargc);
        len = va_arg(ap, typeof(len));
        va_end(ap);

        // clear memory to avoid mixing with previous data
        memset(data, '\0', len);

        // strings like address do no validate content here
        memcpy(data, optarg, __min(len, strlen(optarg)));

        return 0;
}

int optstr_to_int(void *data, char *optarg,
                  size_t vargc, ... /* size_t data_sz, optstr_t *optstrs */)
{
        va_list ap;
        optstr_t *optstrs;
        size_t optlen;
        size_t data_sz;
        int i, err;

        va_start(ap, vargc);
        data_sz = va_arg(ap, typeof(data_sz));
        optstrs = va_arg(ap, typeof(optstrs));
        va_end(ap);

        // optstr array must be NULL terminated
        // if holes (NULL) exist in the list, loop will exit before list ends!
        for (i = 0, optlen = strlen(optarg); optstrs[i].optval != NULL; i++) {
                size_t slen = strlen(optstrs[i].optval);

                if (optlen != slen)
                        continue;

                if (!strncasecmp(optstrs[i].optval, optarg, __min(optlen, slen))) {
                        // @i will not be negative here
                        if ((uint64_t)i > GENMASK((BITS_PER_BYTE * data_sz) - 1U, 0U))
                                pr_err("destination *data cannot hold value 0x%x, continue anyway\n", i);

                        // the optstr array is listed by config index,
                        // so the index is the value of config
                        if ((err = ptr_word_write(data, data_sz, i)) == -EINVAL)
                                pr_err("invalid word size: %zu\n", data_sz);

                        return err;
                }
        }

        pr_err("value \'%s\' is not defined\n", optarg);
        return -ENOENT;
}

static __always_inline int opt_desc_parse(optdesc_t *d, char *optarg)
{
        if (d->parse == optarg_to_int)
                return d->parse(d->data, optarg, 4, d->data_type, d->data_sz, d->min, d->max);

        if (d->parse == optarg_to_str)
                return d->parse(d->data, optarg, 1, d->data_sz);

        if (d->parse == optstr_to_int)
                return d->parse(d->data, optarg, 2, d->data_sz, d->optstrs);

        pr_err("program bugged, usage of option parser not defined!\n");

        return -ENOENT;
}

void opt_desc_find(optdesc_t **list, size_t count,
                   char short_opt, optdesc_t **out)
{
        size_t i;

        if (short_opt == 0)
                return;

        for (i = 0; i < count; i++) {
                if (list[i]->short_opt == short_opt) {
                        *out = list[i];
                        return;
                }
        }
}

static inline int longopt_has_short(struct option opt)
{
        if (opt.flag == NULL && opt.val != '\0')
                return 1;

        return 0;
}

static inline int longopt_need_arg(struct option opt)
{
        if (opt.has_arg != no_argument)
                return 1;

        return 0;
}

int optfmt_alloc(char **buf, struct option *opts, size_t optcnt)
{
        size_t buf_len = 0;
        size_t i;

        // no valid option available
        if (optcnt <= 1)
                return -EINVAL;

        for (i = 0; i < optcnt; i++) {
                if (longopt_has_short(opts[i]))
                        buf_len++;

                if (longopt_need_arg(opts[i]))
                        buf_len++;
        }

        // reserved for extra '\0'
        buf_len++;

        *buf = (char *)calloc(buf_len, sizeof(char));
        if (!*buf)
                return -ENOMEM;

        return 0;
}

int optfmt_free(char **buf)
{
        if (!*buf)
                return 0;

        free(*buf);
        *buf = NULL;

        return 0;
}

int optfmt_puts(char *buf, struct option *opts, size_t optcnt)
{
        size_t i, j;

        // assume that at least dummy { 0, ..., 0 } is set
        if (optcnt <= 1)
                return -EINVAL;

        for (i = 0, j = 0; i < optcnt; i++) {
                if (longopt_has_short(opts[i])) {
                        buf[j] = (char)opts[i].val;

                        if (longopt_need_arg(opts[i]))
                                buf[++j] = ':';

                        j++;
                }
        }

        return 0;
}

static __always_inline void optval_help_print(optdesc_t *d,
                                              size_t param_len)
{
        const optstr_t *v;

        for (v = &d->optstrs[0]; v->optval != NULL; v++) {
                pr_color(FG_LT_GREEN, "    %-*s\t\t%s",
                           param_len, "", v->optval);

                if (v->desc)
                        pr_color(FG_GREEN, ": %s", v->desc);

                // print default option value
                // limited to integer option type
                if (d->data_def) {
                        uint64_t val;

                        if (ptr_unsigned_word_read(d->data_def, d->data_sz, &val)) {
                                pr_err("invalid data sz detected\n");
                                continue;
                        }

                        if ((size_t)val == (size_t)(v - &d->optstrs[0]))
                                pr_color(FG_GREEN, " (default)");
                }

                pr_color(FG_GREEN, "\n");
        }
}

void longopts_help(optdesc_t **descs, size_t count)
{
        char *buf;
        size_t buf_len;
        size_t i, s;

        // find max parameter text length
        for (i = 0, s = 0; i < count; i++) {
                size_t t = 0;

                if (descs[i]->short_opt)
                        t += 1 + 1 + 1; // '-' 'o' ' '

                t += 2 + strlen(descs[i]->long_opt) + 1; // '--' 'longopt' ' '

                if (descs[i]->has_arg == required_argument)
                        t += 4; // '<..>'

                if (t > s)
                        s = t;
        }

        buf_len = s + 8; // 8 whitespaces
        buf = malloc(buf_len);
        if (!buf) {
                pr_err("failed to allocate memory\n");
                return;
        }

        for (i = 0; i < count; i++) {
                optdesc_t *d = descs[i];
                size_t len = 0;
                size_t j;

                memset(buf, 0x00, buf_len);

                // XXX: DO NOT use snprintf() with this string cat trick
                if (d->short_opt)
                        len += snprintf(buf + len, buf_len - len, "-%c ", d->short_opt);

                len += sprintf(buf + len, "--%s ", d->long_opt);

                if (d->has_arg == required_argument)
                        len += snprintf(buf + len, buf_len - len, "<..>");

                // sanity check
                if (strlen(buf) >= buf_len) {
                        pr_err("param buffer overran!\n");
                        goto free_buf;
                }

                pr_color(FG_CYAN, "    %-*s", buf_len, buf);

                if (d->help[0] == NULL) {
                        printf("\n");
                        continue;
                }

                pr_color(FG_GREEN, "%s\n", d->help[0]);

                for (j = 1; d->help[j] != NULL; j++) {
                        pr_color(FG_GREEN,
                                   "    %-*s%s\n", buf_len, "", d->help[j]);
                }

                // if have option string values, aligned to \t\t
                if (d->optstrs)
                        optval_help_print(d, buf_len);

                // printf("\n"); // distinguish last option
        }

free_buf:
        free(buf);
}

struct option *longopts_make(optdesc_t **descs, size_t count)
{
        struct option *opts;
        size_t i;

        // free of out this scope
        opts = calloc(count, sizeof(struct option));
        if (!opts)
                return NULL;

        for (i = 0; i < count; i++) {
                opts[i].has_arg = descs[i]->has_arg;
                opts[i].name    = descs[i]->long_opt;
                opts[i].val     = descs[i]->short_opt;
                opts[i].flag    = NULL;

                if (descs[i]->short_opt == 0 &&
                    descs[i]->has_arg == no_argument) {
                        opts[i].val  = descs[i]->to_set;
                        opts[i].flag = descs[i]->data;
                }
        }

        return opts;
}

int longopts_parse(int argc, char *argv[])
{
        size_t optcnt = ARRAY_SIZE(opt_list);
        struct option *opts;
        char *optfmt;
        int ret = 0;
        int c;

        opts = longopts_make(opt_list, optcnt);
        if (!opts) {
                pr_err("failed to allocate option list\n");
                ret = -ENOMEM;

                goto out;
        }

        if ((ret = optfmt_alloc(&optfmt, opts, optcnt))) {
                pr_err("failed to allocate option buffer\n");
                goto free_opts;
        }

        if ((ret = optfmt_puts(optfmt, opts, optcnt))) {
                pr_err("failed to convert long options to buffer\n");
                goto free_optfmt;
        }

        // printf("%s\n", optfmt);

        while (1) {
                // traverse option array everytime
                optdesc_t *d = NULL;
                int optidx = -1;

                /**
                 * 1. if user input a longopt which has short case,
                 *    both @c and @optidx will be set.
                 * 2. if user input a longopt does not have short case,
                 *    @optidx will be set ONLY.
                 * 3. @optidx will _not_ be set if user input a short opt.
                 */
                c = getopt_long(argc, argv, optfmt, opts, &optidx);

                if (c == -1)
                        break;

                switch (c) {
                case 'h': // --help will be trapped here, too
                        longopts_help(opt_list, optcnt);
                        ret = -EINVAL;

                        goto free_optfmt;

                case '?': // getopt_long() already printed an error message
                        ret = -EINVAL;
                        goto free_optfmt;

                // handle long options that does not have short option
                case 0:
                        // handle for no_argument options
                        if (opts[optidx].flag != NULL)
                                break;

                        // long opt
                        d = opt_list[optidx];

                        /* falls through */
                        // __attribute__((fallthough));
                default: // find descriptor of short option
                        if (!d) { // if not falling from long opt
                                opt_desc_find(opt_list, ARRAY_SIZE(opt_list), c, &d);

                                if (!d) {
                                        pr_err("desc not defined for option \"-%c\"\n", c);
                                        goto free_optfmt;
                                }
                        }

                        if (!d->parse) {
                                pr_err("handler not defined for option [%s]\n", d->long_opt);
                                ret = -EFAULT;

                                goto free_optfmt;
                        }

                        if ((ret = opt_desc_parse(d, optarg))) {
                                pr_err("invalid arg [%s] for option [%s]\n",
                                        optarg, d->long_opt);

                                goto free_optfmt;
                        }

                        break;
                }
        }

        // if (optind < argc) {
        //         printf("non-option argv: ");

        //         while (optind < argc)
        //                 printf("%s ", argv[optind++]);
        // }

free_optfmt:
        optfmt_free(&optfmt);

free_opts:
        free(opts);

out:
        return ret;
}

// copy default configs
int config_init(struct config *cfg)
{
        optdesc_t *p;
        size_t i;

        UNUSED_PARAM(cfg);

        for (i = 0; i < ARRAY_SIZE(opt_list); i++) {
                p = opt_list[i];

                if (!p->data)
                        continue;

                // FIXME: option configs all use fixed data reference
                //        size should be specified at compile time
                //        support dynamic allocate data?
                if (!p->data_sz) {
                        pr_err("@data_sz of opt %s is not defined\n", p->long_opt);
                        return -EINVAL;
                }

                if (p->data_def) {
                        switch (p->data_type) {
                                case D_GENERIC:
                                case D_SIGNED:
                                case D_UNSIGNED:
                                case D_INTEGER:
                                        // use memcpy() on string will overrun
                                        memcpy(p->data, p->data_def, p->data_sz);
                                        continue;

                                case D_STRING:
                                        strncpy(p->data, p->data_def, p->data_sz);
                                        continue;

                                default: // goto memset()
                                        break; // jump out switch()
                        }
                }

                memset(p->data, 0x00, p->data_sz);
        }

        return 0;
}

static __always_inline int longest_text_get(void)
{
        optdesc_t *o;
        int ret = 0;
        size_t i;

        for (i = 0; i < ARRAY_SIZE(opt_list); i++) {
                int t;

                o = opt_list[i];

                if (!o->help[0])
                        continue;

                t = strlen(o->help[0]);
                if (t > ret)
                        ret = t;
        }

        return ret;
}

int config_dump(struct config *cfg)
{
        optdesc_t *o;
        int alignment;
        uint64_t val;

        // reserved for manually printing
        UNUSED_PARAM(cfg);

        alignment = longest_text_get();

        pr_color(FG_LT_CYAN, "---  config  ---\n");

        for (size_t i = 0; i < ARRAY_SIZE(opt_list); i++) {
                o = opt_list[i];

                if (!o->help[0])
                        continue;

                if (o->data_type == D_GENERIC)
                        continue;

                pr_color(FG_LT_CYAN, "%-*s : ", alignment, o->help[0]);

                switch (o->data_type) {
                case D_INTEGER:
                case D_SIGNED:
                        if (ptr_signed_word_read(o->data, o->data_sz, (int64_t *)&val)) {
                                pr_err("invalid data sz\n");
                                return -EINVAL;
                        }

                        if (o->optstrs)
                                if ((int64_t)val >= 0) // FIXME: did not check array range
                                        pr_color(FG_LT_CYAN, "%s", o->optstrs[val].optval);
                                else
                                        return -EINVAL;
                        else
                                pr_color(FG_LT_CYAN, "%jd", (int64_t)val);

                        break;

                case D_UNSIGNED:
                        if (ptr_unsigned_word_read(o->data, o->data_sz, &val)) {
                                pr_err("invalid data sz\n");
                                return -EINVAL;
                        }

                        if (o->optstrs) // FIXME: did not check array range
                                pr_color(FG_LT_CYAN, "%s", o->optstrs[val].optval);
                        else
                                pr_color(FG_LT_CYAN, "%ju", val);

                        break;

                case D_STRING:
                        pr_color(FG_LT_CYAN, "%s", (char *)o->data);
                        break;

                case D_FLOAT:
                case D_DOUBLE:
                        // TODO
                default:
                        break;
                }

                pr_color(FG_LT_CYAN, "\n");
        }

        pr_color(FG_LT_CYAN, "----------------\n");

        return 0;
}

static int cfg_cid_apply(struct config *cfg)
{
        char echo_buf[PATH_MAX] = {0};
        int ret;

        if (!cfg->cid.enabled)
                cfg->cid.method = CID_NONE;

        snprintf(echo_buf, sizeof(echo_buf),"cid=%s",
                 optstrs_cid_method[cfg->cid.method].optval);

        // ensure null terminated, strlen() used below
        echo_buf[sizeof(echo_buf) - 1] = '\0';

        if ((ret = file_write("/proc/si3218x", echo_buf, strlen(echo_buf)))) {
                pr_err("failed to write cid method\n");
                return ret;
        }

        return ret;
}

static int pj_acc_proxy_verify(struct pj_cfg *pj_cfg, struct pj_acc *acc)
{
        for (size_t i = 0; i < ARRAY_SIZE(acc->prx_sel); i++) {
                int8_t prx_idx = acc->prx_sel[i];

                if (prx_idx < 0) {
                        continue;
                }

                if ((size_t)prx_idx >= ARRAY_SIZE(pj_cfg->proxy)) {
                        pr_err("proxy idx %d is run away\n", prx_idx);
                        return -EINVAL;
                }

                for (size_t j = i + 1; j < ARRAY_SIZE(acc->prx_sel); j++) {
                        if (prx_idx == acc->prx_sel[j]) {
                                pr_warn("duplicated proxy selection: [%d], clear it\n", prx_idx);
                                acc->prx_sel[j] = -1;
                        }
                }
        }

        return 0;
}

static int pj_account_apply(struct pj_cfg *pj_cfg)
{
        pjsua_acc_config def_cfg;
        struct pj_acc *acc, *last_acc = NULL;
        int have_default = 0;

        pjsua_acc_config_default(&def_cfg);

        for (size_t i = 0; i < ARRAY_SIZE(pj_cfg->account); i++) {
                acc = pj_cfg->account[i];

                if (!acc)
                        continue;

                last_acc = acc;

                if (!acc->enabled)
                        continue;

                if (pj_acc_proxy_verify(pj_cfg, acc))
                        return -EINVAL;

                if (acc->opt.is_default) {
                        if (have_default == 0) {
                                have_default = 1;
                        } else {
                                pr_err("multiple accounts set as default\n");
                                return -EINVAL;
                        }
                }

                if (acc->reg.reg_timeout)
                        acc->reg.reg_timeout = def_cfg.reg_timeout;

                if (acc->reg.retry_intv == -1)
                        acc->reg.retry_intv = def_cfg.reg_retry_interval;

                if (acc->reg.unreg_timeout == -1)
                        acc->reg.unreg_timeout = def_cfg.unreg_timeout;

                if (acc->reg.hb_intv == -1)
                        acc->reg.hb_intv = def_cfg.ka_interval;

                if (acc->timer.min_expire_secs == -1)
                        acc->timer.min_expire_secs = def_cfg.timer_setting.min_se;

                if (acc->timer.expire_secs == -1)
                        acc->timer.expire_secs = def_cfg.timer_setting.sess_expires;

                if (acc->timer.min_expire_secs > acc->timer.expire_secs) {
                        pr_err("account [%zu]: expire_secs(%d) should > min_expire_secs(%d)\n",
                               i, acc->timer.expire_secs, acc->timer.min_expire_secs);
                        return -EINVAL;
                }
        }

        if (!have_default && last_acc) {
                pr_warn("no default account set, choose last one as default\n");
                last_acc->opt.is_default = 1;
        }

        return 0;
}

static int pj_audio_apply(struct pj_cfg *pj_cfg)
{
        struct pj_audio *audio = &pj_cfg->audio;

        // when exceeds 500ms webrtc reports errors
        if (audio->ec.tail_ms > 500 && audio->ec.alg == EC_ALG_WEBRTC)
                audio->ec.tail_ms = 500;

        if (audio->ec.tail_ms > 1000) {
                pr_warn("@tail_ms is too big\n");
                audio->ec.tail_ms = 1000;
        }

        if (audio->jitter_buf.prefetch_ms.min >= 0 &&
            audio->jitter_buf.prefetch_ms.max >= 0 &&
            audio->jitter_buf.prefetch_ms.init >= 0) {
                if (audio->jitter_buf.prefetch_ms.min >=
                    audio->jitter_buf.prefetch_ms.max) {
                        pr_err("@min of jitter_buf cannot be larger than @max\n");
                        return -EINVAL;
                }

                if (audio->jitter_buf.prefetch_ms.init <
                    audio->jitter_buf.prefetch_ms.min) {
                        pr_err("@init of jitter buf cannot be littler than @min\n");
                        return -EINVAL;
                }

                if (audio->jitter_buf.prefetch_ms.init >
                    audio->jitter_buf.prefetch_ms.max) {
                        pr_err("@init of jitter buf cannot be larger than @max\n");
                        return -EINVAL;
                }
        }

        return 0;
}

static int pj_transport_apply(struct pj_cfg *pj_cfg)
{
        const int sip_proto_ipv6_bm = BIT(SIP_PROTO_UDP6) |
                                      BIT(SIP_PROTO_TCP6) |
                                      BIT(SIP_PROTO_TLS6);

        pjval_conv_safe(pj_cfg->trans.proto_pj,
                        pj_cfg->trans.proto,
                        pjval_sip_proto);

        if (pj_cfg->trans.proto_pj & sip_proto_ipv6_bm) {
                if (!pj_cfg->trans.ipv6) {
                        pr_err("ipv6 global switch is not enabled\n");
                        return -EINVAL;
                }
        }

        return 0;
}

static int cfg_pj_apply(struct config *cfg)
{
        struct pj_cfg *pj_cfg = &cfg->pj;
        int ret;

        if ((ret = pj_transport_apply(pj_cfg)))
                return ret;

        if ((ret = pj_account_apply(pj_cfg)))
                return ret;

        if ((ret = pj_audio_apply(pj_cfg)))
                return ret;

        return 0;
}

int config_apply(struct config *cfg)
{
        int ret;

        if ((ret = cfg_cid_apply(cfg)))
                goto out;

        if ((ret = cfg_pj_apply(cfg)))
                goto out;

out:
        return ret;
}



int
file2wcs (int fd, const char *charset, wchar_t *outbuf, size_t avail)
{
        char inbuf[BUFSIZ];
        size_t insize = 0;
        char *wrptr = (char *) outbuf;
        int result = 0;
        iconv_t cd;

        cd = iconv_open ("WCHAR_T", charset);
        if (cd == (iconv_t) -1)
        {
                /* Something went wrong.  */
                if (errno == EINVAL)
                        error (0, 0, "conversion from '%s' to wchar_t not available",
                               charset);
                else
                        perror ("iconv_open");

                /* Terminate the output string.  */
                *outbuf = L'\0';

                return -1;
        }

        while (avail > 0)
        {
                size_t nread;
                size_t nconv;
                char *inptr = inbuf;

                /* Read more input.  */
                nread = read (fd, inbuf + insize, sizeof (inbuf) - insize);
                if (nread == 0)
                {
                        /* When we come here the file is completely read.
                           This still could mean there are some unused
                           characters in the inbuf.  Put them back.  */
                        if (lseek (fd, -insize, SEEK_CUR) == -1)
                                result = -1;

                        /* Now write out the byte sequence to get into the
                           initial state if this is necessary.  */
                        iconv (cd, NULL, NULL, &wrptr, &avail);

                        break;
                }
                insize += nread;

                /* Do the conversion.  */
                nconv = iconv (cd, &inptr, &insize, &wrptr, &avail);
                if (nconv == (size_t) -1)
                {
                        /* Not everything went right.  It might only be
                           an unfinished byte sequence at the end of the
                           buffer.  Or it is a real problem.  */
                        if (errno == EINVAL)
                                /* This is harmless.  Simply move the unused
                                   bytes to the beginning of the buffer so that
                                   they can be used in the next round.  */
                                memmove (inbuf, inptr, insize);
                        else
                        {
                                /* It is a real problem.  Maybe we ran out of
                                   space in the output buffer or we have invalid
                                   input.  In any case back the file pointer to
                                   the position of the last processed byte.  */
                                lseek (fd, -insize, SEEK_CUR);
                                result = -1;
                                break;
                        }
                }
        }

        /* Terminate the output string.  */
        if (avail >= sizeof (wchar_t))
                *((wchar_t *) wrptr) = L'\0';

        if (iconv_close (cd) != 0)
                perror ("iconv_close");

        return (wchar_t *) wrptr - outbuf;
}