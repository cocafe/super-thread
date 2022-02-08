#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>

#ifdef UNICODE
#include <iconv.h>
#endif

#include "utils.h"
#include "logging.h"
#include "config.h"
#include "config_opts.h"

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
                         (int)param_len, "", v->optval);

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

                pr_color(FG_CYAN, "    %-*s", (int)buf_len, buf);

                if (d->help[0] == NULL) {
                        printf("\n");
                        continue;
                }

                pr_color(FG_GREEN, "%s\n", d->help[0]);

                for (j = 1; d->help[j] != NULL; j++) {
                        pr_color(FG_GREEN,
                                 "    %-*s%s\n", (int)buf_len, "", d->help[j]);
                }

                // if have option string values, aligned to \t\t
                if (d->optstrs)
                        optval_help_print(d, buf_len);

                // printf("\n"); // distinguish last option
        }

free_buf:
        free(buf);
}

#if defined __WINNT__ && defined SUBSYS_WINDOW
void longopts_help_messagebox(optdesc_t **descs, size_t count)
{
        char *line, *buf = NULL;
        size_t line_len, buf_len, buf_pos;
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

        line_len = s + 8; // 8 whitespaces
        line = malloc(line_len);
        if (!line) {
                pr_err("failed to allocate memory\n");
                return;
        }

        buf_pos = 0;
        buf_len = 2048;
        buf = calloc(buf_len, sizeof(char));
        if (!buf) {
                pr_err("failed to allocate memory\n");
                return;
        }

        for (i = 0; i < count; i++) {
                optdesc_t *d = descs[i];
                size_t len = 0;
                size_t j;

                memset(line, 0x00, line_len);

                // XXX: DO NOT use snprintf() with this string cat trick
                if (d->short_opt)
                        len += snprintf(line + len, line_len - len, "-%c ", d->short_opt);

                len += sprintf(line + len, "--%s ", d->long_opt);

                if (d->has_arg == required_argument)
                        len += snprintf(line + len, line_len - len, "<..>");

                snprintf_resize(&buf, &buf_pos, &buf_len, "    %-*s", (int)line_len, line);

                if (d->help[0] == NULL) {
                        printf("\n");
                        continue;
                }

                snprintf_resize(&buf, &buf_pos, &buf_len, "%s\n", d->help[0]);

                for (j = 1; d->help[j] != NULL; j++) {
                        snprintf_resize(&buf, &buf_pos, &buf_len,
                                 "    %-*s%s\n", (int)line_len, "", d->help[j]);
                }

                // if have option string values, aligned to \t\t
                if (d->optstrs) {
                        const optstr_t *v;

                        for (v = &d->optstrs[0]; v->optval != NULL; v++) {
                                snprintf_resize(&buf, &buf_pos, &buf_len,
                                                "    %-*s\t\t%s",
                                                (int)line_len, "", v->optval);

                                if (v->desc)
                                        snprintf_resize(&buf, &buf_pos, &buf_len, ": %s", v->desc);

                                // print default option value
                                // limited to integer option type
                                if (d->data_def) {
                                        uint64_t val;

                                        if (ptr_unsigned_word_read(d->data_def, d->data_sz, &val)) {
                                                pr_err("invalid data sz detected\n");
                                                continue;
                                        }

                                        if ((size_t)val == (size_t)(v - &d->optstrs[0]))
                                                snprintf_resize(&buf, &buf_pos, &buf_len, " (default)");
                                }

                                snprintf_resize(&buf, &buf_pos, &buf_len, "\n");
                        }
                }
        }

        mb_printf("HELP", MB_OK, "%s", buf);

        free(line);
        free(buf);
}
#endif

struct option *longopts_make(optdesc_t **descs, size_t count)
{
        struct option *opts;
        size_t i;

        // free of out this scope
        opts = calloc(count, sizeof(struct option));
        if (!opts)
                return NULL;

        for (i = 0; i < count; i++) {
                if (descs[i] == NULL)
                        break;

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

static size_t opt_list_count(optdesc_t **list)
{
        size_t i = 0;
        optdesc_t *t;

        for (t = list[i]; t; t = list[++i]);

        return i;
}

/**
 * longopts_parse()
 *
 * @param argc: argc
 * @param argv: argv
 * @param opt_list: must be NULL terminated
 * @return 0 on success
 */
int longopts_parse(int argc, char *argv[], optdesc_t **opt_list)
{
        size_t optcnt = opt_list_count(opt_list);
        struct option *opts;
        char *optfmt;
        int ret = 0;
        int c;

        if (optcnt == 0)
                return -ENODATA;

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
#if defined __WINNT__ && defined SUBSYS_WINDOW
                        longopts_help_messagebox(opt_list, optcnt);
#else
                        longopts_help(opt_list, optcnt);
#endif
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
                                opt_desc_find(opt_list, optcnt, c, &d);

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

#ifdef UNICODE
int wchar_longopts_parse(int argc, wchar_t *wargv[], optdesc_t **opt_list)
{
        char **argv;
        int ret = 0;

        argv = calloc(argc, sizeof(char *));
        if (!argv)
                return -ENOMEM;

        for (int i = 0; i < argc; i++) {
                char **v = &argv[i];
                size_t len = wcslen(wargv[i]);
                *v = calloc(len + 2, sizeof(char));
                if (!*v)
                        return -ENOMEM;

                if (iconv_wc2utf8(wargv[i], len * sizeof(wchar_t), *v, len * sizeof(char)))
                        return -EINVAL;
        }

        ret = longopts_parse(argc, argv, opt_list);

        for (int i = 0; i < argc; i++) {
                if (argv[i])
                        free(argv[i]);
        }

        free(argv);

        return ret;
}
#endif
