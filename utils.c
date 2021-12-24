#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <float.h>

#include "cJSON.h"

#include "utils.h"

//
// helpers
//

static const char *quad_bits_rep[] = {
        [0x00] = "0000",
        [0x01] = "0001",
        [0x02] = "0010",
        [0x03] = "0011",
        [0x04] = "0100",
        [0x05] = "0101",
        [0x06] = "0110",
        [0x07] = "0111",
        [0x08] = "1000",
        [0x09] = "1001",
        [0x0A] = "1010",
        [0x0B] = "1011",
        [0x0C] = "1100",
        [0x0D] = "1101",
        [0x0E] = "1110",
        [0x0F] = "1111",
};

int bin_snprintf(char *str, size_t slen, uint64_t val, size_t vsize)
{
        size_t c = 0;

        val = htobe64(val);

        if (!str || !slen || !vsize)
                return -EINVAL;

        // snprintf() will always put an extra '\0' at the end of buffer
        if (vsize > sizeof(uint64_t) || slen < (vsize * BITS_PER_BYTE + 1))
                return -ERANGE;

        for (size_t i = sizeof(uint64_t) - vsize; i < sizeof(uint64_t); i++) {
                uint8_t byte_hi, byte_lo;

                byte_hi = ((uint8_t *)&val)[i] & 0xf0U >> 4U;
                byte_lo = ((uint8_t *)&val)[i] & 0x0fU;

                snprintf(&str[c], slen - c, "%s%s",
                         quad_bits_rep[byte_hi], quad_bits_rep[byte_lo]);
                c += 8;
        }

        return 0;
}

int __str_cat(char *dest, size_t dest_sz, char *src)
{
        // strncat() require @dest has space
        // more than strlen(dest) + @n + 1
        size_t s = strlen(dest) + strlen(src) + 1;

        if (s > dest_sz) {
                pr_err("insufficient space for destination string\n");
                return -E2BIG;
        }

        // strncat() return address to @dest
        strncat(dest, src, strlen(src));

        return 0;
}

char *__str_ncpy(char *dest, const char *src, size_t dest_sz)
{
        char *ret;

        ret = strncpy(dest, src, dest_sz - 1);
        dest[dest_sz - 1] = '\0';

        return ret;
}

//
// pthread helper
//

#define PMUTEX_DBG_TRY_TIMES            (7)
#define PMUTEX_DEB_TRY_SECS             (1)

int pthread_mutex_multi_trylock(pthread_mutex_t *lock)
{
        int i, ret;

        for (i = 0; i < PMUTEX_DBG_TRY_TIMES; i++) {
                ret = pthread_mutex_trylock(lock);
                if (ret == 0)
                        break;

                sleep(PMUTEX_DEB_TRY_SECS);
        }

        if (ret != 0)
                pr_err("failed to acquire lock over %d secs, maybe deadlock?\n",
                        PMUTEX_DBG_TRY_TIMES * PMUTEX_DEB_TRY_SECS);

        return ret;
}

//
// helper
//

int is_valid_ipaddr(char *ipstr, int ipver)
{
        unsigned char buf[sizeof(struct in6_addr)];

        return (inet_pton(ipver, ipstr, buf) == 1);
}

int float_equal(float a, float b, float epsilon)
{
        // abs() also handles -0.0 and +0.0
        float abs_a = fabsf(a);
        float abs_b = fabsf(b);

        float diff = fabsf(a - b);

        // Explicitly handle NaN here
        if (isnan(a) || isnan(b))
                return 0;

        // Handle same infinite edge cases, and same binary representations
        if (a == b) {
                return 1;
        } else if (a == 0 || b == 0 || diff < FLT_MIN) { // -0.0 will be treated as 0.0 arithmetically
                // a or b is zero or both are extremely close to zero
                // that's, diff is smaller than smallest normalized float number (may denormalized)
                // relative error is less meaningful here
                return diff < (epsilon * FLT_MIN);
        } else {
                // use relative error method
                // we have excluded a or b is zero case above
                return (diff / fminf((abs_a + abs_b), FLT_MIN)) < epsilon;
        }
}

char *file_read(const char *path)
{
        char *buf = NULL;
        FILE *fp = 0;
        int64_t fsize = 0; // ssize_t may not suitable on 32bits

        fp = fopen(path, "rb");
        if (!fp) {
                pr_err("fopen(): %s: %s\n", path, strerror(errno));
                goto err;
        }

        if (fseek(fp, 0UL, SEEK_END)) {
                pr_err("fseek(): %s: %s\n", path, strerror(errno));
                goto err;
        }

        fsize = ftell(fp);
        if (fsize == -1) {
                pr_err("ftell(): %s: %s\n", path, strerror(errno));
                goto err;
        }

        if (fseek(fp, 0UL, SEEK_SET)) {
                pr_err("rewind(): %s: %s\n", path, strerror(errno));
                goto err;
        }

        buf = calloc(1, fsize + 2);
        if (!buf) {
                pr_err("failed to allocate memory size: %zu\n", (size_t)fsize);
                goto err;
        }

        if (fread(buf, fsize, 1, fp) != 1) {
                pr_err("fread(): %s: %s\n", path, strerror(ferror(fp)));
                goto err;
        }

        fclose(fp);

        return buf;

err:
        if (fp)
                fclose(fp);

        if (buf)
                free(buf);

        return NULL;
}

int file_write(const char *path, const void *data, size_t sz)
{
        FILE *fp = 0;
        int ret = 0;

        if (!path || !data || !sz)
                return -EINVAL;

        fp = fopen(path, "wb");
        if (!fp) {
                pr_err("fopen(): %s: %s\n", path, strerror(errno));
                return errno;
        }

        if (fwrite(data, sz, 1, fp) != 1) {
                pr_err("fwrite(): %s: %s\n", path, strerror((ret = ferror(fp))));
        }

        fclose(fp);

        return ret;
}

//
// internal buffer
//

void buf_reset(buf_t *buf)
{
        if (unlikely(!buf))
                return;

        buf->s = buf->__data;
        buf->e = buf->s;

        memset(buf->__data, '\0', buf->__size);
}

int buf_init(buf_t *buf, size_t sz)
{
        if (unlikely(!buf))
                return -EINVAL;

        if (buf->__data)
                pr_err("buf_t is not clear, continue anyway\n");

        buf->size = sz;
        // wanna ensure NULL terminated
        buf->__size = buf->size + 2;

        buf->__data = calloc(1, buf->__size);
        if (!buf->__data) {
                pr_err("failed to allocate memory\n");
                return -ENOMEM;
        }

        buf->__s = buf->__data;
        buf->__e = &(buf->__data[buf->size - 1]);

        buf->s = buf->__data;
        buf->e = buf->s;

        return 0;
}

int buf_deinit(buf_t *buf)
{
        if (unlikely(!buf))
                return -EINVAL;

        if (!buf->__data)
                return -ENODATA;

        free(buf->__data);
        memset(buf, 0x00, sizeof(buf_t));

        return 0;
}

int buf_put(buf_t *buf, const char *in, size_t len)
{
        if (unlikely(!buf))
                return -EINVAL;

        if (buf_is_full(buf))
                return -ENOSPC;

        // if buf->e points to outbound last element
        if ((size_t)(buf->e + len) > (size_t)(buf->__e + 1))
                return -E2BIG;

        memcpy(buf->e, in, len);
        buf->e += len;

        return 0;
}

/**
 * buf_forward_discard() - move start pointer towards end pointer
 *
 * @param buf: pointer to buf_t
 * @param len: length to move
 * @return 0 on success, otherwise error code
 */
int buf_forward_discard(buf_t *buf, size_t len)
{
        if (unlikely(!buf))
                return -EINVAL;

        // allow to make valid buffer length 0 (buf->s == buf->e)
        if (buf->s + len > buf->e)
                return -ENOSPC;

        // contents before start pointer is not discarded
        buf->s += len;

        return 0;
}

/**
 * buf_backward_discard() - move end pointer towards start pointer,
 *                          discard contents after end pointer
 *
 * @param buf: pointer to buf_t
 * @param len: length to move
 * @return 0 on success, otherwise error code
 */
int buf_backward_discard(buf_t *buf, size_t len)
{
        if (unlikely(!buf))
                return -EINVAL;

        if (buf->e - len < buf->s)
                return -ENOSPC;

        // recall that buf->e points to where to put next char
        buf->e -= len;

        // discard contents after moved end pointer,
        // to ensure NULL terminated
        memset(buf->e, '\0', (size_t)(buf->__e - buf->e));

        return 0;
}

/*
 * json utils
 */

void json_traverse(cJSON *root, uint32_t depth)
{
        char *padding = alloca(32);
        cJSON *curr = NULL;

        if (!root || !padding)
                return;

        memset(padding, '\t', 32);

        cJSON_ArrayForEach(curr, root) {
                pr_color(FG_LT_YELLOW, "%.*s", depth, padding);

                pr_color(FG_LT_YELLOW, "[%s] ", curr->string);

                switch (curr->type) {
                case cJSON_False:
                        pr_color(FG_RED, ": [false]");
                        break;
                case cJSON_True:
                        pr_color(FG_GREEN, ": [true]");
                        break;
                case cJSON_NULL:
                        pr_color(FG_LT_RED, "[null]");
                        break;
                case cJSON_Number:
                        pr_color(FG_LT_MAGENTA, "[number]");
                        pr_color(FG_LT_WHITE, " : %.f", cJSON_GetNumberValue(curr));
                        break;
                case cJSON_String:
                        pr_color(FG_LT_GREEN, "[string]");
                        pr_color(FG_LT_WHITE, " : \"%s\"", cJSON_GetStringValue(curr));
                        break;
                case cJSON_Array:
                        pr_color(FG_LT_CYAN, "[array]");
                        break;
                case cJSON_Object:
                        pr_color(FG_LT_BLUE, "[object]");
                        break;
                case cJSON_Raw:
                        pr_color(FG_LT_RED, "[raws]");
                        break;
                }

                pr_color(FG_LT_WHITE, "\n");

                json_traverse(curr, depth + 1);
        }
}

/*
 * json validator
 */

static char *cjson_type_to_str(int type)
{
        // return string based on lua's type
        switch (type) {
        case cJSON_False:
        case cJSON_True:
                return "boolean";
        case cJSON_NULL:
                return "null";
        case cJSON_Number:
                return "number";
        case cJSON_String:
                return "string";
        case cJSON_Array:
        case cJSON_Object:
                return "table";
        case cJSON_Raw:
                return "raw";
        default:
                return "invalid";
        }

        return "invalid";
}

static int json_number_validate(cJSON *c, cJSON *v, cJSON *kval)
{
        cJSON *min_j = cJSON_GetObjectItem(kval, "[");
        cJSON *max_j = cJSON_GetObjectItem(kval, "]");
        float val = (float)cJSON_GetNumberValue(c);

        if (min_j) {
                float min = (float)cJSON_GetNumberValue(min_j);

                if (!float_equal(min, val, FLT_EPSILON)) {
                        if (val < min) {
                                pr_err("value of key [%s] out of range: %.f < %.f\n",
                                       v->string, val, min);
                                return -EINVAL;
                        }
                }
        }

        if (max_j) {
                float max = (float)cJSON_GetNumberValue(max_j);

                if (!float_equal(max, val, FLT_EPSILON)) {
                        if (val > max) {
                                pr_err("value of key [%s] out of range: %.f > %.f\n",
                                       v->string,val, max);
                                return -EINVAL;
                        }
                }
        }

        // not supported:
        //      littler_than
        //      greater_than
        //      to_int

        return 0;
}

static int json_string_validate(cJSON *c, cJSON *v, cJSON *kval)
{
        cJSON *i;
        char *str = cJSON_GetStringValue(c);

        if (!str) {
                pr_err("failed to get string from key [%s]\n", v->string);
                return -EINVAL;
        }

        if (strlen(str) == 0) {
                if (cJSON_GetObjectItem(v, "allow_empty"))
                        return 0;

                // fall through
        }

        cJSON_ArrayForEach(i, kval) {
                if (!strcmp(str, i->string))
                        return 0;
        }

        pr_err("value [%s] of key [%s] is not defined\n", str, v->string);

        return -EINVAL;
}

static int json_ipaddr_validate(cJSON *c, cJSON *v, cJSON *kval)
{
        char *ipstr = cJSON_GetStringValue(c);
        char *ipver_s = cJSON_GetStringValue(kval);
        int ipver, any = 0;

        if (!ipstr) {
                pr_err("failed to get string from key [%s]\n", v->string);
                return -EINVAL;
        }

        if (strlen(ipstr) == 0) {
                if (cJSON_GetObjectItem(v, "allow_empty"))
                        return 0;

                // fall through
        }

        if (!strcmp(ipver_s, "ipv4"))
                ipver = AF_INET;
        else if (!strcmp(ipver_s, "ipv6"))
                ipver = AF_INET6;
        else if (!strcmp(ipver_s, "any"))
                any = 1;
        else {
                pr_err("undefined option [%s] for key [%s]\n", ipver_s, v->string);
                return -EINVAL;
        }

        if (any) {
                int vers[] = { AF_INET, AF_INET6 };

                for (size_t i = 0; i < ARRAY_SIZE(vers); i++)
                        if (is_valid_ipaddr(ipstr, vers[i]))
                                return 0;

                pr_err("ip addr [%s] is not either valid ipv4/v6\n", ipstr);
                return -EINVAL;
        } else {
                if (!is_valid_ipaddr(ipstr, ipver)) {
                        pr_err("ip addr [%s] is not a valid %s\n", ipstr, ipver_s);
                        return -EINVAL;
                }
        }

        return 0;
}

static int json_ip_array_validate(cJSON *c, cJSON *v, cJSON *kval)
{
        cJSON *i;
        size_t j = 0;

        cJSON_ArrayForEach(i, c) {
                if (json_ipaddr_validate(i, v, kval)) {
                        pr_err("[#%zu] of array [%s] failed\n", j, c->string);
                        return -EINVAL;
                }

                j++;
        }

        return 0;
}

static int json_str_type_validate(cJSON *c, cJSON *v, cJSON *kval)
{
        cJSON *str_type_j = cJSON_GetObjectItem(v, "str_type");
        char *str_type;

        if (!str_type_j) {
                return json_string_validate(c, v, kval);
        }

        str_type = cJSON_GetStringValue(str_type_j);
        if (!strcmp(str_type, "ipaddr")) {
                if (json_ipaddr_validate(c, v, kval))
                        return -EINVAL;
        } else{
                pr_err("str_type [%s] of key [%s] is not supported\n", str_type, v->string);
                return -EINVAL;
        }

        return 0;
}

static int json_str_array_validate(cJSON *c, cJSON *v, cJSON *kval)
{
        cJSON *i;
        size_t j = 0;

        cJSON_ArrayForEach(i, c) {
                if (json_string_validate(i, v, kval)) {
                        pr_err("[#%zu] of array [%s] failed\n", j, c->string);
                        return -EINVAL;
                }

                j++;
        }

        return 0;
}

static int json_tbl_array_validate(cJSON *c, cJSON *kval)
{
        cJSON *i;
        size_t j = 0;

        cJSON_ArrayForEach(i, c) {
                if (json_validate(i, kval)) {
                        pr_err("[#%zu] of array [%s] failed\n", j, c->string);
                        return -EINVAL;
                }

                j++;
        }

        return 0;
}

static int json_table_validate(cJSON *c, cJSON *v, cJSON *kval)
{
        cJSON *tbl_type_j = cJSON_GetObjectItem(v, "tbl_type");
        char *tbl_type;

        if (!tbl_type_j) {
                pr_err("tbl_type of key [%s] is not defined\n", c->string);
                return -EINVAL;
        }

        tbl_type = cJSON_GetStringValue(tbl_type_j);
        if (!tbl_type) {
                pr_err("tbl_type of key [%s] is not a string\n", c->string);
                return -EINVAL;
        }

        if (c->type == cJSON_Array) {
                if (!strcmp(tbl_type, "str_array")) {
                        if (json_str_array_validate(c, v, kval))
                                return -EINVAL;
                } else if (!strcmp(tbl_type, "tbl_array")) {
                        if (json_tbl_array_validate(c, kval))
                                return -EINVAL;
                } else if (!strcmp(tbl_type, "ip_array")) {
                        if (json_ip_array_validate(c, v, kval))
                                return -EINVAL;
                } else {
                        pr_err("tbl_type [%s] is not supported\n", tbl_type);
                        return -EINVAL;
                }
        }

        if (c->type == cJSON_Object && !strcmp(tbl_type, "table")) {
                if (json_validate(c, kval))
                        return -EINVAL;
        }

        return 0;
}

int json_validate(cJSON *root, cJSON *verify)
{
        cJSON *i, *c;

        if (!root || !verify) {
                pr_err("@root or @verify == null\n");
                return 0;
        }

        cJSON_ArrayForEach(i, verify) {
                char  *key = i->string;
                cJSON *key_val;
                char  *key_type;
                cJSON *key_type_j;

                if (!key)
                        continue;

                c = cJSON_GetObjectItem(root, key);

                if (!c) {
                        if (cJSON_GetObjectItem(i, "optional"))
                                continue;

                        pr_err("key [%s] is not found\n", key);
                        return -EINVAL;
                }

                key_type_j = cJSON_GetObjectItem(i, "key_type");
                if (!key_type_j) {
                        pr_err("key_type for key [%s] is not defined\n", key);
                        return -EINVAL;
                }

                key_type = cJSON_GetStringValue(key_type_j);
                if (strcmp(cjson_type_to_str(c->type), key_type)) {
                        pr_err("type of key [%s] mismatched: %s != %s\n",
                               key, cjson_type_to_str(c->type), key_type);
                        return -EINVAL;
                }

                key_val = cJSON_GetObjectItem(i, "key_value");
                if (!key_val)
                        continue;

                switch (c->type) {
                case cJSON_String:
                        if (json_str_type_validate(c, i, key_val))
                                return -EINVAL;

                        break;
                case cJSON_Number:
                        if (json_number_validate(c, i, key_val))
                                return -EINVAL;

                        break;
                case cJSON_Array:
                case cJSON_Object:
                        if (json_table_validate(c, i, key_val))
                                return -EINVAL;

                        break;
                default:
                        return -EINVAL;
                }
        }

        return 0;
}
