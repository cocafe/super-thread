#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <float.h>

#if defined (__MSVCRT__) || defined (_MSC_VER)
#include <heapapi.h>
#endif

#include "logging.h"
#include "cJSON.h"
#include "utils.h"

//
// helpers
//

#if defined (__MSVCRT__) || defined (_MSC_VER)
static HANDLE hHeap;

void heap_init(void)
{
        hHeap = GetProcessHeap();
}

void *halloc(size_t sz)
{
        return HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sz);
}

void hfree(void *ptr)
{
        HeapFree(hHeap, 0, ptr);
}
#endif

// posix realloc() does not clear new area
void *realloc_safe(void *old_ptr, size_t old_sz, size_t new_sz)
{
        void *new_ptr;

        if (!old_ptr || !new_sz)
                return old_ptr;

        new_ptr = calloc(1, new_sz);
        if (!new_ptr)
                return NULL;

        if (new_sz >= old_sz)
                memcpy(new_ptr, old_ptr, old_sz);
        else
                memcpy(new_ptr, old_ptr, new_sz);

        free(old_ptr);

        return new_ptr;
}

int vprintf_resize(char **buf, size_t *pos, size_t *len, const char *fmt, va_list arg)
{
        va_list arg2;
        char cbuf;
        char *sbuf = *buf;
        int _len, ret;

        va_copy(arg2, arg);
        _len = vsnprintf(&cbuf, sizeof(cbuf), fmt, arg2);
        va_end(arg2);

        if (_len < 0)
                return _len;

        if (!sbuf) {
                size_t append_len = _len + 2;

                sbuf = calloc(append_len, sizeof(char));
                if (!sbuf)
                        return -ENOMEM;

                *buf = sbuf;
                *len = append_len;
                *pos = 0;
        } else {
                size_t append_len = _len + 2;
                size_t new_len = *len + append_len;

                // do realloc
                if (*pos + append_len > *len) {
                        sbuf = realloc_safe(*buf, *len, new_len);
                        if (!sbuf)
                                return -ENOMEM;

                        *buf = sbuf;
                        *len = new_len;
                }
        }

        sbuf = &((*buf)[*pos]);

        ret = vsnprintf(sbuf, *len - *pos, fmt, arg);
        if (ret < 0) {
                return ret;
        }

        *pos += ret;

        return ret;
}

int snprintf_resize(char **buf, size_t *pos, size_t *len, const char *fmt, ...)
{
        va_list ap;
        int ret;

        va_start(ap, fmt);
        ret = vprintf_resize(buf, pos, len, fmt, ap);
        va_end(ap);

        return ret;
}

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

#ifdef __MSVCRT__
int is_valid_ipaddr(char *ipstr, int ipver)
{
        UNUSED_PARAM(ipstr);
        UNUSED_PARAM(ipver);

        pr_err("not implemented on MSVC\n");

        return 0;
}
#else
int is_valid_ipaddr(char *ipstr, int ipver)
{
        unsigned char buf[sizeof(struct in6_addr)];

        return (inet_pton(ipver, ipstr, buf) == 1);
}
#endif

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
 * cJSON utils
 */

void json_traverse_do_print(cJSON *node)
{
        switch (node->type) {
        case cJSON_NULL:
                pr_color(FG_LT_RED, "[null]   ");
                break;
        case cJSON_Number:
                pr_color(FG_LT_MAGENTA, "[number] ");
                break;
        case cJSON_String:
                pr_color(FG_LT_GREEN, "[string] ");
                break;
        case cJSON_Array:
                pr_color(FG_LT_CYAN, "[array]  ");
                break;
        case cJSON_Object:
                pr_color(FG_LT_BLUE, "[object] ");
                break;
        case cJSON_Raw:
                pr_color(FG_LT_RED, "[raws]   ");
                break;
        case cJSON_True:
        case cJSON_False:
                pr_color(FG_YELLOW, "[bool]   ");
                break;
        }

        if (node->string)
                pr_color(FG_LT_YELLOW, "\"%s\" ", node->string);

        switch (node->type) {
        case cJSON_False:
                pr_color(FG_RED, ": false");
                break;
        case cJSON_True:
                pr_color(FG_GREEN, ": true");
                break;
        case cJSON_Number:
                pr_color(FG_LT_CYAN, ": %.f", cJSON_GetNumberValue(node));
                break;
        case cJSON_String:
                pr_color(FG_LT_CYAN, ": \"%s\"", cJSON_GetStringValue(node));
                break;
        }

        pr_color(FG_LT_WHITE, "\n");
}

void json_traverse_print(cJSON *node, uint32_t depth)
{
        static char padding[32] = { [0 ... 31] = '\t' };
        cJSON *child = NULL;

        if (!node)
                return;

        pr_color(FG_LT_WHITE, "%.*s", depth, padding);
        json_traverse_do_print(node);

        // child = root->child
        cJSON_ArrayForEach(child, node) {
                json_traverse_print(child, depth + 1);
        }
}

int json_print(const char *json_path)
{
        cJSON *root_node;
        char *text;
        int err = 0;

        if (!json_path)
                return -EINVAL;

        if (json_path[0] == '\0') {
                pr_err("@path is empty\n");
                return -ENODATA;
        }

        text = file_read(json_path);
        if (!text) {
                pr_err("failed to read file: %s\n", json_path);
                return -EIO;
        }

        root_node = cJSON_Parse(text);
        if (!root_node) {
                pr_err("cJSON failed to parse text\n");
                err = -EINVAL;

                goto free_text;
        }

        json_traverse_print(root_node, 0);

        cJSON_Delete(root_node);

free_text:
        free(text);

        return err;
}


/**
 * iconv utils
 */

#ifdef ICONV_UTILS

#include <iconv.h>

int iconv_locale_ok = 0;

#ifdef __WINNT__
#include <winnls.h>

char locale_cp[64] = { 0 };

int iconv_winnt_locale_init(void)
{
        iconv_t t;

        snprintf(locale_cp, sizeof(locale_cp), "CP%u", GetACP());

        t = iconv_open(ICONV_UTF8, locale_cp);
        if (t == (iconv_t)-1) {
                pr_err("iconv does not support %s->%s\n", locale_cp, ICONV_UTF8);
                iconv_locale_ok = 0;
        } else {
                iconv_locale_ok = 1;
                iconv_close(t);
        }

        return 0;
}

int iconv_locale_to_utf8(char *in, size_t in_bytes, char *out, size_t out_bytes)
{
        if (iconv_locale_ok)
                return iconv_convert(in, in_bytes, locale_cp, ICONV_UTF8, out, out_bytes);

        return -EINVAL;
}

char *iconv_locale_cp(void)
{
        if (iconv_locale_ok)
                return locale_cp;

        return NULL;
}

#endif

/**
 * @param in: should be (char *) or (wchar_t *)
 * @param in_bytes: input bytes, not the string char count (length)
 * @param in_encode: iconv code page name, e.g "utf8", "gb2312"
 * @param out_encode: iconv code page name
 * @param out: can be (char *) or (wchar_t *)
 * @param out_bytes: bytes that [out] can hold, recommended to allocate more
 *                   bytes than [in_bytes] for [out].
 *                   note that, some encodings (e.g. utf-8) may require more
 *                   spaces than utf-16 to represent some chars (e.g CJK chars),
 *                   allocate double space of wchar length for utf-8 if not sure.
 * @return 0 on success
 */
int iconv_convert(void *in, size_t in_bytes, const char *in_encode, const char *out_encode, void *out, size_t out_bytes)
{
        iconv_t cd;

        if (!in || !in_encode || !out_encode || !out || !in_bytes || !out_bytes)
                return -EINVAL;

        cd = iconv_open(out_encode, in_encode);
        if (cd == (iconv_t)-1) {
                if (errno == EINVAL)
                        pr_err("iconv does not support %s->%s\n", in_encode, out_encode);
                else
                        pr_err("iconv_open() failed, err = %d\n", errno);

                return -errno;
        }

        iconv(cd, (char **)&in, &in_bytes, (char **)&out, &out_bytes);

        if (iconv_close(cd) != 0)
                pr_err("iconv_close() failed\n");

        return 0;
}

int iconv_strncmp(char *s1, char *c1, size_t l1, char *s2, char *c2, size_t l2, int *err)
{
        char *b1 = NULL;
        char *b2 = NULL;
        int ret = -EINVAL;
        int __err = 0;
        const int extra = 32;

        if (!s1 || !c1 || !s2 || !c2)
                return -EINVAL;

        if (strcasecmp(c1, ICONV_UTF8)) {
                b1 = calloc(l1 + extra, sizeof(char));
                if (!b1) {
                        __err = -ENOMEM;
                        goto out;
                }

                __err = iconv_convert(s1, l1, c1, ICONV_UTF8, b1, l1 + extra);
                if (__err)
                        goto out;

                s1 = b1;
                l1 += extra;
        }

        if (strcasecmp(c2, ICONV_UTF8)) {
                b2 = calloc(l2 + extra, sizeof(char));
                if (!b2) {
                        __err = -ENOMEM;
                        goto out;
                }

                __err = iconv_convert(s2, l2, c2, ICONV_UTF8, b2, l2 + extra);
                if (__err)
                        goto out;

                s2 = b2;
                l2 += extra;
        }

        ret = strncmp(s1, s2, (l1 > l2) ? l1 : l2);

out:
        if (b1)
                free(b1);

        if (b2)
                free(b2);

        if (err)
                *err = __err;

        return ret;
}

#endif // ICONV_UTILS