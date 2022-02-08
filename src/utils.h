#ifndef __JJ_UTILS_H__
#define __JJ_UTILS_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h>
#include <float.h>
#include <string.h>

#include <sys/types.h>

#include "cJSON.h"

//
// endian magic
//
#ifndef _ENDIAN_H_
#ifdef __WINNT__
#include "endian.h"
#endif // __WINNT__
#endif // _ENDIAN_H_

//
// macro magic
//

#define MACRO_STR_EXPAND(mm)    #mm
// do not put () on @m which should be a macro
#define MACRO_TO_STR(m)         MACRO_STR_EXPAND(m)

//
// compiler magic
//

#if !defined(ARRAY_SIZE)
#define ARRAY_SIZE(x)           (sizeof(x) / sizeof((x)[0]))
#endif

#if !defined(__always_inline)
#define __always_inline         inline __attribute__((always_inline))
#endif

#if !defined(__unused)
#define __unused                __attribute__((unused))
#endif

#if !defined(UNUSED_PARAM)
#define UNUSED_PARAM(x)         (void)(x)
#endif

#if !defined(likely)
#define likely(x)               __builtin_expect(!!(x), 1)
#endif

#if !defined(unlikely)
#define unlikely(x)             __builtin_expect(!!(x), 0)
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({                      \
                const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
                (type *)( (char *)__mptr - offsetof(type,member) );})

//
// bit magic
//

#ifdef __GNUC__
#ifndef BITS_PER_LONG
#define BITS_PER_LONG           (__LONG_WIDTH__)
#endif
#define BITS_PER_LONG_LONG      (__LONG_LONG_WIDTH__)
#endif /* __GNUC__ */

#ifdef __clang__
#ifndef BITS_PER_LONG
#define BITS_PER_LONG           (__SIZEOF_LONG__ * __CHAR_BIT__)
#endif
#ifndef BITS_PER_LONG_LONG_
#define BITS_PER_LONG_LONG      (__SIZEOF_LONG_LONG__ * __CHAR_BIT__)
#endif
#endif /* __clang__ */

#define BIT(nr)                 (1UL << (nr))
#define BIT_ULL(nr)             (1ULL << (nr))
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)        (1ULL << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)        ((nr) / BITS_PER_LONG_LONG)
#define BITS_PER_BYTE           8
#define SIZE_TO_BITS(x)         (sizeof(x) * BITS_PER_BYTE)

/*
 * Create a contiguous bitmask starting at bit position @l and ending at
 * position @h. For example
 * GENMASK_ULL(39, 21) gives us the 64bit vector 0x000000ffffe00000.
 */
#define GENMASK(h, l) \
        (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

#define GENMASK_ULL(h, l) \
        (((~0ULL) - (1ULL << (l)) + 1) & \
         (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))

#define BITS_MASK               GENMASK
#define BITS_MASK_ULL           GENMASK_ULL

//
// helpers
//

#define IPV6_STRLEN_MAX         (4 * 8 + 7 + 1 + 4)
#define IPV4_STRLEN_MAX         (3 * 4 + 3 + 1 + 4)

#define is_strptr_not_set(s)    ((s) == NULL || (s)[0] == '\0')
#define is_strptr_set(s)        (!is_strptr_not_set((s)))

#ifndef __min
#define __min(a, b)                             \
        ({                                      \
                __typeof__((a)) _a = (a);       \
                __typeof__((b)) _b = (b);       \
                _a < _b ? _a : _b;              \
        })
#endif /* __min */

#ifndef __max
#define __max(a, b)                             \
        ({                                      \
                __typeof__((a)) _a = (a);       \
                __typeof__((b)) _b = (b);       \
                _a > _b ? _a : _b;              \
        })
#endif /* __max */

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define INET_ADDR_SIZE          (sizeof(struct in6_addr))

#define WCBUF_LEN               ARRAY_SIZE

int pthread_mutex_multi_trylock(pthread_mutex_t *lock);
int float_equal(float a, float b, float epsilon);
int is_valid_ipaddr(char *ipstr, int ipver);
char *file_read(const char *path);
int file_write(const char *path, const void *data, size_t sz);
int __str_cat(char *dest, size_t dest_sz, char *src);
char *__str_ncpy(char *dest, const char *src, size_t dest_sz);
int bin_snprintf(char *str, size_t slen, uint64_t val, size_t vsize);

static inline int is_str_equal(char *a, char *b, int caseless)
{
        const int EQUAL = 1;
        const int NOT_EQUAL = 0;

        size_t len_a;
        size_t len_b;

        if (!a || !b)
                return NOT_EQUAL;

        if (unlikely(a == b))
                return EQUAL;

        len_a = strlen(a);
        len_b = strlen(b);

        if (len_a != len_b)
                return NOT_EQUAL;

        if (caseless) {
                if (!strncasecmp(a, b, len_a))
                        return EQUAL;

                return NOT_EQUAL;
        }

        if (!strncmp(a, b, len_a))
                return EQUAL;

        return NOT_EQUAL;
}

static inline int is_wstr_equal(wchar_t *a, wchar_t *b)
{
        const int EQUAL = 1;
        const int NOT_EQUAL = 0;
        size_t len_a;
        size_t len_b;

        if (!a || !b)
                return NOT_EQUAL;

        if (unlikely(a == b))
                return EQUAL;

        len_a = wcslen(a);
        len_b = wcslen(b);

        if (len_a != len_b)
                return NOT_EQUAL;

        if (!wcsncmp(a, b, len_a))
                return EQUAL;

        return NOT_EQUAL;
}

static inline int ptr_word_write(void *data, size_t word_sz, int64_t val)
{
        switch (word_sz) {
        case 1:
                *(int8_t *)data = (int8_t)val;
                break;

        case 2:
                *(int16_t *)data = (int16_t)val;
                break;

        case 4:
                *(int32_t *)data = (int32_t)val;
                break;

        case 8:
                *(int64_t *)data = val;
                break;

        default:
                return -EINVAL;
        }

        return 0;
}

static inline int ptr_unsigned_word_read(void *data, size_t word_sz, uint64_t *val)
{
        switch (word_sz) {
        case 1:
                *val = *(uint8_t *)data;
                break;

        case 2:
                *val = *(uint16_t *)data;
                break;

        case 4:
                *val = *(uint32_t *)data;
                break;

        case 8:
                *val = *(uint64_t *)data;
                break;

        default:
                return -EINVAL;
        }

        return 0;
}

// perform arithmetic extend
static inline int ptr_signed_word_read(void *data, size_t word_sz, int64_t *val)
{
        switch (word_sz) {
        case 1:
                *val = *(int8_t *)data;
                break;

        case 2:
                *val = *(int16_t *)data;
                break;

        case 4:
                *val = *(int32_t *)data;
                break;

        case 8:
                *val = *(int64_t *)data;
                break;

        default:
                return -EINVAL;
        }

        return 0;
}

//
// internal buffer
//

typedef struct {
        // locking?

        char    *s;             // points to where valid buffer starts.
        char    *e;             // 1. points to where next char to put,
                                //    not where valid string ends.
                                // 2. when it points outta (size - 1),
                                //    buffer is full

        size_t  size;           // size that user want
        size_t  __size;         // actually allocated buffer size
        char    *__s;           // constant: &__data[0]
        char    *__e;           // constant: &__data[size - 1]
        char    *__data;        // raw buffer
} buf_t;

int buf_init(buf_t *buf, size_t sz);
int buf_deinit(buf_t *buf);
void buf_reset(buf_t *buf);
int buf_put(buf_t *buf, const char *in, size_t len);
int buf_forward_discard(buf_t *buf, size_t len);
int buf_backward_discard(buf_t *buf, size_t len);

static __always_inline size_t buf_length(buf_t *buf)
{
        return (size_t)buf->e - (size_t)buf->s;
}

static __always_inline int buf_is_full(buf_t *buf)
{
        return (buf->e > buf->__e);
}

static __always_inline int buf_is_empty(buf_t *buf)
{
        return !buf_is_full(buf) && (buf->e == buf->s);
}

static __always_inline char *buf_get(buf_t *buf)
{
        return buf->s;
}

//
// json
//

int json_print(const char *json_path);
void json_traverse_print(cJSON *node, uint32_t depth);

//
// MSVC heap
//
#if defined (__MSVCRT__) || defined (_MSC_VER)
void heap_init(void);
void *halloc(size_t sz);
void hfree(void *ptr);
#else
static inline void heap_init(void) { };
static inline void *halloc(size_t sz) { return malloc(sz); };
static inline void hfree(void *ptr) { free(ptr); };
#endif

void *realloc_safe(void *old_ptr, size_t old_sz, size_t new_sz);

int vprintf_resize(char **buf, size_t *pos, size_t *len, const char *fmt, va_list arg);
int snprintf_resize(char **buf, size_t *pos, size_t *len, const char *fmt, ...);

//
// iconv utils
//

#define ICONV_UTILS

#ifdef ICONV_UTILS

#include <iconv.h>

#define ICONV_UTF8              "UTF-8"
#define ICONV_CP936             "CP936"
#define ICONV_WCHAR             "UTF-16LE"

#ifdef __WINNT__
#define ICONV_WIN_WCHAR         "UTF-16LE"

#ifdef ICONV_WCHAR
#undef ICONV_WCHAR
#define ICONV_WCHAR             ICONV_WIN_WCHAR
#endif
extern int iconv_locale_ok;

char *iconv_locale_cp(void);
int iconv_winnt_locale_init(void);
int iconv_locale_to_utf8(char *in, size_t in_bytes, char *out, size_t out_bytes);
#endif // __WINNT__

int iconv_convert(void *in, size_t in_bytes, const char *in_encode, const char *out_encode, void *out, size_t out_bytes);
int iconv_strncmp(char *s1, char *c1, size_t l1, char *s2, char *c2, size_t l2, int *err);

// NOTE:
//      utf-8 may need more spaces to represent same char than wchar_t (utf-16),
//      recommended allocating double of char length for utf-8 spaces
static inline int iconv_wc2utf8(wchar_t *in, size_t in_bytes, char *out, size_t out_bytes)
{
        return iconv_convert(in, in_bytes, ICONV_WCHAR, ICONV_UTF8, out, out_bytes);
}

static inline int iconv_utf82wc(char *in, size_t in_bytes, wchar_t *out, size_t out_bytes)
{
        return iconv_convert(in, in_bytes, ICONV_UTF8, ICONV_WCHAR, out, out_bytes);
}

#endif // ICONV_UTILS

//
// bit-map helpers
//

#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG && (nbits) > 0)

/**
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static __always_inline unsigned long __ffs(unsigned long word)
{
        int num = 0;

#if BITS_PER_LONG == 64
        if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
#endif
        if ((word & 0xffff) == 0) {
                num += 16;
                word >>= 16;
        }
        if ((word & 0xff) == 0) {
                num += 8;
                word >>= 8;
        }
        if ((word & 0xf) == 0) {
                num += 4;
                word >>= 4;
        }
        if ((word & 0x3) == 0) {
                num += 2;
                word >>= 2;
        }
        if ((word & 0x1) == 0)
                num += 1;
        return num;
}

/*
 * Find the first set bit in a memory region.
 */
static inline unsigned long _find_first_bit(const unsigned long *addr, unsigned long bits)
{
        unsigned long idx;

        for (idx = 0; idx * BITS_PER_LONG < bits; idx++) {
                if (addr[idx])
                        return min(idx * BITS_PER_LONG + __ffs(addr[idx]), bits);
        }

        return bits;
}

/**
 * find_first_bit - find the first set bit in a memory region
 * @addr: The address to start the search at
 * @bits: The maximum number of bits to search
 *
 * @return the bit number of the first set bit.
 * If no bits are set, returns @size.
 */
static inline unsigned long find_first_bit(const unsigned long *addr, unsigned long bits)
{
        if (small_const_nbits(bits)) {
                unsigned long val = *addr & GENMASK(bits - 1, 0);

                return val ? __ffs(val) : bits;
        }

        return _find_first_bit(addr, bits);
}

/*
 * ffz - find first zero in word.
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
#define ffz(x)  __ffs(~(x))

/*
 * Find the first cleared bit in a memory region.
 */
static inline unsigned long _find_first_zero_bit(const unsigned long *addr, unsigned long bits)
{
        unsigned long idx;

        for (idx = 0; idx * BITS_PER_LONG < bits; idx++) {
                if (addr[idx] != ~0UL)
                        return min(idx * BITS_PER_LONG + ffz(addr[idx]), bits);
        }

        return bits;
}

/**
 * find_first_zero_bit - find the first cleared bit in a memory region
 * @addr: The address to start the search at
 * @bits: The maximum number of bits to search
 *
 * @return the bit number of the first cleared bit.
 * If no bits are zero, returns @size.
 */
static inline unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long bits)
{
        if (small_const_nbits(bits)) {
                unsigned long val = *addr | ~GENMASK(bits - 1, 0);

                return val == ~0UL ? bits : ffz(val);
        }

        return _find_first_zero_bit(addr, bits);
}

#if BITS_PER_LONG == 32
static inline unsigned long find_first_bit_u64(const uint64_t *addr)
{
#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        struct {
                uint32_t hi;
                uint32_t lo;
        } *u64_rep = (void *)addr;
#else /* __ORDER_LITTLE_ENDIAN__ */
        struct {
                uint32_t lo;
                uint32_t hi;
        } *u64_rep = (void *)addr;
#endif

        unsigned long ret;

        ret = find_first_bit((void *)&u64_rep->lo, SIZE_TO_BITS(uint32_t));
        if (ret == 32)
                ret += find_first_bit((void *)&u64_rep->hi, SIZE_TO_BITS(uint32_t));

        return ret;
}

static inline unsigned long find_first_zero_bit_u64(const uint64_t *addr)
{
#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        struct {
                uint32_t hi;
                uint32_t lo;
        } *u64_rep = (void *)addr;
#else /* __ORDER_LITTLE_ENDIAN__ */
        struct {
                uint32_t lo;
                uint32_t hi;
        } *u64_rep = (void *)addr;
#endif

        unsigned long ret;

        ret = find_first_zero_bit((void *)&u64_rep->lo, SIZE_TO_BITS(uint32_t));
        if (ret == 32)
                ret += find_first_zero_bit((void *)&u64_rep->hi, SIZE_TO_BITS(uint32_t));

        return ret;
}
#else
#define find_first_bit_u64 find_first_bit
#define find_first_zero_bit_u64 find_first_zero_bit
#endif // BITS_PER_LONG == 32

#endif //__JJ_UTILS_H__