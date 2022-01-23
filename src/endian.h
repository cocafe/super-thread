#ifndef __JJ_ENDIAN_H__
#define __JJ_ENDIAN_H__

#include <stdint.h>

// #include <endian.h>
// endian.h is not portable, only available on linux
// it defines htobeXX/htoleXX macros, may conflict

#define byteswap16(val) \
 ( (((val) >> 8) & 0x00FF) | (((val) << 8) & 0xFF00) )

#define byteswap32(val) \
 ( (((val) >> 24) & 0x000000FF) | (((val) >>  8) & 0x0000FF00) | \
   (((val) <<  8) & 0x00FF0000) | (((val) << 24) & 0xFF000000) )

#define byteswap64(val) \
 ( (((val) >> 56) & 0x00000000000000FFULL) | (((val) >> 40) & 0x000000000000FF00ULL) | \
   (((val) >> 24) & 0x0000000000FF0000ULL) | (((val) >>  8) & 0x00000000FF000000ULL) | \
   (((val) <<  8) & 0x000000FF00000000ULL) | (((val) << 24) & 0x0000FF0000000000ULL) | \
   (((val) << 40) & 0x00FF000000000000ULL) | (((val) << 56) & 0xFF00000000000000ULL) )

// alternative name
#define betole16 byteswap16
#define betole32 byteswap32
#define betole64 byteswap64
#define letobe16 byteswap16
#define letobe32 byteswap32
#define letobe64 byteswap64

#if !defined (_ENDIAN_H) && !defined (_ENDIAN_H_)
#if defined (__GNUC__) || defined (__clang__)
#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define htobe16(val) (val)
                        #define htobe32(val) (val)
                        #define htobe64(val) (val)
                        #define htole16(val) byteswap16((val))
                        #define htole32(val) byteswap32((val))
                        #define htole64(val) byteswap64((val))
                        #define be16toh(val) (val)
                        #define be32toh(val) (val)
                        #define be64toh(val) (val)
                        #define le16toh(val) byteswap16((val))
                        #define le32toh(val) byteswap32((val))
                        #define le64toh(val) byteswap64((val))
#else /* __ORDER_LITTLE_ENDIAN__ */
#define htobe16(val) byteswap16((val))
#define htobe32(val) byteswap32((val))
#define htobe64(val) byteswap64((val))
#define htole16(val) (val)
#define htole32(val) (val)
#define htole64(val) (val)
#define be16toh(val) byteswap16((val))
#define be32toh(val) byteswap32((val))
#define be64toh(val) byteswap64((val))
#define le16toh(val) (val)
#define le32toh(val) (val)
#define le64toh(val) (val)
#endif /* __BYTE_ORDER__ */
#endif /* __GNUC__ || __clang__ */
#endif /* _ENDIAN_H_ */

#ifdef _MSC_VER
#include <Windows.h>
// in winnt.h
        #if (REG_DWORD == REG_DWORD_BIG_ENDIAN)
                #define htobe16(val) (val)
                #define htobe32(val) (val)
                #define htobe64(val) (val)
                #define htole16(val) byteswap16((val))
                #define htole32(val) byteswap32((val))
                #define htole64(val) byteswap64((val))
                #define be16toh(val) (val)
                #define be32toh(val) (val)
                #define be64toh(val) (val)
                #define le16toh(val) byteswap16((val))
                #define le32toh(val) byteswap32((val))
                #define le64toh(val) byteswap64((val))
        #else /* REG_DWORD_LITTLE_ENDIAN */
                #define htobe16(val) byteswap16((val))
                #define htobe32(val) byteswap32((val))
                #define htobe64(val) byteswap64((val))
                #define htole16(val) (val)
                #define htole32(val) (val)
                #define htole64(val) (val)
                #define be16toh(val) byteswap16((val))
                #define be32toh(val) byteswap32((val))
                #define be64toh(val) byteswap64((val))
                #define le16toh(val) (val)
                #define le32toh(val) (val)
                #define le64toh(val) (val)
        #endif /* REG_DWORD */
#endif /* _MSC_VER */

#if defined (__GNUC__) || defined (__clang__)
static inline void int128_swap(__uint128_t *val)
{
        uint64_t *u64_seg = (uint64_t *)val;
        uint64_t t;

        u64_seg[0] = be64toh(u64_seg[0]);
        u64_seg[1] = be64toh(u64_seg[1]);
        t = u64_seg[0];
        u64_seg[0] = u64_seg[1];
        u64_seg[1] = t;
}

static inline void be128toh(__uint128_t *val)
{
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
        int128_swap(val);
#else
        (void)val;
#endif
}

static inline void le128toh(__uint128_t *val)
{
#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        int128_swap(val);
#else
        (void)val;
#endif
}

#define hto128be        be128toh
#define hto128le        le128toh
#endif /* __GNUC__ || __clang__ */

#endif //__JJ_ENDIAN_H__
