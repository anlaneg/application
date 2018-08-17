/*
 * common.h
 *
 *  Created on: Aug 17, 2018
 *      Author: anlang
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>

/* Given ATTR, and TYPE, cast the ATTR to TYPE by first casting ATTR to
 * (void *). This is to suppress the alignment warning issued by clang. */
#define ALIGNED_CAST(TYPE, ATTR) ((TYPE) (void *) (ATTR))

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define OVS_NOT_REACHED() (*(int*)0=0)
#define COVERAGE_DEFINE(a)
#define NL_DUMP_BUFSIZE         4096
#define OVS_MUTEX_INITIALIZER { PTHREAD_MUTEX_INITIALIZER, "<unlocked>" }

#define VLOG_ERR(fmt,...)  printf(fmt,##__VA_ARGS__)
#define VLOG_WARN(fmt,...) printf(fmt,##__VA_ARGS__)
#define VLOG_DBG(fmt,...) printf(fmt,##__VA_ARGS__)
#define VLOG_INFO(fmt,...) printf(fmt,##__VA_ARGS__)

/* The ovs_be<N> types indicate that an object is in big-endian, not
 * native-endian, byte order.  They are otherwise equivalent to uint<N>_t. */
typedef uint16_t  ovs_be16;
typedef uint32_t  ovs_be32;
typedef uint64_t  ovs_be64;

/* A 64-bit value, in network byte order, that is only aligned on a 32-bit
 * boundary. */
typedef struct {
        ovs_be32 hi, lo;
} ovs_32aligned_be64;

struct ovs_mutex {
    pthread_mutex_t lock;
    const char *where;          /* NULL if and only if uninitialized. */
};

#undef WORDS_BIGENDIAN
/* Returns the value of 'x'. */
static inline ovs_be64
get_32aligned_be64(const ovs_32aligned_be64 *x)
{
#ifdef WORDS_BIGENDIAN
    return ((ovs_be64) x->hi << 32) | x->lo;
#else
    return ((ovs_be64) x->lo << 32) | x->hi;
#endif
}

//X/Y 后的按，如果有余数，则值加1
#define DIV_ROUND_UP(X, Y) (((X) + ((Y) - 1)) / (Y))

/* Returns X rounded up to the nearest multiple of Y. */
#define ROUND_UP(X, Y) (DIV_ROUND_UP(X, Y) * (Y))

/* Returns the least number that, when added to X, yields a multiple of Y. */
#define PAD_SIZE(X, Y) (ROUND_UP(X, Y) - (X))

/* The C standards say that neither the 'dst' nor 'src' argument to
 * memcpy() may be null, even if 'n' is zero.  This wrapper tolerates
 * the null case. */
static inline void
nullable_memcpy(void *dst, const void *src, size_t n)
{
    if (n) {
        memcpy(dst, src, n);
    }
}

/* The C standards say that the 'dst' argument to memset may not be
 * null, even if 'n' is zero.  This wrapper tolerates the null case. */
static inline void
nullable_memset(void *dst, int c, size_t n)
{
    if (n) {
        memset(dst, c, n);
    }
}


/* Returns the value of 'c' as a hexadecimal digit. */
static int
hexit_value(unsigned char c)
{
    static const signed char tbl[UCHAR_MAX + 1] = {
#define TBL(x)                                  \
        (  x >= '0' && x <= '9' ? x - '0'       \
         : x >= 'a' && x <= 'f' ? x - 'a' + 0xa \
         : x >= 'A' && x <= 'F' ? x - 'A' + 0xa \
         : -1)
#define TBL0(x)  TBL(x),  TBL((x) + 1),   TBL((x) + 2),   TBL((x) + 3)
#define TBL1(x) TBL0(x), TBL0((x) + 4),  TBL0((x) + 8),  TBL0((x) + 12)
#define TBL2(x) TBL1(x), TBL1((x) + 16), TBL1((x) + 32), TBL1((x) + 48)
        TBL2(0), TBL2(64), TBL2(128), TBL2(192)
    };

    return tbl[c];
}

/* Returns the integer value of the 'n' hexadecimal digits starting at 's', or
 * UINTMAX_MAX if one of those "digits" is not really a hex digit.  Sets '*ok'
 * to true if the conversion succeeds or to false if a non-hex digit is
 * detected. */
static inline uintmax_t
hexits_value(const char *s, size_t n, bool *ok)
{
    uintmax_t value;
    size_t i;

    value = 0;
    for (i = 0; i < n; i++) {
        int hexit = hexit_value(s[i]);
        if (hexit < 0) {
            *ok = false;
            return UINTMAX_MAX;
        }
        value = (value << 4) + hexit;
    }
    *ok = true;
    return value;
}

static inline struct in6_addr
in6_addr_mapped_ipv4(ovs_be32 ip4)
{
    struct in6_addr ip6;
    memset(&ip6, 0, sizeof(ip6));
    ip6.s6_addr[10] = 0xff, ip6.s6_addr[11] = 0xff;
    memcpy(&ip6.s6_addr[12], &ip4, 4);
    return ip6;
}

static inline void
in6_addr_set_mapped_ipv4(struct in6_addr *ip6, ovs_be32 ip4)
{
    *ip6 = in6_addr_mapped_ipv4(ip4);
}
#endif /* COMMON_H_ */
