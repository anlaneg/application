/*
 * private.h
 *
 *  Created on: Aug 24, 2018
 *      Author: anlang
 */

#ifndef PRIVATE_H_
#define PRIVATE_H_

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

#define MAX(a,b) (((a)>(b))?(a):(b))
#define OVS_NOT_REACHED() (*(int*)0=0)
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

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
static inline int
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

#endif /* PRIVATE_H_ */
