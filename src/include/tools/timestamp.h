#pragma once
#include <limits.h>
#include <stdint.h>

/* TMODULO()
 * Implements modf() in <math.h> for the timestamp (aka int64) datatype.
 * We assume that int64 follows the C99 semantics for division (negative
 * quotients truncate towards zero).
*/
#define TMODULO(t,q,u) \
do { \
    (q) = ((t) / (u)); \
    if ((q) != 0) (t) -= ((q) * (u)); \
} while(0)

#define INT64CONST(x) (x##L)
#define USECS_PER_DAY INT64CONST(86400000000)
#define POSTGRES_EPOCH_JDATE 2451545

#ifdef __cplusplus
extern "C" {
#endif

int year_from_timestamp(int64_t timestamp);
#ifdef __cplusplus
}
#endif
