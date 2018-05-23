#include "tools/timestamp.h"

/*-------------------------------------------------------------------------
 *
 * This function has been adapted from the timestamp2tm function found in
 * src/backend/utils/adt/timestamp.c of the PostgreSQL source, a file
 * for which:
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */

int year_from_timestamp(int64_t timestamp)
{

    int64_t date;
    unsigned int quad;
    unsigned int extra;
    int year;

    TMODULO(timestamp, date, USECS_PER_DAY);
    if (timestamp < INT64CONST(0))
    {
        timestamp += USECS_PER_DAY;
        date -= 1;
    }

    /* add offset to go from J2000 back to standard Julian date */
    date += POSTGRES_EPOCH_JDATE;

    /* Julian day routine does not work for negative Julian days */
    if (date < 0 || date > (int64_t)INT_MAX)
        return -1;

    date += 32044;
    quad = date / 146097;
    extra = (date - quad * 146097) * 4 + 3;

    date += 60 + quad * 3 + extra / 146097;
    quad = date / 1461;
    date -= quad * 1461;

    year = date * 4 / 1461;
    year += quad * 4;
    return year - 4800;
}
