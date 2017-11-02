#include "stdafx.h"

PGDLLEXPORT Datum enctimestampin(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestampout(PG_FUNCTION_ARGS);

PGDLLEXPORT Datum enctimestamp_enc(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_dec(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_eq(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_ne(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_lt(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_le(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_gt(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_ge(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_cmp(PG_FUNCTION_ARGS);

/*PGDLLEXPORT Datum enctimestamp_add(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_subs(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_mult(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_mod(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_div(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_exp(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_addfinal(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum enctimestamp_avgfinal(PG_FUNCTION_ARGS);
*/
