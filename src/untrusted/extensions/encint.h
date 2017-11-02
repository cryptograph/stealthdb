#include "stdafx.h"

// the structure is used to describe an element of the encint type 

PGDLLEXPORT Datum encint_in(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_out(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_eq(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_ne(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_lt(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_le(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_gt(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_ge(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_addfinal(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_avgfinal(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_minfinal(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_maxfinal(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_enc(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encint_dec(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum int4_to_encint(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum int8_to_encint(PG_FUNCTION_ARGS);
