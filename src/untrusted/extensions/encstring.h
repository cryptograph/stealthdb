#include "stdafx.h"

// List of all functions for the extension
PGDLLEXPORT Datum encstring_in(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_out(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum text_to_encstring(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_to_text(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_eq(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_ne(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_lt(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_le(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_gt(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_ge(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_cmp(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_concat(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_like(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_enc(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum encstring_dec(PG_FUNCTION_ARGS);
