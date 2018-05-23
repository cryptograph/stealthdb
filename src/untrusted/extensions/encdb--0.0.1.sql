-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION encdb" to load this file. \quit

CREATE FUNCTION launch() RETURNS integer
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION generate_key()
RETURNS int
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION load_key(int)
RETURNS int
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION enable_debug_mode(int)
RETURNS int
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

-------------------------------------------------------------------------------
--ENCRYPTED INTEGER TYPE (randomized)
-------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION pg_enc_int4_in(cstring)
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_enc_int4_out(enc_int4)
RETURNS cstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_eq(enc_int4, enc_int4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_ne(enc_int4, enc_int4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_lt(enc_int4, enc_int4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_le(enc_int4, enc_int4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_gt(enc_int4, enc_int4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_ge(enc_int4, enc_int4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_encrypt(integer)
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_decrypt(enc_int4)
RETURNS integer
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_enc_int4_add(enc_int4, enc_int4)
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_enc_int4_sub(enc_int4, enc_int4)
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_enc_int4_mult(enc_int4, enc_int4)
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_enc_int4_div(enc_int4, enc_int4)
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_enc_int4_mod(enc_int4, enc_int4)
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_enc_int4_pow(enc_int4, enc_int4)
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_enc_int4_cmp(enc_int4, enc_int4)
RETURNS integer
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

--CREATE OR REPLACE FUNCTION pg_enc_int4_recv(internal)
--RETURNS enc_int4
--AS '$libdir/encdb'
--LANGUAGE C IMMUTABLE STRICT;

--CREATE OR REPLACE FUNCTION pg_enc_int4_send(enc_int4)
--RETURNS bytea
--AS '$libdir/encdb'
--LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE enc_int4 (
    INPUT          = pg_enc_int4_in,
    OUTPUT         = pg_enc_int4_out,
--    RECEIVE        = pg_enc_int4_recv,
--    SEND           = pg_enc_int4_send,
    INTERNALLENGTH = 45,
    ALIGNMENT      = int4,
    STORAGE        = PLAIN
);
COMMENT ON TYPE enc_int4 IS 'ENCRYPTED INTEGER';

CREATE FUNCTION pg_enc_int4_addfinal(enc_int4[])
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_sum_bulk(enc_int4[])
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_avgfinal(enc_int4[])
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_avg_bulk(enc_int4[])
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_minfinal(enc_int4[])
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_min_bulk(enc_int4[])
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_maxfinal(enc_int4[])
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_int4_max_bulk(enc_int4[])
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OPERATOR = (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_eq,
  COMMUTATOR = '=',
  NEGATOR = '<>',
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES, MERGES
);

CREATE OPERATOR <> (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_ne,
  COMMUTATOR = '<>',
  NEGATOR = '=',
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);
CREATE OPERATOR < (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_lt,
  COMMUTATOR = > ,
  NEGATOR = >= ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_le,
  COMMUTATOR = >= ,
  NEGATOR = > ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_gt,
  COMMUTATOR = < ,
  NEGATOR = <= ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_ge,
  COMMUTATOR = <= ,
  NEGATOR = < ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE AGGREGATE sum (enc_int4)
(
   sfunc = array_append,
   stype = enc_int4[],
   finalfunc = pg_enc_int4_sum_bulk
);

CREATE AGGREGATE sum_simple (enc_int4)
(
   sfunc = array_append,
   stype = enc_int4[],
   finalfunc = pg_enc_int4_addfinal
);

CREATE AGGREGATE avg (enc_int4)
(
   sfunc = array_append,
   stype = enc_int4[],
   finalfunc = pg_enc_int4_avg_bulk

);

CREATE AGGREGATE avg_simple (enc_int4)
(
   sfunc = array_append,
   stype = enc_int4[],
   finalfunc = pg_enc_int4_avgfinal

);

CREATE AGGREGATE min (enc_int4)
(
   sfunc = array_append,
   stype = enc_int4[],
   finalfunc = pg_enc_int4_min_bulk
);

CREATE AGGREGATE min_simple (enc_int4)
(
   sfunc = array_append,
   stype = enc_int4[],
   finalfunc = pg_enc_int4_minfinal
);

CREATE AGGREGATE max (enc_int4)
(
   sfunc = array_append,
   stype = enc_int4[],
   finalfunc = pg_enc_int4_max_bulk
);

CREATE AGGREGATE max_simple (enc_int4)
(
   sfunc = array_append,
   stype = enc_int4[],
   finalfunc = pg_enc_int4_maxfinal
);

CREATE OPERATOR + (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_add
);


CREATE OPERATOR - (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_sub
);

CREATE OPERATOR * (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_mult
);

CREATE OPERATOR / (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_div
);

CREATE OPERATOR % (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_mod
);

CREATE OPERATOR ^ (
  LEFTARG = enc_int4,
  RIGHTARG = enc_int4,
  PROCEDURE = pg_enc_int4_pow
);


CREATE OPERATOR CLASS btree_pg_enc_int4_ops
DEFAULT FOR TYPE enc_int4 USING btree
AS
        OPERATOR        1       <  ,
        OPERATOR        2       <= ,
        OPERATOR        3       =  ,
        OPERATOR        4       >= ,
        OPERATOR        5       >  ,
        FUNCTION        1       pg_enc_int4_cmp(enc_int4, enc_int4);

CREATE OR REPLACE FUNCTION enc_int4(int4)
    RETURNS enc_int4
    AS '$libdir/encdb', 'pg_int4_to_enc_int4'
    LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION enc_int4(int8)
    RETURNS enc_int4
    AS '$libdir/encdb', 'pg_int8_to_enc_int4'
    LANGUAGE C STRICT IMMUTABLE;

CREATE CAST (int4 AS enc_int4) WITH FUNCTION enc_int4(int4) AS ASSIGNMENT;
CREATE CAST (int8 AS enc_int4) WITH FUNCTION enc_int4(int8) AS ASSIGNMENT;

--------------------------------------------------------------------------------
--ENCRYPTED STRING TYPE (randomized)
--------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION pg_enc_text_in(cstring)
RETURNS enc_text
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_enc_text_out(enc_text)
RETURNS cstring
--LANGUAGE internal IMMUTABLE AS 'textout';
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_eq(enc_text, enc_text)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_ne(enc_text, enc_text)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_lt(enc_text, enc_text)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_le(enc_text, enc_text)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_gt(enc_text, enc_text)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_ge(enc_text, enc_text)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_cmp(enc_text, enc_text)
RETURNS integer
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_concatenate(enc_text, enc_text)
RETURNS enc_text
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_catalog.substring(enc_text, enc_int4, enc_int4)
RETURNS enc_text
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_like(enc_text, enc_text)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_notlike(enc_text, enc_text)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

--CREATE FUNCTION pg_enc_text_mult(enc_text, enc_text)
--RETURNS enc_text
--AS '$libdir/encdb'
--LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_encrypt(cstring)
RETURNS enc_text
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_text_decrypt(enc_text)
RETURNS cstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;


--CREATE OR REPLACE FUNCTION pg_enc_text_recv(internal)
--RETURNS enc_text
--AS '$libdir/encdb'
--LANGUAGE C IMMUTABLE STRICT;

--CREATE OR REPLACE FUNCTION pg_enc_text_send(enc_text)
--RETURNS bytea
--AS '$libdir/encdb'
--LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE enc_text (
    INPUT          = pg_enc_text_in,
    OUTPUT         = pg_enc_text_out,
--    RECEIVE        = pg_enc_text_recv,
--    SEND         = pg_enc_text_send,
--      LIKE       = text,
    INTERNALLENGTH = 1024,
--    CATEGORY = 'S',
--    PREFERRED = false
    ALIGNMENT      = int4,
    STORAGE        = PLAIN
);
COMMENT ON TYPE enc_text IS 'ENCRYPTED STRING';

CREATE OPERATOR = (
  LEFTARG = enc_text,
  RIGHTARG = enc_text,
  PROCEDURE = pg_enc_text_eq,
  COMMUTATOR = '=',
  NEGATOR = '<>',
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES, MERGES
);

CREATE OPERATOR <> (
  LEFTARG = enc_text,
  RIGHTARG = enc_text,
  PROCEDURE = pg_enc_text_ne,
  COMMUTATOR = '<>',
  NEGATOR = '=',
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);
CREATE OPERATOR < (
  LEFTARG = enc_text,
  RIGHTARG = enc_text,
  PROCEDURE = pg_enc_text_lt,
  COMMUTATOR = > ,
  NEGATOR = >= ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  LEFTARG = enc_text,
  RIGHTARG = enc_text,
  PROCEDURE = pg_enc_text_le,
  COMMUTATOR = >= ,
  NEGATOR = > ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
  LEFTARG = enc_text,
  RIGHTARG = enc_text,
  PROCEDURE = pg_enc_text_gt,
  COMMUTATOR = < ,
  NEGATOR = <= ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  LEFTARG = enc_text,
  RIGHTARG = enc_text,
  PROCEDURE = pg_enc_text_ge,
  COMMUTATOR = <= ,
  NEGATOR = < ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR || (
  LEFTARG = enc_text,
  RIGHTARG = enc_text,
  PROCEDURE = pg_enc_text_concatenate
);

CREATE OPERATOR ~~ (
  LEFTARG = enc_text,
  RIGHTARG = enc_text,
  PROCEDURE = pg_enc_text_like
);

CREATE OPERATOR !~~ (
  LEFTARG = enc_text,
  RIGHTARG = enc_text,
  PROCEDURE = pg_enc_text_notlike
);

CREATE OPERATOR CLASS btree_pg_enc_text_ops
DEFAULT FOR TYPE enc_text USING btree
AS
        OPERATOR        1       <  ,
        OPERATOR        2       <= ,
        OPERATOR        3       =  ,
        OPERATOR        4       >= ,
        OPERATOR        5       >  ,
        FUNCTION        1       pg_enc_text_cmp(enc_text, enc_text);



CREATE OR REPLACE FUNCTION enc_text(varchar)
    RETURNS enc_text
    AS '$libdir/encdb', 'varchar_to_enc_text'
    LANGUAGE C STRICT IMMUTABLE;

CREATE CAST (varchar AS enc_text) WITH FUNCTION enc_text(varchar) AS ASSIGNMENT;

--------------------------------------------------------------------------------
--ENCRYPTED FLOAT4 TYPE (randomized)
--------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION pg_enc_float4_in(cstring)
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_enc_float4_out(enc_float4)
RETURNS cstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE enc_float4 (
    INPUT          = pg_enc_float4_in,
    OUTPUT         = pg_enc_float4_out,
    INTERNALLENGTH = 45,
    ALIGNMENT      = int4,
    STORAGE        = PLAIN
);

CREATE FUNCTION pg_enc_float4_encrypt(float4)
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_decrypt(enc_float4)
RETURNS float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_eq(enc_float4, enc_float4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_ne(enc_float4, enc_float4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_lt(enc_float4, enc_float4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_le(enc_float4, enc_float4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_gt(enc_float4, enc_float4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_ge(enc_float4, enc_float4)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_cmp(enc_float4, enc_float4)
RETURNS integer
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_add(enc_float4, enc_float4)
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_subs(enc_float4, enc_float4)
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_mult(enc_float4, enc_float4)
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_div(enc_float4, enc_float4)
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_exp(enc_float4, enc_float4)
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_addfinal(enc_float4[])
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_sum_bulk(enc_float4[])
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_maxfinal(enc_float4[])
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_max_bulk(enc_float4[])
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_minfinal(enc_float4[])
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_min_bulk(enc_float4[])
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_avgfinal(enc_float4[])
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_avg_bulk(enc_float4[])
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_float4_mod(enc_float4, enc_float4)
RETURNS enc_float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OPERATOR = (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_eq,
  COMMUTATOR = '=',
  NEGATOR = '<>',
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES, MERGES
);

CREATE OPERATOR <> (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_ne,
  COMMUTATOR = '<>',
  NEGATOR = '=',
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);
CREATE OPERATOR < (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_lt,
  COMMUTATOR = > ,
  NEGATOR = >= ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_le,
  COMMUTATOR = >= ,
  NEGATOR = > ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_gt,
  COMMUTATOR = < ,
  NEGATOR = <= ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_ge,
  COMMUTATOR = <= ,
  NEGATOR = < ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR + (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_add
);

CREATE OPERATOR - (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_subs
);

CREATE OPERATOR * (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_mult
);

CREATE OPERATOR / (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_div
);

CREATE OPERATOR % (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_mod
);

CREATE OPERATOR ^ (
  LEFTARG = enc_float4,
  RIGHTARG = enc_float4,
  PROCEDURE = pg_enc_float4_exp
);


CREATE OPERATOR CLASS btree_pg_enc_float4_ops
DEFAULT FOR TYPE enc_float4 USING btree
AS
        OPERATOR        1       <  ,
        OPERATOR        2       <= ,
        OPERATOR        3       =  ,
        OPERATOR        4       >= ,
        OPERATOR        5       >  ,
        FUNCTION        1       pg_enc_float4_cmp(enc_float4, enc_float4);

--CREATE AGGREGATE sum (enc_float4)
--(
--   sfunc = pg_enc_float4_add,
--   stype = enc_float4
--);

CREATE AGGREGATE sum (enc_float4)
(
   sfunc = array_append,
   stype = enc_float4[],
  finalfunc = pg_enc_float4_sum_bulk
);

CREATE AGGREGATE sum_simple (enc_float4)
(
   sfunc = array_append,
   stype = enc_float4[],
  finalfunc = pg_enc_float4_addfinal
);

CREATE AGGREGATE avg (enc_float4)
(
   sfunc = array_append,
   stype = enc_float4[],
   finalfunc = pg_enc_float4_avg_bulk
);

CREATE AGGREGATE avg_simple (enc_float4)
(
   sfunc = array_append,
   stype = enc_float4[],
   finalfunc = pg_enc_float4_avgfinal
);

CREATE AGGREGATE max (enc_float4)
(
   sfunc = array_append,
   stype = enc_float4[],
   finalfunc = pg_enc_float4_max_bulk
);

CREATE AGGREGATE max_simple (enc_float4)
(
   sfunc = array_append,
   stype = enc_float4[],
   finalfunc = pg_enc_float4_maxfinal
);

CREATE AGGREGATE min (enc_float4)
(
   sfunc = array_append,
   stype = enc_float4[],
   finalfunc = pg_enc_float4_min_bulk
);

CREATE AGGREGATE min_simple (enc_float4)
(
   sfunc = array_append,
   stype = enc_float4[],
   finalfunc = pg_enc_float4_minfinal
);

CREATE OR REPLACE FUNCTION enc_float4(float4)
    RETURNS enc_float4
    AS '$libdir/encdb', 'float4_to_enc_float4'
    LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION enc_float4(double precision)
    RETURNS enc_float4
    AS '$libdir/encdb', 'double_to_enc_float4'
    LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION enc_float4(numeric)
    RETURNS enc_float4
    AS '$libdir/encdb', 'numeric_to_enc_float4'
    LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION enc_float4(int8)
    RETURNS enc_float4
    AS '$libdir/encdb', 'int8_to_enc_float4'
    LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION enc_float4(int4)
    RETURNS enc_float4
    AS '$libdir/encdb', 'int4_to_enc_float4'
    LANGUAGE C STRICT IMMUTABLE;

CREATE CAST (float4 AS enc_float4) WITH FUNCTION enc_float4(float4) AS ASSIGNMENT;
CREATE CAST (double precision AS enc_float4) WITH FUNCTION enc_float4(double precision) AS ASSIGNMENT;
CREATE CAST (numeric AS enc_float4) WITH FUNCTION enc_float4(numeric) AS ASSIGNMENT;
CREATE CAST (int8 AS enc_float4) WITH FUNCTION enc_float4(int8) AS ASSIGNMENT;
CREATE CAST (int4 AS enc_float4) WITH FUNCTION enc_float4(int4) AS ASSIGNMENT;
--------------------------------------------------------------------------------
--ENCRYPTED TIMESTAMP TYPE (randomized)
--------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION pg_enc_timestamp_in(cstring)
RETURNS enc_timestamp
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_enc_timestamp_out(enc_timestamp)
RETURNS cstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE enc_timestamp (
    INPUT          = pg_enc_timestamp_in,
    OUTPUT         = pg_enc_timestamp_out,
    INTERNALLENGTH = 49,
    ALIGNMENT      = int4,
    STORAGE        = PLAIN
);

CREATE FUNCTION pg_enc_timestamp_encrypt(cstring)
RETURNS enc_timestamp
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_timestamp_decrypt(enc_timestamp)
RETURNS cstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_timestamp_eq(enc_timestamp, enc_timestamp)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_timestamp_ne(enc_timestamp, enc_timestamp)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_timestamp_lt(enc_timestamp, enc_timestamp)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_timestamp_le(enc_timestamp, enc_timestamp)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pg_catalog.date_part(text, enc_timestamp)
RETURNS enc_int4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_timestamp_gt(enc_timestamp, enc_timestamp)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_timestamp_ge(enc_timestamp, enc_timestamp)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pg_enc_timestamp_cmp(enc_timestamp, enc_timestamp)
RETURNS integer
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OPERATOR = (
  LEFTARG = enc_timestamp,
  RIGHTARG = enc_timestamp,
  PROCEDURE = pg_enc_timestamp_eq,
  COMMUTATOR = '=',
  NEGATOR = '<>',
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES, MERGES
);

CREATE OPERATOR <> (
  LEFTARG = enc_timestamp,
  RIGHTARG = enc_timestamp,
  PROCEDURE = pg_enc_timestamp_ne,
  COMMUTATOR = '<>',
  NEGATOR = '=',
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);
CREATE OPERATOR < (
  LEFTARG = enc_timestamp,
  RIGHTARG = enc_timestamp,
  PROCEDURE = pg_enc_timestamp_lt,
  COMMUTATOR = > ,
  NEGATOR = >= ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  LEFTARG = enc_timestamp,
  RIGHTARG = enc_timestamp,
  PROCEDURE = pg_enc_timestamp_le,
  COMMUTATOR = >= ,
  NEGATOR = > ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
  LEFTARG = enc_timestamp,
  RIGHTARG = enc_timestamp,
  PROCEDURE = pg_enc_timestamp_gt,
  COMMUTATOR = < ,
  NEGATOR = <= ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  LEFTARG = enc_timestamp,
  RIGHTARG = enc_timestamp,
  PROCEDURE = pg_enc_timestamp_ge,
  COMMUTATOR = <= ,
  NEGATOR = < ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR CLASS btree_enc_timestamp_ops
DEFAULT FOR TYPE enc_timestamp USING btree
AS
        OPERATOR        1       <  ,
        OPERATOR        2       <= ,
        OPERATOR        3       =  ,
        OPERATOR        4       >= ,
        OPERATOR        5       >  ,
        FUNCTION        1       pg_enc_timestamp_cmp(enc_timestamp, enc_timestamp);


CREATE OR REPLACE FUNCTION enc_timestamp(timestamp)
    RETURNS enc_timestamp
    AS '$libdir/encdb', 'pg_enc_timestamp_encrypt'
    LANGUAGE C STRICT IMMUTABLE;

CREATE CAST (timestamp AS enc_timestamp) WITH FUNCTION enc_timestamp(timestamp) AS ASSIGNMENT;
