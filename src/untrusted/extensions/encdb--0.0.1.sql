-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION encdb" to load this file. \quit

CREATE OR REPLACE FUNCTION generate_key()
RETURNS int
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION load_key(int)
RETURNS int
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION enable_decryption(int)
RETURNS int
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

-------------------------------------------------------------------------------
--ENCRYPTED INTEGER TYPE (randomized)
-------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION encint_in(cstring)
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION encint_out(encint)
RETURNS cstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encint_eq(encint, encint)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encint_ne(encint, encint)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encint_lt(encint, encint)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encint_le(encint, encint)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encint_gt(encint, encint)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encint_ge(encint, encint)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encint_enc(integer)
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encint_dec(encint)
RETURNS integer
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;


--CREATE OR REPLACE FUNCTION encint_recv(internal)
--RETURNS encint
--AS '$libdir/encdb'
--LANGUAGE C IMMUTABLE STRICT;

--CREATE OR REPLACE FUNCTION encint_send(encint)
--RETURNS bytea
--AS '$libdir/encdb'
--LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE encint (
    INPUT          = encint_in,
    OUTPUT         = encint_out,
--    RECEIVE        = encint_recv,
--    SEND           = encint_send,
    INTERNALLENGTH = 45,
    ALIGNMENT      = int4,
    STORAGE        = PLAIN
);
COMMENT ON TYPE encint IS 'ENCRYPTED INTEGER';

CREATE FUNCTION encint_addfinal(encint[])
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encint_avgfinal(encint[])
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encint_minfinal(encint[])
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encint_maxfinal(encint[])
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OPERATOR = (
  LEFTARG = encint,
  RIGHTARG = encint,
  PROCEDURE = encint_eq,
  COMMUTATOR = '=',
  NEGATOR = '<>',
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES, MERGES
);

CREATE OPERATOR <> (
  LEFTARG = encint,
  RIGHTARG = encint,
  PROCEDURE = encint_ne,
  COMMUTATOR = '<>',
  NEGATOR = '=',
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);
CREATE OPERATOR < (
  LEFTARG = encint,
  RIGHTARG = encint,
  PROCEDURE = encint_lt,
  COMMUTATOR = > ,
  NEGATOR = >= ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  LEFTARG = encint,
  RIGHTARG = encint,
  PROCEDURE = encint_le,
  COMMUTATOR = >= ,
  NEGATOR = > ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
  LEFTARG = encint,
  RIGHTARG = encint,
  PROCEDURE = encint_gt,
  COMMUTATOR = < ,
  NEGATOR = <= ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  LEFTARG = encint,
  RIGHTARG = encint,
  PROCEDURE = encint_ge,
  COMMUTATOR = <= ,
  NEGATOR = < ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

--CREATE AGGREGATE sum_arr (encint)
--(
--   sfunc = array_append,
--   stype = encint[],   
--   finalfunc = encint_addfinal	
--);

CREATE AGGREGATE avg (encint)
(
   sfunc = array_append,
   stype = encint[],
   finalfunc = encint_avgfinal
	
);

------------NEW---------------------------
CREATE FUNCTION launch() RETURNS integer
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION encintPlus(encint, encint)
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION encintMinus(encint, encint)
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION encintMult(encint, encint)
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION encintDiv(encint, encint)
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION encintMod(encint, encint)
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION encintExp(encint, encint)
RETURNS encint
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION encintcompare(encint, encint)
RETURNS integer
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE AGGREGATE sum (encint)
(
   sfunc = array_append,
   stype = encint[],   
   finalfunc = encint_addfinal
);

CREATE AGGREGATE min (encint)
(
   sfunc = array_append,
   stype = encint[],   
   finalfunc = encint_minfinal
);

CREATE AGGREGATE max (encint)
(
   sfunc = array_append,
   stype = encint[],   
   finalfunc = encint_maxfinal
);
----------------------------------------------------------------
CREATE OPERATOR + (
  LEFTARG = encint,
  RIGHTARG = encint,
--  PROCEDURE = encint_add
  PROCEDURE = encintplus
);


CREATE OPERATOR - (
  LEFTARG = encint,
  RIGHTARG = encint,
--  PROCEDURE = encint_subs
  PROCEDURE = encintminus

);

CREATE OPERATOR * (
  LEFTARG = encint,
  RIGHTARG = encint,
--  PROCEDURE = encint_mult
  PROCEDURE = encintmult

);

CREATE OPERATOR / (
  LEFTARG = encint,
  RIGHTARG = encint,
--  PROCEDURE = encint_div
  PROCEDURE = encintdiv

);

CREATE OPERATOR % (
  LEFTARG = encint,
  RIGHTARG = encint,
  PROCEDURE = encintmod
);

CREATE OPERATOR ^ (
  LEFTARG = encint,
  RIGHTARG = encint,
  PROCEDURE = encintexp
);


CREATE OPERATOR CLASS btree_encint_ops
DEFAULT FOR TYPE encint USING btree
AS
        OPERATOR        1       <  ,
        OPERATOR        2       <= ,
        OPERATOR        3       =  ,
        OPERATOR        4       >= ,
        OPERATOR        5       >  ,
        FUNCTION        1       encintcompare(encint, encint);

CREATE OR REPLACE FUNCTION encint(int4)
	RETURNS encint
    AS '$libdir/encdb', 'int4_to_encint'
	LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION encint(int8)
	RETURNS encint
    AS '$libdir/encdb', 'int8_to_encint'
	LANGUAGE C STRICT IMMUTABLE;

CREATE CAST (int4 AS encint) WITH FUNCTION encint(int4) AS ASSIGNMENT;
CREATE CAST (int8 AS encint) WITH FUNCTION encint(int8) AS ASSIGNMENT;

--CREATE FUNCTION encstr_in(cstring)
--RETURNS encstr
--AS '$libdir/encdb'
--LANGUAGE C STRICT IMMUTABLE;

--CREATE FUNCTION encstr_out(encstr)
--RETURNS cstring
--AS '$libdir/encdb'
--LANGUAGE C STRICT IMMUTABLE;

--CREATE TYPE encstr (
--        INTERNALLENGTH = variable,
--        INPUT = encstr_in,
--        OUTPUT = encstr_out,
 --       --TYPMOD_IN = hll_typmod_in,
--        --TYPMOD_OUT = hll_typmod_out,
--        --RECEIVE = hll_recv,
--        --SEND = hll_send,
--        STORAGE = external
--);


--------------------------------------------------------------------------------
--ENCRYPTED STRING TYPE (randomized)
--------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION encstring_in(cstring)
RETURNS encstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION encstring_out(encstring)
RETURNS cstring
--LANGUAGE internal IMMUTABLE AS 'textout';
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encstring_eq(encstring, encstring)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encstring_ne(encstring, encstring)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encstring_lt(encstring, encstring)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encstring_le(encstring, encstring)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encstring_gt(encstring, encstring)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encstring_ge(encstring, encstring)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encstring_cmp(encstring, encstring)
RETURNS integer 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encstring_concat(encstring, encstring)
RETURNS encstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encstring_like(encstring, encstring)
RETURNS boolean
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

--CREATE FUNCTION encstring_mult(encstring, encstring)
--RETURNS encstring
--AS '$libdir/encdb'
--LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encstring_enc(cstring)
RETURNS encstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encstring_dec(encstring)
RETURNS cstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;


--CREATE OR REPLACE FUNCTION encstring_recv(internal)
--RETURNS encstring
--AS '$libdir/encdb'
--LANGUAGE C IMMUTABLE STRICT;

--CREATE OR REPLACE FUNCTION encstring_send(encstring)
--RETURNS bytea
--AS '$libdir/encdb'
--LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE encstring (
    INPUT          = encstring_in,
    OUTPUT         = encstring_out,
--    RECEIVE        = encstring_recv,
--    SEND         = encstring_send,
--      LIKE	   = text, 
    INTERNALLENGTH = 128,
--    CATEGORY = 'S',
--    PREFERRED = false
    ALIGNMENT      = int4,
    STORAGE        = PLAIN
);
COMMENT ON TYPE encstring IS 'ENCRYPTED STRING';

CREATE OPERATOR = (
  LEFTARG = encstring,
  RIGHTARG = encstring,
  PROCEDURE = encstring_eq,
  COMMUTATOR = '=',
  NEGATOR = '<>',
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES, MERGES
);

CREATE OPERATOR <> (
  LEFTARG = encstring,
  RIGHTARG = encstring,
  PROCEDURE = encstring_ne,
  COMMUTATOR = '<>',
  NEGATOR = '=',
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);
CREATE OPERATOR < (
  LEFTARG = encstring,
  RIGHTARG = encstring,
  PROCEDURE = encstring_lt,
  COMMUTATOR = > ,
  NEGATOR = >= ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  LEFTARG = encstring,
  RIGHTARG = encstring,
  PROCEDURE = encstring_le,
  COMMUTATOR = >= ,
  NEGATOR = > ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
  LEFTARG = encstring,
  RIGHTARG = encstring,
  PROCEDURE = encstring_gt,
  COMMUTATOR = < ,
  NEGATOR = <= ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  LEFTARG = encstring,
  RIGHTARG = encstring,
  PROCEDURE = encstring_ge,
  COMMUTATOR = <= ,
  NEGATOR = < ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR || (
  LEFTARG = encstring,
  RIGHTARG = encstring,
  PROCEDURE = encstring_concat);

CREATE OPERATOR ~~ (
  LEFTARG = encstring,
  RIGHTARG = encstring,
  PROCEDURE = encstring_like
);

CREATE OPERATOR CLASS btree_encstring_ops
DEFAULT FOR TYPE encstring USING btree
AS
        OPERATOR        1       <  ,
        OPERATOR        2       <= ,
        OPERATOR        3       =  ,
        OPERATOR        4       >= ,
        OPERATOR        5       >  ,
        FUNCTION        1       encstring_cmp(encstring, encstring);



CREATE OR REPLACE FUNCTION encstring(varchar)
	RETURNS encstring
    AS '$libdir/encdb', 'varchar_to_encstring'
	LANGUAGE C STRICT IMMUTABLE;

CREATE CAST (varchar AS encstring) WITH FUNCTION encstring(varchar);
--------------------------------------------------------------------------------
--ENCRYPTED FLOAT4 TYPE (randomized)
--------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION encfloatin(cstring)
RETURNS encfloat
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION encfloatout(encfloat)
RETURNS cstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE encfloat (
    INPUT          = encfloatin,
    OUTPUT         = encfloatout,
    INTERNALLENGTH = 45,
    ALIGNMENT      = int4,
    STORAGE        = PLAIN
);

CREATE FUNCTION encfloat_enc(float4)
RETURNS encfloat
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_dec(encfloat)
RETURNS float4
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_eq(encfloat, encfloat)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_ne(encfloat, encfloat)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_lt(encfloat, encfloat)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_le(encfloat, encfloat)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_gt(encfloat, encfloat)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_ge(encfloat, encfloat)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_cmp(encfloat, encfloat)
RETURNS integer 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_add(encfloat, encfloat)
RETURNS encfloat
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_subs(encfloat, encfloat)
RETURNS encfloat
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_mult(encfloat, encfloat)
RETURNS encfloat
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_div(encfloat, encfloat)
RETURNS encfloat
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_exp(encfloat, encfloat)
RETURNS encfloat
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_addfinal(encfloat[])
RETURNS encfloat
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_avgfinal(encfloat[])
RETURNS encfloat
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION encfloat_mod(encfloat, encfloat)
RETURNS encfloat
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OPERATOR = (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_eq,
  COMMUTATOR = '=',
  NEGATOR = '<>',
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES, MERGES
);

CREATE OPERATOR <> (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_ne,
  COMMUTATOR = '<>',
  NEGATOR = '=',
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);
CREATE OPERATOR < (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_lt,
  COMMUTATOR = > ,
  NEGATOR = >= ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_le,
  COMMUTATOR = >= ,
  NEGATOR = > ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_gt,
  COMMUTATOR = < ,
  NEGATOR = <= ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_ge,
  COMMUTATOR = <= ,
  NEGATOR = < ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR + (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_add
);

CREATE OPERATOR - (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_subs
);

CREATE OPERATOR * (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_mult
);

CREATE OPERATOR / (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_div
);

CREATE OPERATOR % (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_mod
);

CREATE OPERATOR ^ (
  LEFTARG = encfloat,
  RIGHTARG = encfloat,
  PROCEDURE = encfloat_exp
);


CREATE OPERATOR CLASS btree_encfloat_ops
DEFAULT FOR TYPE encfloat USING btree
AS
        OPERATOR        1       <  ,
        OPERATOR        2       <= ,
        OPERATOR        3       =  ,
        OPERATOR        4       >= ,
        OPERATOR        5       >  ,
        FUNCTION        1       encfloat_cmp(encfloat, encfloat);

--CREATE AGGREGATE sum (encfloat)
--(
--   sfunc = encfloat_add,
--   stype = encfloat
--);

CREATE AGGREGATE sum (encfloat)
(
   sfunc = array_append,
   stype = encfloat[],   
  finalfunc = encfloat_addfinal	
);

CREATE AGGREGATE avg (encfloat)
(
   sfunc = array_append,
   stype = encfloat[],
    finalfunc = encfloat_avgfinal
	
);


CREATE OR REPLACE FUNCTION encfloat(float4)
	RETURNS encfloat
    AS '$libdir/encdb', 'float4_to_encfloat'
	LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION encfloat(double precision)
	RETURNS encfloat
    AS '$libdir/encdb', 'double_to_encfloat'
	LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION encfloat(numeric)
	RETURNS encfloat
    AS '$libdir/encdb', 'numeric_to_encfloat'
	LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION encfloat(int8)
	RETURNS encfloat
    AS '$libdir/encdb', 'int8_to_encfloat'
	LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION encfloat(int4)
	RETURNS encfloat
    AS '$libdir/encdb', 'int4_to_encfloat'
	LANGUAGE C STRICT IMMUTABLE;
		
CREATE CAST (float4 AS encfloat) WITH FUNCTION encfloat(float4) AS ASSIGNMENT;
CREATE CAST (double precision AS encfloat) WITH FUNCTION encfloat(double precision) AS ASSIGNMENT;
CREATE CAST (numeric AS encfloat) WITH FUNCTION encfloat(numeric) AS ASSIGNMENT;
CREATE CAST (int8 AS encfloat) WITH FUNCTION encfloat(int8) AS ASSIGNMENT;
CREATE CAST (int4 AS encfloat) WITH FUNCTION encfloat(int4) AS ASSIGNMENT;
--------------------------------------------------------------------------------
--ENCRYPTED TIMESTAMP TYPE (randomized)
--------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enctimestampin(cstring)
RETURNS enctimestamp
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION enctimestampout(enctimestamp)
RETURNS cstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE enctimestamp (
    INPUT          = enctimestampin,
    OUTPUT         = enctimestampout,
    INTERNALLENGTH = 49,
    ALIGNMENT      = int4,
    STORAGE        = PLAIN
);

CREATE FUNCTION enctimestamp_enc(cstring)
RETURNS enctimestamp
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION enctimestamp_dec(enctimestamp)
RETURNS cstring
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION enctimestamp_eq(enctimestamp, enctimestamp)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION enctimestamp_ne(enctimestamp, enctimestamp)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION enctimestamp_lt(enctimestamp, enctimestamp)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION enctimestamp_le(enctimestamp, enctimestamp)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION enctimestamp_gt(enctimestamp, enctimestamp)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION enctimestamp_ge(enctimestamp, enctimestamp)
RETURNS boolean 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION enctimestamp_cmp(enctimestamp, enctimestamp)
RETURNS integer 
AS '$libdir/encdb'
LANGUAGE C IMMUTABLE STRICT;

CREATE OPERATOR = (
  LEFTARG = enctimestamp,
  RIGHTARG = enctimestamp,
  PROCEDURE = enctimestamp_eq,
  COMMUTATOR = '=',
  NEGATOR = '<>',
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES, MERGES
);

CREATE OPERATOR <> (
  LEFTARG = enctimestamp,
  RIGHTARG = enctimestamp,
  PROCEDURE = enctimestamp_ne,
  COMMUTATOR = '<>',
  NEGATOR = '=',
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);
CREATE OPERATOR < (
  LEFTARG = enctimestamp,
  RIGHTARG = enctimestamp,
  PROCEDURE = enctimestamp_lt,
  COMMUTATOR = > ,
  NEGATOR = >= ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  LEFTARG = enctimestamp,
  RIGHTARG = enctimestamp,
  PROCEDURE = enctimestamp_le,
  COMMUTATOR = >= ,
  NEGATOR = > ,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
  LEFTARG = enctimestamp,
  RIGHTARG = enctimestamp,
  PROCEDURE = enctimestamp_gt,
  COMMUTATOR = < ,
  NEGATOR = <= ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  LEFTARG = enctimestamp,
  RIGHTARG = enctimestamp,
  PROCEDURE = enctimestamp_ge,
  COMMUTATOR = <= ,
  NEGATOR = < ,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR CLASS btree_enctimestamp_ops
DEFAULT FOR TYPE enctimestamp USING btree
AS
        OPERATOR        1       <  ,
        OPERATOR        2       <= ,
        OPERATOR        3       =  ,
        OPERATOR        4       >= ,
        OPERATOR        5       >  ,
        FUNCTION        1       enctimestamp_cmp(enctimestamp, enctimestamp);


CREATE OR REPLACE FUNCTION enctimestamp(timestamp)
	RETURNS enctimestamp
    AS '$libdir/encdb', 'enctimestamp_enc'
	LANGUAGE C STRICT IMMUTABLE;

CREATE CAST (timestamp AS enctimestamp) WITH FUNCTION enctimestamp(timestamp) AS ASSIGNMENT;
