\unset ECHO
\i sql/setup.sql

select plan(47);

DROP TABLE IF EXISTS test_table;
CREATE TABLE test_table (id int, num_i enc_int4, num_f enc_float4, str enc_text, time enc_timestamp);


--CREATE FUNCTION TEST_INSERT () 
--DECLARE
--   counter INTEGER := 0 ; 
---BEGIN

-- WHILE counter <= 20 LOOP
--counter := counter + 1 ; 
-- END LOOP ; END ; 

--INSERT INTO test_table VALUES (1,'qPi1p4veVIVUTOauaOlrKcnY0aj5K+GS9q6QWYlmKkH=','+G3Bb/jHI78D3Hq3gbo+DEfOtLdWEPqYYs9baZrNobP=','dtf8fCOV4LuswydUmfzFsrHkjHupFElIjD5K26pANmk8');
--INSERT INTO test_table VALUES (2,'imddM6yDio+8m9YjdgHAd8W2Zr+PCE0Yfh3PCpoMyQX=','AJrPjKwICexdS5dsuQKiwQBQs7eZ/zUlDaNCTYHNjDD=','JclPi1jtjtI7nnxbZ/xZoRleWHHdXdtLKmZ5JW3pTv4ziAP9ZkAEMw==');
--INSERT INTO test_table VALUES (3,'cYJSlL5Z1LQwHSHa9iDAIG3xg/2x9RLhxAHBkVWGrqv=','5ptgfZb2N6s0jo+pnJM8nwQw3vQWWmELg8Le6zv/oBn=','VJ6kaUSHFcQU25XCKIGi8VHdFM5Di/kUCz67QQ==');

select ok(pg_enc_int4_decrypt(pg_enc_int4_encrypt(1)) = 1::int4, 'enc_int4: encryption/decryption test');
select ok(pg_enc_float4_decrypt(pg_enc_float4_encrypt(1.1)) = 1.1::float4, 'enc_float4: encryption/decryption test');
--select is(pg_enc_timestamp_decrypt(pg_enc_timestamp_encrypt('11/11/11 11:11:11')), '11/11/11 11:11:11'::timestamp, 'enc_timestamp: encryption/decryption test');
--select ok(pg_enc_text_decrypt(pg_enc_text_encrypt('test')) = 'test'::cstring, 'enc_test: encryption/decryption test');

select enable_debug_mode(1);

INSERT INTO test_table VALUES (1, '1', '1.1', 'hello', '01/01/2020');
INSERT INTO test_table VALUES (2, '2', '2.1', 'world', '01/01/2019');
INSERT INTO test_table VALUES (3, '3', '3.1', 'from', '01/01/2018');
INSERT INTO test_table VALUES (3, '3', '3.1', 'stealth', '01/01/2017');


SELECT results_eq(
   'select SUM(num_i) from test_table',
    $$VALUES (9::enc_int4)$$,
    'enc_int4: SUM function '
);

SELECT results_eq(
   'select MIN(num_i) from test_table',
    $$VALUES (1::enc_int4)$$,
    'enc_int4: MIN function '
);

SELECT results_eq(
   'select MAX(num_i) from test_table',
    $$VALUES (3::enc_int4)$$,
    'enc_int4: MAX function '
);

SELECT results_eq(
   'select AVG(num_i) from test_table',
    $$VALUES (2::enc_int4)$$,
    'enc_int4: AVG function (with rounding)'
);

SELECT results_eq(
   'select SUM(num_f) from test_table',
    $$VALUES (9.4::enc_float4)$$,
    'enc_float4: SUM function'
);

SELECT results_eq(
   'select AVG(num_f) from test_table',
    $$VALUES (2.35::enc_float4)$$,
    'enc_float4: AVG function'
);

DECLARE q1 CURSOR FOR select id from test_table where time < '01/01/2018';
SELECT results_eq(
   'q1'::refcursor,
    $$VALUES (3::int4)$$,
    'enc_float: < operator in a table'
);

DECLARE q2 CURSOR FOR select id from test_table where str = 'stealth';
SELECT results_eq(
   'q2'::refcursor,
    $$VALUES (3)$$,
    'enc_text: = operator in a table'
);

--select ok(0::enc_int4 = 0::int4, 'enc_int4: encryption/decryption test in a preprocessing form');
--select ok(0.5::enc_float4 = 0.5::float4, 'enc_float4: encryption/decryption test in a preprocessing form');
--select ok('11/11/11 11:11:11'::enc_timestamp = '11/11/11 11:11:11'::timestamp, 'enc_timestamp: encryption/decryption test in a preprocessing form');
--select ok('test2'::enc_text = 'test2'::cstring, 'enc_text: encryption/decryption test in a preprocessing form');

select ok(1::enc_int4 = 1::enc_int4, 'enc_int4: inequality test, operator =');
select ok(0::enc_int4 != 1::enc_int4, 'enc_int4: inequality test, operator !=');
select ok(0::enc_int4 <> 1::enc_int4, 'enc_int4: inequality test, operator <>');
select ok(1::enc_int4 <= 2::enc_int4, 'enc_int4: inequality test, operator <=');
select ok(1::enc_int4 <= 1::enc_int4, 'enc_int4: inequality test, operator <=');
select ok(3::enc_int4 >= 2::enc_int4, 'enc_int4: inequality test, operator >=');
select ok(1::enc_int4 >= 1::enc_int4, 'enc_int4: inequality test, operator >=');
select ok(2::enc_int4 < 3::enc_int4, 'enc_int4: inequality test, operator <');
select ok(3::enc_int4 > 2::enc_int4, 'enc_int4: inequality test, operator >');

select ok(2::enc_int4 + 1::enc_int4 = 3::enc_int4, 'enc_int4: operator +');
select ok(2::enc_int4 - 1::enc_int4 = 1::enc_int4, 'enc_int4: operator -');
select ok(2::enc_int4 * 2::enc_int4 = 4::enc_int4, 'enc_int4: operator *');
select ok(6::enc_int4 / 2::enc_int4 = 3::enc_int4, 'enc_int4: operator /');
--SELECT throws_ok(6::enc_int4 / 0::enc_int4, '', 'SGX_ERROR_CODE -4: ARITHMETIC_ERROR', '' );


select ok(1.1::enc_float4 = 1.1::enc_float4, 'enc_float4: inequality test, operator =');
select ok(0.2::enc_float4 != 1.1::enc_float4, 'enc_float4: inequality test, operator !=');
select ok(0.2::enc_float4 <> 1.1::enc_float4, 'enc_float4: inequality test, operator <>');
select ok(1.1::enc_float4 <= 2.3::enc_float4, 'enc_float4: inequality test, operator <=');
select ok(1.1::enc_float4 <= 1.1::enc_float4, 'enc_float4: inequality test, operator <=');
select ok(3.4::enc_float4 >= 2.3::enc_float4, 'enc_float4: inequality test, operator >=');
select ok(1.1::enc_float4 >= 1.1::enc_float4, 'enc_float4: inequality test, operator >=');
select ok(2.3::enc_float4 < 3.4::enc_float4, 'enc_float4: inequality test, operator <');
select ok(3.4::enc_float4 > 2.3::enc_float4, 'enc_float4: inequality test, operator >');

select ok(2.3::enc_float4 + 1.1::enc_float4 = 3.4::enc_float4, 'enc_float4: operator +');
--select ok(pg_enc_float4_encrypt(2.3) - pg_enc_float4_encrypt(1.1) = pg_enc_float4_encrypt(1.2), 'enc_float4: operator -');
--select ok(2.3::enc_float4 - 1.1::enc_float4 = 1.2::enc_float4, 'enc_float4: operator -');
--select ok(2.3::enc_float4 * 2.3::enc_float4 = 5.29::enc_float4, 'enc_float4: operator *');
select ok(9.9::enc_float4 / 3.3::enc_float4 = 3::enc_float4, 'enc_float4: operator /');

select ok('11/11/12'::enc_timestamp = '11/11/12'::enc_timestamp, 'enc_timestamp: inequality test, operator =');
select ok('11/11/12 00:00:01'::enc_timestamp != '11/11/12 00:00:02'::enc_timestamp, 'enc_timestamp: inequality test, operator !=');
select ok('11/11/12 00:00:01'::enc_timestamp <> '11/11/12 00:00:02'::enc_timestamp, 'enc_timestamp: inequality test, operator <>');
select ok('11/11/12 00:00:01'::enc_timestamp <= '11/11/12 00:00:01'::enc_timestamp, 'enc_timestamp: inequality test, operator <=');
select ok('11/11/12 00:00:01'::enc_timestamp <= '11/11/12 00:00:03'::enc_timestamp, 'enc_timestamp: inequality test, operator <=');
select ok('11/11/12 00:00:01'::enc_timestamp >= '11/11/12 00:00:01'::enc_timestamp, 'enc_timestamp: inequality test, operator >=');
select ok('11/11/12 00:00:02'::enc_timestamp >= '11/11/12 00:00:01'::enc_timestamp, 'enc_timestamp: inequality test, operator >=');
select ok('11/11/12 00:00:01'::enc_timestamp < '11/11/12 00:00:03'::enc_timestamp, 'enc_timestamp: inequality test, operator <');
select ok('11/11/12 00:00:03'::enc_timestamp > '11/11/12 00:00:01'::enc_timestamp, 'enc_timestamp: inequality test, operator >');

select ok('test1'::enc_text = 'test1'::enc_text, 'enc_text: inequality test, operator =');
select ok('test1'::enc_text != 'test2'::enc_text, 'enc_text: inequality test, operator !=');
select ok('test1'::enc_text <> 'test2'::enc_text, 'enc_text: inequality test, operator <>');
select ok('hello'::enc_text || 'world'::enc_text = 'helloworld'::enc_text, 'enc_text: operator ||');


select * from finish();
--DROP TABLE IF EXISTS test_table;
ROLLBACK;
