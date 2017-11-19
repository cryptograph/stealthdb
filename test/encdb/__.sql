\unset ECHO
\i setup.sql

select plan(16);
select launch();
DROP TABLE IF EXISTS test_table;
CREATE TABLE test_table (id int, num_i encint, num_f encfloat, str encstring);
INSERT INTO test_table VALUES (1, 100.1::encfloat +G3Bb/jHI78D3Hq3gbo+DEfOtLdWEPqYYs9baZrNobP=','dtf8fCOV4LuswydUmfzFsrHkjHupFElIjD5K26pANmk8');
INSERT INTO test_table VALUES (2,'imddM6yDio+8m9YjdgHAd8W2Zr+PCE0Yfh3PCpoMyQX=','AJrPjKwICexdS5dsuQKiwQBQs7eZ/zUlDaNCTYHNjDD=','JclPi1jtjtI7nnxbZ/xZoRleWHHdXdtLKmZ5JW3pTv4ziAP9ZkAEMw==');
INSERT INTO test_table VALUES (3,'cYJSlL5Z1LQwHSHa9iDAIG3xg/2x9RLhxAHBkVWGrqv=','5ptgfZb2N6s0jo+pnJM8nwQw3vQWWmELg8Le6zv/oBn=','VJ6kaUSHFcQU25XCKIGi8VHdFM5Di/kUCz67QQ==');




--COPY test_table FROM 'C:\Users\sergey\git\testing\unit\test_table.csv' DELIMITER ',' CSV;


select ok('IirftDZ9BUh5PMl/55EvY5bCqTLmgfzNS2Klv5pEYej='::encfloat != 'gbpU4NYvtQdQnIO3aNvpT/sV/ooFHbyXkByXTCt96sT='::encfloat, 'test operator != [100.1 != 100.2]');
select ok('gbpU4NYvtQdQnIO3aNvpT/sV/ooFHbyXkByXTCt96sT='::encfloat = 'Uqcj7/K4wr20tHeKH5Y7in+oXZ4NkMGZP7O4l9DdXZn='::encfloat, 'test operator = [100.2=100.2]');
select ok('gbpU4NYvtQdQnIO3aNvpT/sV/ooFHbyXkByXTCt96sT='::encfloat > 'IirftDZ9BUh5PMl/55EvY5bCqTLmgfzNS2Klv5pEYej='::encfloat, 'test operator > [100.2>100.1]');
select ok('gbpU4NYvtQdQnIO3aNvpT/sV/ooFHbyXkByXTCt96sT='::encfloat >= '+SH4a0Z1t/y7DPhgtM2AVcqEmNOhjKQduF6/7eNoc/H='::encfloat, 'test operator >= [100.2>=100.1');
select ok('IirftDZ9BUh5PMl/55EvY5bCqTLmgfzNS2Klv5pEYej='::encfloat >= '+SH4a0Z1t/y7DPhgtM2AVcqEmNOhjKQduF6/7eNoc/H='::encfloat, 'test operator >= [100.1>=100.1]');
select ok('veQ7SSVUsrFHRb1BHIHHaD5LfSGSUobBs+Nc86r0uRX='::encfloat < 'Bk3KwaEVDw0vOeQT6uTfXZ1bzjey21EGmFsdBZ3LFyr='::encfloat, 'test operator < [100.1<100.2]');
select ok('sp/kqXn6T88F2+oCylxPiePXINr9eKlOAgLi1hAE2Lv='::encfloat <= 'Bk3KwaEVDw0vOeQT6uTfXZ1bzjey21EGmFsdBZ3LFyr='::encfloat, 'test operator <= [100.1<=100.2]');
select ok('IirftDZ9BUh5PMl/55EvY5bCqTLmgfzNS2Klv5pEYej='::encfloat <= 'sp/kqXn6T88F2+oCylxPiePXINr9eKlOAgLi1hAE2Lv='::encfloat, 'test operator <= [100.1<=100.1]');


select isnt('K2EL/gcybgqwor4zm5iQ8WMhlXZeDTuJ2TmhYnQtWi3='::encfloat, '6lm9Odf56sWk3VyWUQTc/4nRfz4T/GR/KM79mGkm1NX='::encfloat, 'eq encifloat , [1.5!=1.55]');
select is('CTAC+4OiRqXWYyQsq9b0qftcW9Oe0PfbpRhdk9kSg+/='::encfloat + 'QyZHdHoGAdcUSev2CnmjBuHiqZ2TNI7f8a+dDtwGZIr='::encfloat, '+JjgKx356e1cWBOh3Ao/KtOM7weUPNklNOqU/EmM7K3='::encfloat, '+ test encfloat[1.2 + 3.6 = 4.8]');

--select is('CTAC+4OiRqXWYyQsq9b0qftcW9Oe0PfbpRhdk9kSg+/='::encfloat * 'QyZHdHoGAdcUSev2CnmjBuHiqZ2TNI7f8a+dDtwGZIr='::encfloat, 'RjfmjKQyR6J+26RWSkrAOau4WH3FcH7RhZKUSbHiI1/='::encfloat, '* test encfloat[1.2 * 3.6 = 4.8]');
--select is('CTAC+4OiRqXWYyQsq9b0qftcW9Oe0PfbpRhdk9kSg+/='::encfloat - 'QyZHdHoGAdcUSev2CnmjBuHiqZ2TNI7f8a+dDtwGZIr='::encfloat, 'Qut46//vcBkBrnPN0kXwhRBTdxq9fqphWLQBgXnxqDv='::encfloat, '- test encfloat[1.2 - 3.6 = - 2.4]');
--select is('CTAC+4OiRqXWYyQsq9b0qftcW9Oe0PfbpRhdk9kSg+/='::encfloat / 'QyZHdHoGAdcUSev2CnmjBuHiqZ2TNI7f8a+dDtwGZIr='::encfloat, 'CjLzlMrgsK1+9Q/VzTdmspY4EvgVuuqdfHyDFLg4KtX='::encfloat, '/ test encfloat[1.2 / 3.6 = 0.3333]');
--select is('CTAC+4OiRqXWYyQsq9b0qftcW9Oe0PfbpRhdk9kSg+/='::encfloat ^ 'QyZHdHoGAdcUSev2CnmjBuHiqZ2TNI7f8a+dDtwGZIr='::encfloat, 'xC+wc6tUQzms7fcbhbKT7SO8aPVMJPPMZ4Q25kQ/R4X='::encfloat, '^ test encfloat[1.2 ^ 3.6 = 1.92766]');

--SELECT results_eq(
--   'select SUM(num_f) from test_table;',
--    $$VALUES ('BkTcAPHFjbKEa7EdlTSl6qf2LHTn8v37e86SIDnCpqX='::encfloat)$$,
--    'test SUM() function'
--);

--SELECT results_eq(
--    'select SUM_ARR(num_f) from test_table;',
--    $$VALUES ('RU0vU2oKQ3ebrciCRZN0gAT18ZG/pZdEXDbr+EcCLNj='::encfloat)$$,
--    'test SUM_ARR() function'
--);

--SELECT results_eq(
--    'select AVG(num_f) from test_table;',
--    $$VALUES ('t0BDEll8w+X33CHBy/kmJsmCJ+aha90rLsqFlvM8Tsz='::encfloat)$$,
--    'test AVG() function'
--);


SELECT results_eq(
    'select num_f from test_table where num_f < encfloat_enc(1.3);',
    $$VALUES ('+G3Bb/jHI78D3Hq3gbo+DEfOtLdWEPqYYs9baZrNobP='::encfloat)$$,
    'test selection with the where condition based on < operator function'
);

SELECT results_eq(
    'select num_f from test_table where num_f <= encfloat_enc(1.2);',
    $$VALUES ('+G3Bb/jHI78D3Hq3gbo+DEfOtLdWEPqYYs9baZrNobP='::encfloat)$$,
    'test selection with the where condition based on <= operator function'
);

SELECT results_eq(
    'select num_f from test_table where num_f != encfloat_enc(1.2001);',
    ARRAY['+G3Bb/jHI78D3Hq3gbo+DEfOtLdWEPqYYs9baZrNobP='::encfloat, 'AJrPjKwICexdS5dsuQKiwQBQs7eZ/zUlDaNCTYHNjDD='::encfloat , '5ptgfZb2N6s0jo+pnJM8nwQw3vQWWmELg8Le6zv/oBn='::encfloat],
    'test selection with the where condition based on != operator function'
);


SELECT results_eq(
    'select num_f from test_table where num_f = encfloat_enc(3.6);',
    $$VALUES ('5ptgfZb2N6s0jo+pnJM8nwQw3vQWWmELg8Le6zv/oBn='::encfloat)$$,
    'test selection with the where condition based on = operator function'
);

SELECT results_eq(
    'select num_f from test_table where num_f > encfloat_enc(2.399);',
    ARRAY['AJrPjKwICexdS5dsuQKiwQBQs7eZ/zUlDaNCTYHNjDD='::encfloat, '5ptgfZb2N6s0jo+pnJM8nwQw3vQWWmELg8Le6zv/oBn='::encfloat],
    'test selection with the where condition based on > operator function'
);

SELECT results_eq(
    'select num_f from test_table where num_f >= encfloat_enc(0.1);',
    ARRAY['+G3Bb/jHI78D3Hq3gbo+DEfOtLdWEPqYYs9baZrNobP='::encfloat, 'AJrPjKwICexdS5dsuQKiwQBQs7eZ/zUlDaNCTYHNjDD='::encfloat, '5ptgfZb2N6s0jo+pnJM8nwQw3vQWWmELg8Le6zv/oBn='::encfloat],
    'test selection with the where condition based on >= operator function'
);




select * from finish();
ROLLBACK;
