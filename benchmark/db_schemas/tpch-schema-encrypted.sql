DROP TABLE IF EXISTS nation CASCADE;
DROP TABLE IF EXISTS region CASCADE;
DROP TABLE IF EXISTS part CASCADE;
DROP TABLE IF EXISTS supplier CASCADE;
DROP TABLE IF EXISTS partsupp CASCADE;
DROP TABLE IF EXISTS orders CASCADE;
DROP TABLE IF EXISTS customer CASCADE;
DROP TABLE IF EXISTS lineitem CASCADE;

CREATE TABLE nation  ( n_nationkey  INTEGER NOT NULL,
                       n_name       enc_text NOT NULL,
                       n_regionkey  INTEGER NOT NULL,
                       n_comment    enc_text);

CREATE TABLE region  ( r_regionkey  INTEGER NOT NULL,
                       r_name       enc_text NOT NULL,
                       r_comment    enc_text);

CREATE TABLE part  ( p_partkey     INTEGER NOT NULL,
                     p_name        enc_text NOT NULL,
                     p_mfgr        enc_text NOT NULL,
                     p_brand       enc_text NOT NULL,
                     p_type        enc_text NOT NULL,
                     p_size        enc_int4 NOT NULL,
                     p_container   enc_text NOT NULL,
                     p_retailprice enc_float4 NOT NULL,
                     p_comment     enc_text NOT NULL );

CREATE TABLE supplier ( s_suppkey     INTEGER NOT NULL,
                        s_name        enc_text NOT NULL,
                        s_address     enc_text NOT NULL,
                        s_nationkey   INTEGER NOT NULL,
                        s_phone       enc_text NOT NULL,
                        s_acctbal     enc_float4 NOT NULL,
                        s_comment     enc_text NOT NULL);

CREATE TABLE partsupp ( ps_partkey     INTEGER NOT NULL,
                        ps_suppkey     INTEGER NOT NULL,
                        ps_availqty    enc_float4 NOT NULL,
                        ps_supplycost  enc_float4  NOT NULL,
                        ps_comment     enc_text NOT NULL );

CREATE TABLE customer ( c_custkey     INTEGER NOT NULL,
                        c_name        enc_text NOT NULL,
                        c_address     enc_text NOT NULL,
                        c_nationkey   INTEGER NOT NULL,
                        c_phone       enc_text NOT NULL,
                        c_acctbal     enc_float4   NOT NULL,
                        c_mktsegment  enc_text NOT NULL,
                        c_comment     enc_text NOT NULL);

CREATE TABLE orders  ( o_orderkey       INTEGER NOT NULL,
                       o_custkey        INTEGER NOT NULL,
                       o_orderstatus    enc_text NOT NULL,
                       o_totalprice     enc_float4 NOT NULL,
                       o_orderdate      DATE NOT NULL,
                       o_orderpriority  enc_text NOT NULL,  
                       o_clerk          enc_text NOT NULL, 
                       o_shippriority   enc_int4 NOT NULL,
                       o_comment        enc_text NOT NULL);

CREATE TABLE lineitem ( l_orderkey    INTEGER NOT NULL,
                        l_partkey     INTEGER NOT NULL,
                        l_suppkey     INTEGER NOT NULL,
                        l_linenumber  INTEGER NOT NULL,
                        l_quantity    enc_float4 NOT NULL,
                        l_extendedprice  enc_float4 NOT NULL,
                        l_discount    enc_float4 NOT NULL,
                        l_tax         enc_float4 NOT NULL,
                        l_returnflag  enc_text NOT NULL,
                        l_linestatus  enc_text NOT NULL,
                        l_shipdate    DATE NOT NULL,
                        l_commitdate  DATE NOT NULL,
                        l_receiptdate DATE NOT NULL,
                        l_shipinstruct enc_text NOT NULL,
                        l_shipmode     enc_text NOT NULL,
                        l_comment      enc_text NOT NULL);
