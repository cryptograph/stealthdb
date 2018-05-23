# Benchmarking suite

We use modified open-source OLTP Benchmarking Framework (http://oltpbenchmark.com) to measure TPC-C and TPC-H performance. One can clone the source code of the framework and apply the patch or just use jar executable file to get numbers. 

## Build from the source code.

	```
	git clone https://github.com/oltpbenchmark/oltpbench.git 
	git checkout 51f9aa011defb33cfe4c8ebd902c495830c2824f
	git apply patches/oltpbenchmark.patch
	```

## Configuration

* setup database credentials in configuration file config/tpcc_config_postgres.xml 
* setup logger configuration in log4j.properties
* create TPC-C database schema, select which columns to encrypt 
		(ex.   ol_number int NOT NULL -->   ol_number enc_int4 NOT NULL)
 
See more information in the [original repository](https://github.com/oltpbenchmark/oltpbench/wiki/Quickstart)

## How to start

0. Create the user and the database

	```
	psql
	postgres> CREATE USER test WITH PASSWORD 'password';
	postgres> CREATE DATABASE test;
	postgres> \c test;
	postgres> CREATE EXTENSION encdb;
	```

### TPC-C
1. Create tables and relations

	```
	psql -U test -d test -f db_schemas/tpcc-schema.sql
	(or psql -U test -d test -f db_schemas/tpcc-schema_encrypted.sql)
	```

2.  Run experiments

	```
	java -Dlog4j.configuration=log4j.properties -jar bin/oltp.jar -b tpcc -o output -s 10 --config config/tpcc_config.xml --load true --execute true
	```

3. The output will be in the folder results/ containing files with the listing of start time and duration for each transaction type (output.raw), the throughput and different latency measures in milliseconds (output.res)

### TPC-H
1. Create tables and relations between them

	```
	psql -U test -d test -f db_schemas/tpch-schema.sql
	(or psql -U test -d test -f db_schemas/tpch-schema_encrypted.sql)
	psql -U test -d test -f db_schemas/tpch-index.sql
	```

2. Generate tables

	```
	tool/dbgen -s 2
	```

3.  Run experiments

	```
	java -Dlog4j.configuration=log4j.properties -jar bin/tpch.jar -b tpch -o output -s 10 --config config/tpch_config.xml --load true --execute true
	```

4. The output will be in the folder results/ containing files with the listing of start time and duration for each transaction type (output.csv), the throughput and different latency measures in milliseconds (output.res)

