# Test suite

We use pgTAP tool to make testing cases based on SQL queries.

## Install

	```
	sudo apt-get install libtap-parser-sourcehandler-pgtap-perl

	```

## Run

	```
	pg_prove -U postgres -d postgres encdb/run_test.sql

	```

