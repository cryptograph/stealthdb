StealthDB
=======================================================================

StealthDB is an extension to PostgreSQL, leveraging Intel SGX, that endows it with encrypted database functionality (i.e. encrypted values can be persisted in tables, and queries with encrypted expressions and predicates can be specified). The database's integrity and confidentiality is guaranteed under a threat model in which only the CPU is trusted. Further information can be found in [the paper](https://arxiv.org/pdf/1711.02279.pdf).

## Status

StealthDB is a research project and is **not** suitable for production use.

## Quickstart

0. Install dependencies:

	```
	sudo ./install-dependencies.sh
	```

### Installing on 64-bit Ubuntu Desktop-16.04

1. Install PostgreSQL server

2. Run the following commands:

	```
	make
	sudo make install
	```

### Creating a Docker Container

1. If you have the PostgreSQL service running, make sure to stop it with `sudo service postgresql stop`.

2. Run the script from the docker/ folder:

    ```
    sudo ./run.sh
    ```

### Running Queries

0. Run the PostgreSQL client.

1. Load the extension into the database and generate the default master key.

	```
	create extension encdb;
	select generate_key();
	```
2. Try some examples

	```
	select load_key(0);
	select pg_enc_int4_encrypt(1) + pg_enc_int4_encrypt(2);
	select pg_enc_int4_decrypt(pg_enc_int4_encrypt(1) + pg_enc_int4_encrypt(2));
    ```

`pg_enc_int4_decrypt` and `pg_enc_int4_encrypt` are wrappers around the `enc_int4` data type, which in turn corresponds to the `int4` type offered by PostgreSQL. 

 `pg_enc_int4_encrypt(x)` encrypts the number `x` and stores it as an `enc_int4` value. `pg_enc_int4_decrypt(x)` takes an `enc_int4` value `x` and decrypts it. Further information can be found [here](https://github.com/cryptograph/stealthdb/blob/master/docs/user/README.md).

Consult the [manual](https://github.com/cryptograph/stealthdb/blob/master/docs/user/install.md) for further information.
