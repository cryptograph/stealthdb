StealthDB
=======================================================================

StealthDB is an extension to PostgreSQL, leveraging Intel SGX, that allows it to be used as an encrypted database (i.e. encrypted values can be persisted in tables, and queries with encrypted expressions and predicates can be specified). The database's integrity and confidentiality is guaranteed under a threat model in which only the CPU is trusted. Further information can be found in [our paper](https://arxiv.org/pdf/1711.02279.pdf).

## Status

StealthDB is a research project and is **not** suitable for production use. 

## Prerequisites

* nasm

	```
	sudo apt-get install nasm
	```

* PostgreSQL 9.6 or above

	```
	sudo apt-get install postgresql postgresql-server-dev-all
	sudo service postgresql restart
	```

* Intel SGX-enabled CPU with installed in the `/opt` directory [Intel SGX PSW&SDK](https://github.com/01org/linux-sgx#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package) and [Intel SGX Driver](https://github.com/01org/linux-sgx-driver#build-and-install-the-intelr-sgx-driver), version 1.9.

* Linux, Ubuntu Desktop-16.04-LTS 64-bit

## Quickstart (Ubuntu)

1. Build and install StealthDB

	```
	make
	sudo make install
	```

2. Run the PostgreSQL client (ex. `sudo -u postgres psql`), load the extension into the database and generate the default master key
 
	```
	create extension encdb;
	select generate_key();
	```

3. Use encrypted datatypes (ex. enc_int4) in tables, queries and functions likewise native datatypes. See more information in the [manual](https://github.com/cryptograph/stealthdb/docs/user/README.md).


## Examples

1. Try some examples

	```
	select pg_enc_int4_encrypt(1) + pg_enc_int4_encrypt(2);
	select pg_enc_int4_decrypt(pg_enc_int4_encrypt(1) + pg_enc_int4_encrypt(2));
	```
 
2. Enable auto-encryption of input values and auto-decryption of encrypted query results, run `select enable_debug_mode(1);`. This will enable you to run the following

	```
	select 1::enc_int4 > 2::enc_int4;
	select 10.5::enc_float4 / 2.2::enc_float4;
	```

