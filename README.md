StealthDB
=======================================================================

StealthDB is an extension to PostgreSQL, leveraging Intel SGX, that endows it with encrypted database functionality (i.e. encrypted values can be persisted in tables, and queries with encrypted expressions and predicates can be specified). The database's integrity and confidentiality is guaranteed under a threat model in which only the CPU is trusted. Further information can be found [here](https://arxiv.org/pdf/1711.02279.pdf).

## Status

StealthDB is a research project and is **not** suitable for production use.

## Requirements

* An Intel:registered: SGX-enabled CPU. In addition:
    * The [Intel:registered: SGX PSW and SDK](https://github.com/01org/linux-sgx#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package) installed in the `/opt` directory
    * Version 2.0 of the [Intel:registered: SGX Driver](https://github.com/01org/linux-sgx-driver#build-and-install-the-intelr-sgx-driver)

* The NASM assembler.

## Quickstart

### Installing on 64-bit Ubuntu Desktop-16.04

0. Install PostgreSQL server and the PostgreSQL extension build tool:

```
sudo apt-get install postgresql postgresql-server-dev-all
```

1. Run:

```
make
sudo make install
```

### Creating a Debian-based Docker Container

1. If you have a PostgreSQL service already running, be sure to stop it with `sudo service postgresql stop`.

2. Run

```
make docker
```

### Running Queries

0. Run the PostgreSQL client.

1. Load the extension into the database, generate the default master key, and load the key.

```
CREATE EXTENSION encdb;
SELECT generate_key();
SELECT load_key(0);
```

2. Try some examples

```
SELECT pg_enc_int4_encrypt(1) + pg_enc_int4_encrypt(2);
SELECT pg_enc_int4_decrypt(pg_enc_int4_encrypt(1) + pg_enc_int4_encrypt(2));
```

`pg_enc_int4_decrypt` and `pg_enc_int4_encrypt` are wrappers around the `enc_int4` data type, which in turn corresponds to the `int4` type offered by PostgreSQL.

`pg_enc_int4_encrypt(x)` encrypts the number `x` and stores it as an `enc_int4` value. `pg_enc_int4_decrypt(x)` takes an `enc_int4` value `x` and decrypts it. Further information can be found [here](https://github.com/cryptograph/stealthdb/blob/master/docs/user/README.md).

Consult the [manual](https://github.com/cryptograph/stealthdb/blob/master/docs/user/install.md) for further information.
