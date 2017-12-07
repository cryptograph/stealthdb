## Ubuntu Desktop-16.04-LTS, 64-bit

### Prerequisites
StealthDB dependencies can be installed by running the script `./install-dependencies.sh`.
* nasm
* PostgreSQL 10.0
* [Intel SGX PSW&SDK](https://github.com/01org/linux-sgx#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package) and [Intel SGX Driver](https://github.com/01org/linux-sgx-driver#build-and-install-the-intelr-sgx-driver) (and their build dependencies)

### Build and install StealthDB
Building process includes the generation of a signing key, an extension and an enclave compilation, the enclave signing. All needed libraries can be found in "build\" folder.

	```
	make
	```

During the installation process we create the folder "/usr/local/lib/stealthdb" and copy needed files to it.

	```
	sudo make install
	```

## Docker

### Prerequisites

* Docker

Other dependencies can be installed by running the script `./install-dependencies.sh`.

### Run StealthDB
We build the docker container from the native postgres image and install StealthDB inside. 

	```
	sudo make docker
	```

## Client

1. Run the PostgreSQL client (ex. `sudo -u postgres psql` if PostgreSQL was installed on the host or `sudo -u postgres psql -h 0.0.0.0` in case of docker path), load the extension into the database and generate the default master key
 
	```
	create extension encdb;
	select generate_key();
	```

2. Use encrypted datatypes (e.g. `enc_int4`) in tables, queries and functions likewise native datatypes. See more information in the [manual](https://github.com/cryptograph/stealthdb/blob/master/docs/user/README.md)


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

## Note

The enclave was created with SGX_DEBUG=1 flag and signed with an automatically generated signing key. To use an enclave in production, the signing key must be whitelisted by Intel.

