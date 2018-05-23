# The StealthDB Installation Process

## 1. a) Building and Installing StealthDB on Ubuntu

The build process, which is kicked off by running `make`, consists of the building the enclave used by StealthDB as well as the interface it presents to PostgreSQL. The enclave is built as a shared library (`enclave.so`) and is signed using a signing key generated during the build process. The extension itself is also a shared library (`encdb.so`). All the build artifacts can be found in the `build/` folder.

`sudo make install` starts the installation process, which involes copying the artifacts in the `build` directory into various system and PostgreSQL directories.

## 1. b) Building and Installing StealthDB in a Debian-based Docker container

To build the docker image, we bypass the `install_dependencies.sh` script and specify that the Dockerfile install dependencies and clone the StealthDB GitHub repository. This built image is then run, and we specify that the running container use the Intel SGX driver (installed on the host kernel) and Intel AESMD service (running on the host) using the `--device=/dev/isgx` and `--volume=/var/run/aesmd/aesm.socket` flags.

As a result, we need only build in the docker container a subset of all the Intel SGX artifacts. The Dockerfile invokes the `sgx-deps.mk` Makefile to do exactly this, and proceeds to build StealthDB inside the running container through a process analogous to the one described in Section 1. a).

## Note

The enclave created by the above build process is created with SGX_DEBUG=1 flag and is signed with an automatically generated signing key. It is thus a debug enclave. To use an enclave in production, the signing key must be whitelisted by Intel.

