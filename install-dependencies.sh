#!/bin/sh

OS=$(lsb_release -si)

if [ "$OS" = "Ubuntu" ]; then
    sudo apt -y update
# intel sgx libraries
    sudo apt -y install ocaml automake autoconf libtool protobuf-compiler libprotobuf-dev
# postgreSQL
    sudo apt -y install postgresql-server-dev-all
# StealthDB
    sudo apt -y install git nasm build-essential
    sudo service restart postgresql
    make -C external
    sudo make -C external install

elif [ "$OS" = "Debian" ]; then
    sudo apt -y update
# intel sgx libraries
    sudo apt -y install ocaml automake autoconf libtool protobuf-compiler libprotobuf-dev
# postgreSQL
    sudo apt -y install postgresql-server-dev-all
# StealthDB
    sudo apt -y install git nasm build-essential
    sudo service restart postgresql
    make -C external
    sudo make -C external install
fi
