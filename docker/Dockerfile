FROM postgres:latest

RUN apt-get update  \
 && apt-get install --yes \
        nasm \
        build-essential \
        ocaml \
        automake \
        autoconf \
        git \
        libtool \
        wget \
        python \
        #Have to use downgraded openSSL headers due to compilation errors.
        libssl1.0-dev \
        libcurl4-openssl-dev \
        protobuf-compiler \
        libprotobuf-dev \
        postgresql-server-dev-all \
 && rm -rf /var/lib/apt/lists/*

COPY sgx-deps.mk /opt/Makefile
WORKDIR /opt
RUN make

RUN git clone https://github.com/cryptograph/stealthdb /home/stealthDB

WORKDIR /home/stealthDB
RUN make && make install
