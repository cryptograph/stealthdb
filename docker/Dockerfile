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
        libssl-dev \
        libcurl4-openssl-dev \
        protobuf-compiler \
        libprotobuf-dev \
        postgresql-server-dev-all \
 && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/cryptograph/stealthdb /home/stealthDB
