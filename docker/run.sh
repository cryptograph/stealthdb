#!/bin/sh
docker build -t stealthdb:1.0 .
docker run -it -d --rm --device=/dev/isgx --volume=/var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket -p 5432:5432 --entrypoint=/bin/bash --name sdb stealthdb:1.0

docker exec sdb make -C /home/stealthDB/external
docker exec sdb make -C /home/stealthDB/external install

docker exec sdb make -C /home/stealthDB
docker exec sdb make -C /home/stealthDB install

docker exec sdb ./docker-entrypoint.sh postgres
