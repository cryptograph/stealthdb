# stealthdb (DEVELOPMENT IS IN PROGRESS, THIS VERSION IS NOT STABLE)
stealthdb: an encrypted database with small trusted computing base.

requirements:
- install Intel SGX (SDK, PSW, driver)
- PostgreSQL 9.6 (server, client)

build StealthDB:

    make

install StealthDB:

    sudo make install

documentation:

    in progress.....

test suite:

    in progress.....

benchmarking suite:

    in progress.....

usage:
- initialization

        1. connect to the Postgres server with the psql client (ex, psql -U postgres -d postgres)

        2. in psql: create extension encdb;
        
        3. in psql: select generate_key(0);

- runtime:
        
        1. in psql: select launch();
        
        2. try some command: 
        
                        select 1::encint + 2::encint
                        
                        select 1.1::encfloat * 2.4::encfloat
