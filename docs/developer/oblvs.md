## Oblivious Operators

Operations such as addition, comparison, mutliplication that form the building blocks for queries are carried out inside an SGX enclave. While this is done to ensure confidentiality of the operands, the enclave is still vulnerable to side channel timing attacks. 

We presently have oblivious implementations of operations involving the enc_int4 type. To enable these, run `make` with the `OBLVS=1` option. By default, `OBLVS` is 0.
