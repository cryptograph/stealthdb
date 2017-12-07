# StealthDB special functions
*    ```
    generate_key()
    ```
Generates a new key, seals it with SGX hardware key and appends to the local file DATA_FILENAME. All computations with the secret data are performed inside an enclave. The function returns the serial number of the key (note: temporarily, serial number is always 0).

*   ```
    load_key(int4)
    ```
Reads sealed key from the local file DATA_FILENAME, unseals it and uploads into an enclave as the master key. The argument is a serial number of a previously generated key (note: temporarily, serial number is always 0).

*   ```
    enable_debug_mode(int4)
    ```
Enables/disables encryption of PostgreSQL datatypes and their conversion into encrypted ones, it also allows automatically decrypt the query result. The argument is 0 (disable) or 1 (enable). This function makes the system insecure, because a malicious DBMS can potentially extract and decrypt all encrypted values. Eventually, the function will be moved to an independent enclave according to the paper.
*    ```
    pg_enc_int4_encrypt(int4)
    ```
Encrypts an int4 with the master key, returns enc_int4 element.
*    ```
    pg_enc_int4_decrypt(enc_int4)
    ```
Decrypts an enc_int4 element with the master key and returns int4.
*    ```
    pg_enc_float4_encrypt(float4)
    ```
Encrypts a float4 with the master key, returns enc_float4 element.
*    ```
    pg_enc_float4_decrypt(enc_float4)
    ```
Decrypts an enc_float4 element with the master key and returns float4.
*    ```
    pg_enc_text_encrypt(varchar)
    ```
Encrypts a string with the master key, returns enc_text element as a string (note: temporarily, the length of the input string is limited by 1024 characters)
*    ```
    pg_enc_text_decrypt(enc_text)
    ```
Decrypts an enc_text element with the master key and returns a string.
*    ```
    pg_enc_timestamp_enrypt(timestamp)
    ```
Encrypts the timestamp with the master key, returns enc_timestamp element. 
*    ```
    pg_enc_timestamp_decrypt(enc_timestamp)
    ```
Decrypts an enc_timestamp element with the master key and returns timestamp.

