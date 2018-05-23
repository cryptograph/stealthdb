#include "enclave/enc_int32_ops.hpp"
#include "enclave/enclave.h"
#include "enclave/enclave_t.h" /* print_string */
#include "utils/bytes.hpp"
#include "utils/oblvs_int32_ops.hpp"

extern sgx_aes_ctr_128bit_key_t p_key;

/* Compare two encrypted by aes_gcm algorithm integers
 @input: uint8_t array - encrypted integer1
         size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE +
 INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted integer2
         size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE +
 INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32)

         uint8_t array - which contains the result  1 (if a > b). -1 (if b > a),
 0 (if a == b) size_t - length of result (INT32_LENGTH = 4)

 @return:
 * SGX_error, if there was an error during decryption
*/

int enc_int32_cmp(uint8_t* int1,
                  size_t int1_len,
                  uint8_t* int2,
                  size_t int2_len,
                  uint8_t* result,
                  size_t res_len)
{
    int32_t src1_decrypted, src2_decrypted;
    int resp, cmp;

    uint8_t* pSrc1_decrypted = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* pSrc2_decrypted = (uint8_t*)malloc(INT32_LENGTH);

    resp = decrypt_bytes(int1, int1_len, pSrc1_decrypted, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(int2, int2_len, pSrc2_decrypted, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    if (bytearray2int(pSrc1_decrypted, src1_decrypted, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    if (bytearray2int(pSrc2_decrypted, src2_decrypted, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    cmp = obs_int32_cmp(src1_decrypted, src2_decrypted);

    memcpy(result, &cmp, res_len);

    memset_s(pSrc1_decrypted, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(pSrc2_decrypted, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(&src1_decrypted, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(&src2_decrypted, INT32_LENGTH, 0, INT32_LENGTH);
    free_allocated_memory(pSrc1_decrypted);
    free_allocated_memory(pSrc2_decrypted);

    return resp;
}
/* Sum of two encrypted by aes_gcm integers
 @input: uint8_t array - encrypted integer1
         size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE +
 INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted integer2
         size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE +
 INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted result
         size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT32_LENGTH
 + SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_int32_add(uint8_t* int1,
                  size_t int1_len,
                  uint8_t* int2,
                  size_t int2_len,
                  uint8_t* int3,
                  size_t int3_len)
{
    uint8_t *dec_int1, *dec_int2, *dec_int3;
    int32_t decint1_int, decint2_int;
    int64_t decint3_int;
    int resp;
    uint8_t* dec_int1_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int2_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int3_v = (uint8_t*)malloc(INT32_LENGTH);

    if (!dec_int1_v || !dec_int2_v || !dec_int3_v)
    {
        return MEMORY_ALLOCATION_ERROR;
        ;
    }

    resp = decrypt_bytes(int1, int1_len, dec_int1_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(int2, int2_len, dec_int2_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    if (bytearray2int(dec_int1_v, decint1_int, INT32_LENGTH))
        return MEMORY_COPY_ERROR;
    if (bytearray2int(dec_int2_v, decint2_int, INT32_LENGTH))
        return MEMORY_COPY_ERROR;

    decint3_int = (int64_t)decint1_int + (int64_t)decint2_int;

    if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) || (decint2_int > INT32_MAX || decint2_int < INT32_MIN) || (decint3_int > INT32_MAX || decint3_int < INT32_MIN))
        return OUT_OF_THE_RANGE_ERROR;

    if (int2bytearray((int32_t)decint3_int, dec_int3_v, INT32_LENGTH))
        return MEMORY_COPY_ERROR;

    resp = encrypt_bytes(dec_int3_v, INT32_LENGTH, int3, int3_len);

    memset_s(dec_int1_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int2_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int3_v, INT32_LENGTH, 0, INT32_LENGTH);

    memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));

    free_allocated_memory(dec_int1_v);
    free_allocated_memory(dec_int2_v);
    free_allocated_memory(dec_int3_v);
    return resp;
}

/* Subtraction of two aes_gcm encrypted integers
 @input: uint8_t array - encrypted integer1
         size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE +
 INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted integer2
         size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE +
 INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted result
         size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT32_LENGTH
 + SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_int32_sub(uint8_t* int1,
                  size_t int1_len,
                  uint8_t* int2,
                  size_t int2_len,
                  uint8_t* int3,
                  size_t int3_len)
{
    int32_t decint1_int, decint2_int;
    int64_t decint3_int;
    int resp;

    uint8_t* dec_int1_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int2_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int3_v = (uint8_t*)malloc(INT32_LENGTH);

    resp = decrypt_bytes(int1, int1_len, dec_int1_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(int2, int2_len, dec_int2_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    if (bytearray2int(dec_int1_v, decint1_int, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    if (bytearray2int(dec_int2_v, decint2_int, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    decint3_int = (int64_t)decint1_int - (int64_t)decint2_int;

    if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) || (decint2_int > INT32_MAX || decint2_int < INT32_MIN) || (decint3_int > INT32_MAX || decint3_int < INT32_MIN))
        return OUT_OF_THE_RANGE_ERROR;

    if (int2bytearray((int32_t)decint3_int, dec_int3_v, INT32_LENGTH))
        return MEMORY_COPY_ERROR;

    resp = encrypt_bytes(dec_int3_v, INT32_LENGTH, int3, int3_len);

    memset_s(dec_int1_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int2_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int3_v, INT32_LENGTH, 0, INT32_LENGTH);

    memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));

    free_allocated_memory(dec_int1_v);
    free_allocated_memory(dec_int2_v);
    free_allocated_memory(dec_int3_v);

    return resp;
}

/* Multiplication of two encrypted by aes_gcm integers
 @input: uint8_t array - encrypted integer1
         size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE +
 INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted integer2
         size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE +
 INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32) uint8_t arrayenc_int32_sub - encrypted
 result size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT32_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_int32_mult(uint8_t* int1,
                   size_t int1_len,
                   uint8_t* int2,
                   size_t int2_len,
                   uint8_t* int3,
                   size_t int3_len)
{
    int32_t decint1_int, decint2_int;
    int64_t decint3_int;
    int resp;

    uint8_t* dec_int1_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int2_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int3_v = (uint8_t*)malloc(INT32_LENGTH);

    resp = decrypt_bytes(int1, int1_len, dec_int1_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(int2, int2_len, dec_int2_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    if (bytearray2int(dec_int1_v, decint1_int, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    if (bytearray2int(dec_int2_v, decint2_int, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    decint3_int = decint1_int * decint2_int;

    if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) || (decint2_int > INT32_MAX || decint2_int < INT32_MIN) || (decint1_int != 0 && decint3_int / decint1_int != decint2_int))
        return OUT_OF_THE_RANGE_ERROR;

    if (int2bytearray((int32_t)decint3_int, dec_int3_v, INT32_LENGTH))
        return MEMORY_COPY_ERROR;

    resp = encrypt_bytes(dec_int3_v, INT32_LENGTH, int3, int3_len);

    memset_s(dec_int1_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int2_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int3_v, INT32_LENGTH, 0, INT32_LENGTH);

    memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));

    free_allocated_memory(dec_int1_v);
    free_allocated_memory(dec_int2_v);
    free_allocated_memory(dec_int3_v);

    return resp;
}

/* Modulus operation of two encrypted by aes_gcm integers
 @input: uint8_t array - encrypted integer1
         size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE +
 INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted module
         size_t - length of encrypted module (SGX_AESGCM_IV_SIZE + INT32_LENGTH
 + SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted result size_t - length of
 encrypted result (SGX_AESGCM_IV_SIZE + INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_int32_mod(uint8_t* int1,
                  size_t int1_len,
                  uint8_t* int2,
                  size_t int2_len,
                  uint8_t* int3,
                  size_t int3_len)
{
    int32_t decint1_int, decint2_int;
    int64_t decint3_int;
    int resp;

    uint8_t* dec_int1_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int2_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int3_v = (uint8_t*)malloc(INT32_LENGTH);

    resp = decrypt_bytes(int1, int1_len, dec_int1_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(int2, int2_len, dec_int2_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    if (bytearray2int(dec_int1_v, decint1_int, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    if (bytearray2int(dec_int2_v, decint2_int, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    if (decint2_int == 0)
        return ARITHMETIC_ERROR;

    decint3_int = decint1_int % decint2_int;

    if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) || (decint2_int > INT32_MAX || decint2_int < INT32_MIN))
        return OUT_OF_THE_RANGE_ERROR;

    if (int2bytearray((int32_t)decint3_int, dec_int3_v, INT32_LENGTH))
        return MEMORY_COPY_ERROR;

    resp = encrypt_bytes(dec_int3_v, INT32_LENGTH, int3, int3_len);

    memset_s(dec_int1_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int2_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int3_v, INT32_LENGTH, 0, INT32_LENGTH);

    memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));

    free_allocated_memory(dec_int1_v);
    free_allocated_memory(dec_int2_v);
    free_allocated_memory(dec_int3_v);

    return resp;
}

/* Power operation of two encrypted by aes_gcm integers
 @input: uint8_t array - encrypted integer base
         size_t - length of encrypted base (SGX_AESGCM_IV_SIZE + INT32_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted integer exponent size_t -
 length of encrypted exponent (SGX_AESGCM_IV_SIZE + INT32_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted result size_t - length of
 encrypted result (SGX_AESGCM_IV_SIZE + INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_int32_pow(uint8_t* int1,
                  size_t int1_len,
                  uint8_t* int2,
                  size_t int2_len,
                  uint8_t* int3,
                  size_t int3_len)
{
    int32_t decint1_int, decint2_int;
    int64_t decint3_int;
    int resp;

    uint8_t* dec_int1_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int2_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int3_v = (uint8_t*)malloc(INT32_LENGTH);

    resp = decrypt_bytes(int1, int1_len, dec_int1_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(int2, int2_len, dec_int2_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    if (bytearray2int(dec_int1_v, decint1_int, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    if (bytearray2int(dec_int2_v, decint2_int, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    decint3_int = (int64_t)obs_int32_pow(decint1_int, decint2_int);

    if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) || (decint2_int > INT32_MAX || decint2_int < INT32_MIN) || (decint3_int > (int64_t)INT32_MAX || decint3_int < (int64_t)INT32_MIN))
        return OUT_OF_THE_RANGE_ERROR;

    if (int2bytearray((int32_t)decint3_int, dec_int3_v, INT32_LENGTH))
        return MEMORY_COPY_ERROR;

    resp = encrypt_bytes(dec_int3_v, INT32_LENGTH, int3, int3_len);

    memset_s(dec_int1_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int2_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int3_v, INT32_LENGTH, 0, INT32_LENGTH);

    memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));

    free_allocated_memory(dec_int1_v);
    free_allocated_memory(dec_int2_v);
    free_allocated_memory(dec_int3_v);

    return resp;
}

/* Division of two encrypted by aes_gcm integers
 @input: uint8_t array - encrypted integer1
         size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE +
 INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted integer2
         size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE +
 INT32_LENGTH + SGX_AESGCM_MAC_SIZE = 32) uint8_t array - encrypted result
         size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT32_LENGTH
 + SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_int32_div(uint8_t* int1,
                  size_t int1_len,
                  uint8_t* int2,
                  size_t int2_len,
                  uint8_t* int3,
                  size_t int3_len)
{
    int32_t decint1_int, decint2_int;
    int64_t decint3_int;
    int resp;

    uint8_t* dec_int1_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int2_v = (uint8_t*)malloc(INT32_LENGTH);
    uint8_t* dec_int3_v = (uint8_t*)malloc(INT32_LENGTH);

    resp = decrypt_bytes(int1, int1_len, dec_int1_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(int2, int2_len, dec_int2_v, INT32_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    if (bytearray2int(dec_int1_v, decint1_int, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    if (bytearray2int(dec_int2_v, decint2_int, INT32_LENGTH) == -1)
        return MEMORY_COPY_ERROR;

    if (decint2_int == 0)
        return ARITHMETIC_ERROR;

    if (decint2_int == 0)
        return ARITHMETIC_ERROR;

    decint3_int = decint1_int / decint2_int;

    if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) || (decint2_int > INT32_MAX || decint2_int < INT32_MIN))
        return OUT_OF_THE_RANGE_ERROR;

    if (int2bytearray((int32_t)decint3_int, dec_int3_v, INT32_LENGTH))
        return MEMORY_COPY_ERROR;

    resp = encrypt_bytes(dec_int3_v, INT32_LENGTH, int3, int3_len);

    memset_s(dec_int1_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int2_v, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(dec_int3_v, INT32_LENGTH, 0, INT32_LENGTH);

    memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
    memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));

    free_allocated_memory(dec_int1_v);
    free_allocated_memory(dec_int2_v);
    free_allocated_memory(dec_int3_v);

    return resp;
}
