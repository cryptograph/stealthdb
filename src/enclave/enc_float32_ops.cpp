#include "enclave/enc_float32_ops.hpp"

/* Compare two aes_gcm-encrypted floats
 @input: uint8_t array - encrypted lhs
         size_t - length of encrypted lhs (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
          uint8_t array - encrypted rhs
          size_t - length of
 encrypted rhs (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - which contains the output 1 (if lhs > rhs). -1 (if lhs
 < rhs), 0 (if lhs == rhs) size_t - length of out (INT64_LENGTH = 4)

 @return:
 * SGX_error, if there was an error during decryption
*/
int enc_float32_cmp(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size)
{
    int result, resp;
    union_float4 lhs, rhs;

    resp = decrypt_bytes(in1, in1_size, lhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(in2, in2_size, rhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    result = (lhs.val == rhs.val) ? 0 : (lhs.val < rhs.val) ? -1 : 1;

    memcpy(out, &result, out_size);

    memset_s(lhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(rhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

    return resp;
}

/* Add two aes_gcm-encrypted floats
 @input: uint8_t array - encrypted lhs
         size_t - length of encrypted lhs (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted rhs
         size_t - length of
 encrypted rhs (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted out
         size_t - length of encrypted out (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
/* comment from PSQL code
 * There isn't any way to check for underflow of addition/subtraction
 * because numbers near the underflow value have already been rounded to
 * the point where we can't detect that the two values were originally
 * different, e.g. on x86, '1e-45'::float4 == '2e-45'::float4 ==
 * 1.4013e-45.
 * we have only 4 bytes for float4 datatype
 * we can check if the out size is less 8^4
 *
 */
int enc_float32_add(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size)
{
    union_float4 lhs, rhs, result;
    int resp;

    resp = decrypt_bytes(in1, in1_size, lhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(in2, in2_size, rhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    result.val = lhs.val + rhs.val;

    resp = encrypt_bytes(result.bytes, FLOAT4_LENGTH, out, out_size);

    memset_s(lhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(rhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(result.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

    return resp;
}

/* Subtract one aes_gcm-encrypted float from another
 @input: uint8_t array - encrypted lhs
         size_t - length of encrypted lhs (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted rhs size_t - length of
 encrypted rhs (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted out
         size_t - length of encrypted out (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_float32_sub(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size)
{
    union_float4 lhs, rhs, result;
    int resp;

    resp = decrypt_bytes(in1, in1_size, lhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(in2, in2_size, rhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    result.val = lhs.val - rhs.val;

    resp = encrypt_bytes(result.bytes, FLOAT4_LENGTH, out, out_size);

    memset_s(lhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(rhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(result.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

    return resp;
}

/* Multiply two aes_gcm-encrypted floats
 @input: uint8_t array - encrypted lhs
         size_t - length of encrypted lhs (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
        uint8_t array - encrypted rhs size_t - length of
 encrypted rhs (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted out
         size_t - length of encrypted out (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_float32_mult(uint8_t* in1,
                     size_t in1_size,
                     uint8_t* in2,
                     size_t in2_size,
                     uint8_t* out,
                     size_t out_size)
{
    union_float4 lhs, rhs, result;
    int resp;

    resp = decrypt_bytes(in1, in1_size, lhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(in2, in2_size, rhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    /*TODO: Check for overflow*/
    result.val = lhs.val * rhs.val;

    resp = encrypt_bytes(result.bytes, FLOAT4_LENGTH, out, out_size);

    memset_s(lhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(rhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(result.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

    return resp;
}

/* Take the power of one aes_gcm-encrypted float by another
 @input: uint8_t array - encrypted float base
         size_t - length of encrypted base (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted float exponent
         size_t - length of encrypted exponent (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
        uint8_t array - encrypted out size_t - length of
 encrypted out (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_float32_pow(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size)
{
    union_float4 lhs, rhs, result;
    int resp;

    resp = decrypt_bytes(in1, in1_size, lhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(in2, in2_size, rhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    /*TODO: Check for overflow*/
    result.val = pow(lhs.val, rhs.val);

    resp = encrypt_bytes(result.bytes, FLOAT4_LENGTH, out, out_size);

    memset_s(lhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(rhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(result.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

    return resp;
}

/* Divide two aes_gcm-encrypted floats
 @input: uint8_t array - encrypted lhs
         size_t - length of encrypted lhs (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted rhs size_t - length of
 encrypted src3 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted out
         size_t - length of encrypted out (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_float32_div(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size)
{
    union_float4 lhs, rhs, result;
    int resp;

    resp = decrypt_bytes(in1, in1_size, lhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(in2, in2_size, rhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    /*TODO: Check for overflow*/
    if (rhs.val == 0)
        return ARITHMETIC_ERROR;
    result.val = lhs.val / rhs.val;

    resp = encrypt_bytes(result.bytes, FLOAT4_LENGTH, out, out_size);

    memset_s(lhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(rhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(result.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

    return resp;
}

/* Take the modulus of one aes_gcm-encrypted float with respect to another
 @input: uint8_t array - encrypted lhs
         size_t - length of encrypted lhs (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted module size_t - length of
 encrypted module (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted out
         size_t - length of encrypted out (SGX_AESGCM_IV_SIZE + INT_LENGTH +
 SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_float32_mod(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size)
{
    union_float4 lhs, rhs, result;
    int resp;

    resp = decrypt_bytes(in1, in1_size, lhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(in2, in2_size, rhs.bytes, FLOAT4_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    /*TODO: Check for correctness*/
    result.val = (int)lhs.val % (int)rhs.val;

    resp = encrypt_bytes(result.bytes, FLOAT4_LENGTH, out, out_size);

    memset_s(lhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(rhs.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(result.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

    return resp;
}

int enc_float32_sum_bulk(uint8_t* in1,
                         size_t in1_len,
                         uint8_t* in2,
                         size_t in2_len,
                         uint8_t* out,
                         size_t out_len)
{
    union_float4 temp, result;
    int32_t bulk_size = 0, current_position = 0;
    int resp, counter = 0;

    if (bytearray2int(in1, bulk_size, INT32_LENGTH))
        return MEMORY_COPY_ERROR;

    result.val = 0;
    while (counter < bulk_size)
    {
        resp = decrypt_bytes(
            in2 + current_position, ENC_FLOAT4_LENGTH, temp.bytes, FLOAT4_LENGTH);
        if (resp != SGX_SUCCESS)
            return resp;
        current_position += ENC_FLOAT4_LENGTH;

        result.val += temp.val;
        counter++;
    }

    resp = encrypt_bytes(result.bytes, FLOAT4_LENGTH, out, out_len);

    memset_s(temp.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
    memset_s(result.bytes, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

    return resp;
}
