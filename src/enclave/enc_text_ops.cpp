#include "enclave/enc_text_ops.hpp"

/* Compare two encrypted by aes_gcm strings
 @input: uint8_t array - encrypted string1
         size_t - length of encrypted string1 (max lenght = SGX_AESGCM_IV_SIZE +
 ??? + SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted string2 size_t -
 length of encrypted string2 (SGX_AESGCM_IV_SIZE + ??? + SGX_AESGCM_MAC_SIZE =
 32)
         uint8_t array - which contains the result  1 (if a > b). -1 (if b > a),
 0 (if a == b)
         size_t - length of result (INT32_LENGTH = 4)
 @return:
 * SGX_error, if there was an error during decryption
*/
int enc_text_like(uint8_t* in1,
                  size_t in1_size,
                  uint8_t* in2,
                  size_t in2_size,
                  uint8_t* out,
                  size_t out_size)
{
    int str_raw_size = in1_size - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    int pattern_raw_size = in2_size - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    int resp, result;
    char* str = (char*)malloc(str_raw_size + 1);
    char* pattern = (char*)malloc(pattern_raw_size + 1);

    resp = decrypt_bytes((uint8_t*)in1, in1_size, (uint8_t*)str, str_raw_size);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes((uint8_t*)in2, in2_size, (uint8_t*)pattern, pattern_raw_size);
    if (resp != SGX_SUCCESS)
        return resp;

    result = (MatchText(str, str_raw_size, pattern, pattern_raw_size) == LIKE_TRUE);

    memcpy(out, &result, out_size);

    memset_s(str, str_raw_size + 1, 0, str_raw_size + 1);
    memset_s(pattern, pattern_raw_size + 1, 0, pattern_raw_size + 1);
    memset_s(&result, sizeof(result), 0, sizeof(result));

    free(str);
    free(pattern);

    return resp;
}
/* Compare two encrypted by aes_gcm strings
 @input: uint8_t array - encrypted string1
         size_t - length of encrypted string1 (max lenght = SGX_AESGCM_IV_SIZE +
 ??? + SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted string2 size_t -
 length of encrypted string2 (SGX_AESGCM_IV_SIZE + ??? + SGX_AESGCM_MAC_SIZE =
 32)
         uint8_t array - which contains the result  1 (if a > b). -1 (if b > a),
 0 (if a == b)
         size_t - length of result (INT32_LENGTH = 4)

 @return:
 * SGX_error, if there was an error during decryption
*/
int enc_text_cmp(uint8_t* string1,
                 size_t string1_len,
                 uint8_t* string2,
                 size_t string2_len,
                 uint8_t* result,
                 size_t res_len)
{
    if ((string1_len < SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE) || (string2_len < SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE))
        return MEMORY_COPY_ERROR;

    int raw_str1_len = string1_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    int raw_str2_len = string2_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    int resp, cmp;
    uint8_t* dec_string1 = (uint8_t*)malloc(raw_str1_len + 1);
    uint8_t* dec_string2 = (uint8_t*)malloc(raw_str2_len + 1);

    resp = decrypt_bytes(string1, string1_len, dec_string1, raw_str1_len);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(string2, string2_len, dec_string2, raw_str2_len);
    if (resp != SGX_SUCCESS)
        return resp;

    dec_string1[raw_str1_len] = dec_string2[raw_str2_len] = '\0';

    cmp = strcmp((const char*)dec_string1, (const char*)dec_string2);

    memcpy(result, &cmp, res_len);

    memset_s(dec_string1, raw_str1_len + 1, 0, raw_str1_len + 1);
    memset_s(dec_string2, raw_str2_len + 1, 0, raw_str2_len + 1);

    free(dec_string1);
    free(dec_string2);

    return resp;
}

/* Concatenation of two encrypted by aes_gcm strings
 @input: uint8_t array - encrypted integer1
         size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE + ?? +
 SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted integer2 size_t - length of
 encrypted integer2 (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted result size_t - length of encrypted result
 (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int enc_text_concatenate(uint8_t* string1,
                         size_t string1_len,
                         uint8_t* string2,
                         size_t string2_len,
                         uint8_t* string3,
                         size_t string3_len)
{
    int raw_str1_len = string1_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    int raw_str2_len = string2_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    int raw_str3_len = string3_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    int resp;

    uint8_t* dec_string1 = (uint8_t*)malloc(raw_str1_len + 1);
    uint8_t* dec_string2 = (uint8_t*)malloc(raw_str2_len + 1);
    uint8_t* dec_string3 = (uint8_t*)malloc(raw_str3_len + 1);

    resp = decrypt_bytes(string1, string1_len, dec_string1, raw_str1_len);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(string2, string2_len, dec_string2, raw_str2_len);
    if (resp != SGX_SUCCESS)
        return resp;

    memcpy(dec_string3, dec_string1, raw_str1_len);
    memcpy(dec_string3 + raw_str1_len, dec_string2, raw_str2_len);

    resp = encrypt_bytes(dec_string3, raw_str3_len, string3, string3_len);

    memset_s(dec_string1, raw_str1_len + 1, 0, raw_str1_len + 1);
    memset_s(dec_string2, raw_str2_len + 1, 0, raw_str2_len + 1);
    memset_s(dec_string3, raw_str3_len + 1, 0, raw_str3_len + 1);

    free_allocated_memory(dec_string1);
    free_allocated_memory(dec_string2);
    free_allocated_memory(dec_string3);

    return resp;
}

/* Search for substring in the string (both are encrypted by aes_gcm)
 @input: uint8_t array - encrypted string
         size_t - length of encrypted string (SGX_AESGCM_IV_SIZE + ?? +
 SGX_AESGCM_MAC_SIZE = 32)
         uint8_t array - encrypted substring size_t - length
 of encrypted substring (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, if the strings contains the substring
    1, it not
*/
int enc_text_substring(uint8_t* in1,
                       size_t in1_size,
                       uint8_t* in2,
                       size_t in2_size,
                       uint8_t* in3,
                       size_t in3_size,
                       uint8_t* out,
                       size_t* out_size)
{
    size_t str_size = in1_size - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

    union {
        int val;
        unsigned char bytes[sizeof(val)];
    } from, n_chars;

    char* str = (char*)malloc(str_size + 1);
    uint8_t* result = (uint8_t*)malloc(*out_size + 1);
    int resp = decrypt_bytes(in1, in1_size, (uint8_t*)str, str_size);
    if (resp != SGX_SUCCESS)
        return resp;

    if ((in2_size == INT32_LENGTH) && (in3_size == INT32_LENGTH))
    {
        memcpy(from.bytes, in2, INT32_LENGTH);
        memcpy(n_chars.bytes, in3, INT32_LENGTH);
    }
    else
    {
        resp = decrypt_bytes(in2, in2_size, from.bytes, INT32_LENGTH);
        if (resp != SGX_SUCCESS)
            return resp;

        resp = decrypt_bytes(in3, in3_size, n_chars.bytes, INT32_LENGTH);
        if (resp != SGX_SUCCESS)
            return resp;
    }

    if ((from.val < 0 || n_chars.val < 0) || (from.val + n_chars.val > str_size))
    {
        return OUT_OF_THE_RANGE_ERROR;
    }

    for (size_t i = 0; i < n_chars.val; i++)
    {
        result[i] = str[from.val + i - 1];
    }

    resp = encrypt_bytes(result, n_chars.val, out, *out_size);

    memset_s(result, *out_size + 1, 0, *out_size + 1);

    *out_size = n_chars.val + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;

    memset_s(str, str_size + 1, 0, str_size + 1);
    memset_s(from.bytes, INT32_LENGTH, 0, INT32_LENGTH);
    memset_s(n_chars.bytes, INT32_LENGTH, 0, INT32_LENGTH);

    free(str);
    free(result);

    return resp;
}
