#include "enclave/enclave.hpp"
#include "enclave/enclave_t.h"

sgx_aes_ctr_128bit_key_t* p_key = NULL;

void free_allocated_memory(void* pointer)
{
    if (pointer != NULL)
    {
        free(pointer);
        pointer = NULL;
    }
}

/* Generate a master key
 @input: uint8_t sealed_key - pointer to sealed master key array
         size_t - length of the array (=
 sgx_calc_sealed_data_size(sgx_aes_ctr_128bit_key_t) = 576)
 @return:
    * SGX_error, if there was an error during seal function
    0, otherwise
*/
int generateKeyEnclave(uint8_t* sealed_key, size_t sealedkey_len)
{
    int resp = SGX_SUCCESS;
    uint32_t len = sizeof(sgx_aes_ctr_128bit_key_t);
    uint8_t* p_key_tmp = (uint8_t*)malloc(len);

    if (sgx_calc_sealed_data_size(0, len) > sealedkey_len)
        return MEMORY_COPY_ERROR;

    sgx_read_rand(p_key_tmp, len);
    resp = sgx_seal_data(
        0, NULL, len, p_key_tmp, sealedkey_len, (sgx_sealed_data_t*)sealed_key);

    memset_s(p_key_tmp, len, 0, len);
    free_allocated_memory(p_key_tmp);

    return resp;
}

/* Load the master key from sealed data
 *  @input: uint8_t sealed_key - pointer to a sealed data byte array
            size_t - length of the array (=
 sgx_calc_sealed_data_size(sgx_aes_ctr_128bit_key_t) = 576)
 @return:
    * SGX_error, if there was an error during unsealing
    0, otherwise
*/
int loadKeyEnclave(uint8_t* sealed_key, size_t sealedkey_len)
{
    int resp = SGX_SUCCESS;
    uint32_t len = sizeof(sgx_aes_ctr_128bit_key_t);

    if (p_key == NULL)
        p_key = new sgx_aes_ctr_128bit_key_t[len];

    if (sgx_calc_sealed_data_size(0, sizeof(sgx_aes_ctr_128bit_key_t)) > sealedkey_len)
        return MEMORY_COPY_ERROR;

    resp = sgx_unseal_data(
        (const sgx_sealed_data_t*)sealed_key, NULL, NULL, (uint8_t*)p_key, &len);

    return resp;
}

/* Decrypts byte array by aesgcm mode
 @input: uint8_t array - pointer to encrypted byte array
         size_t - length of encrypted  array
         uint8_t array - pointer to decrypted array
         size_t - length of decrypted array (length of array -
 SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int decrypt_bytes(uint8_t* pSrc, size_t src_len, uint8_t* pDst, size_t dst_len)
{
    int resp = sgx_rijndael128GCM_decrypt(
        p_key,
        pSrc + SGX_AESGCM_IV_SIZE, // cipher
        src_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE,
        pDst, // plain out
        pSrc,
        SGX_AESGCM_IV_SIZE, // nonce
        NULL,
        0, // aad
        (sgx_aes_gcm_128bit_tag_t*)(pSrc - SGX_AESGCM_MAC_SIZE + src_len)); // tag

    return resp;
}

/* Encrypts byte array by aesgcm mode
 @input: uint8_t array - pointer to a byte array
         size_t - length of the array
         uint8_t array - pointer to result array
         size_t - length of result array (SGX_AESGCM_IV_SIZE + length of array +
 SGX_AESGCM_MAC_SIZE)
 @return:
    * SGX_error, if there was an error during encryption/decryption
    0, otherwise
*/
int encrypt_bytes(uint8_t* pSrc, size_t src_len, uint8_t* pDst, size_t dst_len)
{
    unsigned char* nonce = new unsigned char[SGX_AESGCM_IV_SIZE];

    int resp = sgx_read_rand(nonce, SGX_AESGCM_IV_SIZE);
    if (resp != SGX_SUCCESS)
        return resp;

    memcpy(pDst, nonce, SGX_AESGCM_IV_SIZE);
    resp = sgx_rijndael128GCM_encrypt(
        p_key,
        pSrc,
        src_len,
        pDst + SGX_AESGCM_IV_SIZE,
        nonce,
        SGX_AESGCM_IV_SIZE,
        NULL,
        0,
        (sgx_aes_gcm_128bit_tag_t*)(pDst + SGX_AESGCM_IV_SIZE + src_len));

    delete[] nonce;

    return resp;
}

int enclaveProcess(void* arg1)
{
    size_t src_len = 0, src2_len = 0, src3_len = 0, dst_len = 0;
    uint8_t src1[INPUT_BUFFER_SIZE];
    uint8_t src2[INPUT_BUFFER_SIZE];
    uint8_t dst[INPUT_BUFFER_SIZE];
    uint8_t in1[ENC_INT32_LENGTH], in2[ENC_INT32_LENGTH];
    int buf_pos = 0;

    if (arg1 == NULL)
        return -1;
    Queue* inQueue = (Queue*)arg1;

    while (true)
    {
        request* req = inQueue->dequeue();

        if (req == NULL)
            __asm__("pause");
        else
        {
            // request* response = new request;

            switch (req->ocall_index)
            {
            case CMD_INT64_PLUS:
                req->resp = enc_int32_add(req->buffer,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH + ENC_INT32_LENGTH,
                                          ENC_INT32_LENGTH);
                break;

            case CMD_INT64_MINUS:
                req->resp = enc_int32_sub(req->buffer,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH + ENC_INT32_LENGTH,
                                          ENC_INT32_LENGTH);
                break;

            case CMD_INT64_MULT:
                req->resp = enc_int32_mult(req->buffer,
                                           ENC_INT32_LENGTH,
                                           req->buffer + ENC_INT32_LENGTH,
                                           ENC_INT32_LENGTH,
                                           req->buffer + ENC_INT32_LENGTH + ENC_INT32_LENGTH,
                                           ENC_INT32_LENGTH);
                break;

            case CMD_INT64_DIV:
                req->resp = enc_int32_div(req->buffer,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH + ENC_INT32_LENGTH,
                                          ENC_INT32_LENGTH);
                break;

            case CMD_INT64_EXP:
                req->resp = enc_int32_pow(req->buffer,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH + ENC_INT32_LENGTH,
                                          ENC_INT32_LENGTH);
                break;

            case CMD_INT64_MOD:
                req->resp = enc_int32_mod(req->buffer,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH + ENC_INT32_LENGTH,
                                          ENC_INT32_LENGTH);
                break;

            case CMD_INT64_CMP:
                req->resp = enc_int32_cmp(req->buffer,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH,
                                          ENC_INT32_LENGTH,
                                          req->buffer + 2 * ENC_INT32_LENGTH,
                                          INT32_LENGTH);
                break;

            case CMD_INT32_SUM_BULK:
                memcpy(&src_len, req->buffer, INT32_LENGTH);
                req->resp = enc_int32_sum_bulk(
                    req->buffer,
                    INT32_LENGTH,
                    req->buffer + INT32_LENGTH,
                    src_len * ENC_INT32_LENGTH,
                    req->buffer + (src_len)*ENC_INT32_LENGTH + INT32_LENGTH,
                    ENC_INT32_LENGTH);
                break;

            case CMD_INT64_ENC:
                req->resp = encrypt_bytes(req->buffer,
                                          INT32_LENGTH,
                                          req->buffer + INT32_LENGTH,
                                          ENC_INT32_LENGTH);
                break;

            case CMD_INT64_DEC:
                req->resp = decrypt_bytes(req->buffer,
                                          ENC_INT32_LENGTH,
                                          req->buffer + ENC_INT32_LENGTH,
                                          INT32_LENGTH);
                break;

            case CMD_FLOAT4_PLUS:
                req->resp = enc_float32_add(req->buffer,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + ENC_FLOAT4_LENGTH,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + 2 * ENC_FLOAT4_LENGTH,
                                            ENC_FLOAT4_LENGTH);
                break;

            case CMD_FLOAT4_MINUS:
                req->resp = enc_float32_sub(req->buffer,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + ENC_FLOAT4_LENGTH,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + 2 * ENC_FLOAT4_LENGTH,
                                            ENC_FLOAT4_LENGTH);
                break;

            case CMD_FLOAT4_MULT:
                req->resp = enc_float32_mult(req->buffer,
                                             ENC_FLOAT4_LENGTH,
                                             req->buffer + ENC_FLOAT4_LENGTH,
                                             ENC_FLOAT4_LENGTH,
                                             req->buffer + 2 * ENC_FLOAT4_LENGTH,
                                             ENC_FLOAT4_LENGTH);
                break;

            case CMD_FLOAT4_DIV:
                req->resp = enc_float32_div(req->buffer,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + ENC_FLOAT4_LENGTH,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + 2 * ENC_FLOAT4_LENGTH,
                                            ENC_FLOAT4_LENGTH);
                break;

            case CMD_FLOAT4_EXP:
                req->resp = enc_float32_pow(req->buffer,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + ENC_FLOAT4_LENGTH,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + 2 * ENC_FLOAT4_LENGTH,
                                            ENC_FLOAT4_LENGTH);
                break;

            case CMD_FLOAT4_MOD:
                req->resp = enc_float32_mod(req->buffer,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + ENC_FLOAT4_LENGTH,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + 2 * ENC_FLOAT4_LENGTH,
                                            ENC_FLOAT4_LENGTH);
                break;

            case CMD_FLOAT4_CMP:
                req->resp = enc_float32_cmp(req->buffer,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + ENC_FLOAT4_LENGTH,
                                            ENC_FLOAT4_LENGTH,
                                            req->buffer + 2 * ENC_FLOAT4_LENGTH,
                                            INT32_LENGTH);
                break;

            case CMD_FLOAT4_SUM_BULK:
                memcpy(&src_len, req->buffer, INT32_LENGTH);
                req->resp = enc_float32_sum_bulk(
                    req->buffer,
                    INT32_LENGTH,
                    req->buffer + INT32_LENGTH,
                    src_len * ENC_FLOAT4_LENGTH,
                    req->buffer + (src_len)*ENC_FLOAT4_LENGTH + INT32_LENGTH,
                    ENC_FLOAT4_LENGTH);
                break;

            case CMD_FLOAT4_ENC:
                req->resp = encrypt_bytes(req->buffer,
                                          FLOAT4_LENGTH,
                                          req->buffer + FLOAT4_LENGTH,
                                          ENC_FLOAT4_LENGTH);
                break;

            case CMD_FLOAT4_DEC:
                req->resp = decrypt_bytes(req->buffer,
                                          ENC_FLOAT4_LENGTH,
                                          req->buffer + ENC_FLOAT4_LENGTH,
                                          FLOAT4_LENGTH);
                break;

            case CMD_STRING_CMP:
                memcpy(&src_len, req->buffer, INT32_LENGTH);
                memcpy(src1, req->buffer + INT32_LENGTH, src_len);
                memcpy(&src2_len, req->buffer + INT32_LENGTH + src_len, INT32_LENGTH);
                memcpy(src2,
                       req->buffer + INT32_LENGTH + src_len + INT32_LENGTH,
                       src2_len);
                req->resp = enc_text_cmp(src1,
                                         src_len,
                                         src2,
                                         src2_len,
                                         req->buffer + 2 * INT32_LENGTH + src_len + src2_len,
                                         INT32_LENGTH);
                break;

            case CMD_STRING_LIKE:
                memcpy(&src_len, req->buffer + buf_pos, INT32_LENGTH);
                buf_pos += INT32_LENGTH;

                memcpy(src1, req->buffer + buf_pos, src_len);
                buf_pos += src_len;

                memcpy(&src2_len, req->buffer + buf_pos, INT32_LENGTH);
                buf_pos += INT32_LENGTH;

                memcpy(src2, req->buffer + buf_pos, src2_len);
                buf_pos += src2_len;

                req->resp = enc_text_like(
                    src1, src_len, src2, src2_len, req->buffer + buf_pos, INT32_LENGTH);
                buf_pos = 0;
                break;

            case CMD_STRING_ENC:
                memcpy(&src_len, req->buffer, INT32_LENGTH);
                dst_len = src_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;

                memcpy(src1, req->buffer + INT32_LENGTH, src_len);

                memcpy(req->buffer + INT32_LENGTH + src_len, &dst_len, INT32_LENGTH);
                req->resp = encrypt_bytes(
                    src1, src_len, req->buffer + src_len + 2 * INT32_LENGTH, dst_len);
                break;

            case CMD_STRING_DEC:
                memcpy(&src_len, req->buffer, INT32_LENGTH);
                dst_len = src_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
                memcpy(src1, req->buffer + INT32_LENGTH, src_len);
                req->resp = decrypt_bytes(src1, src_len, dst, dst_len);
                memcpy(req->buffer + INT32_LENGTH + src_len, &dst_len, INT32_LENGTH);
                memcpy(req->buffer + src_len + 2 * INT32_LENGTH, dst, dst_len);
                break;

            case CMD_STRING_SUBSTRING:
                memcpy(&src_len, req->buffer + buf_pos, INT32_LENGTH);
                buf_pos += INT32_LENGTH;

                memcpy(src1, req->buffer + buf_pos, src_len);
                buf_pos += src_len;

                memcpy(&src2_len, req->buffer + buf_pos, INT32_LENGTH);
                buf_pos += INT32_LENGTH;

                memcpy(in1, req->buffer + buf_pos, src2_len);
                buf_pos += src2_len;

                memcpy(&src3_len, req->buffer + buf_pos, INT32_LENGTH);
                buf_pos += INT32_LENGTH;

                memcpy(in2, req->buffer + buf_pos, src3_len);
                buf_pos += src3_len;

                memcpy(&dst_len, req->buffer + buf_pos, INT32_LENGTH);
                buf_pos += INT32_LENGTH;

                memcpy(dst, req->buffer + buf_pos, dst_len);
                buf_pos += dst_len;

                req->resp = enc_text_substring(
                    src1, src_len, in1, src2_len, in2, src3_len, dst, &dst_len);

                memcpy(req->buffer + buf_pos, &dst_len, INT32_LENGTH);
                buf_pos += INT32_LENGTH;

                memcpy(req->buffer + buf_pos, dst, dst_len);
                buf_pos = 0;
                break;

            case CMD_STRING_CONCAT:
                memcpy(&src_len, req->buffer + buf_pos, INT32_LENGTH);
                buf_pos += INT32_LENGTH;

                memcpy(src1, req->buffer + buf_pos, src_len);
                buf_pos += src_len;

                memcpy(&src2_len, req->buffer + buf_pos, INT32_LENGTH);
                buf_pos += INT32_LENGTH;

                memcpy(src2, req->buffer + buf_pos, src2_len);
                buf_pos += src2_len;

                dst_len = src_len + src2_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

                req->resp = enc_text_concatenate(src1, src_len, src2, src2_len, dst, dst_len);
                memcpy(req->buffer + buf_pos, &dst_len, INT32_LENGTH);
                buf_pos += INT32_LENGTH;

                memcpy(req->buffer + buf_pos, dst, dst_len);
                buf_pos = 0;
                break;

            case CMD_TIMESTAMP_EXTRACT_YEAR:
                req->resp = enc_timestamp_extract_year(req->buffer,
                                                       ENC_TIMESTAMP_LENGTH,
                                                       req->buffer + ENC_TIMESTAMP_LENGTH,
                                                       ENC_INT32_LENGTH);
                break;

            case CMD_TIMESTAMP_CMP:
                req->resp = enc_timestamp_cmp(req->buffer,
                                              ENC_TIMESTAMP_LENGTH,
                                              req->buffer + ENC_TIMESTAMP_LENGTH,
                                              ENC_TIMESTAMP_LENGTH,
                                              req->buffer + 2 * ENC_TIMESTAMP_LENGTH,
                                              INT32_LENGTH);
                break;

            case CMD_TIMESTAMP_ENC:
                req->resp = encrypt_bytes(req->buffer,
                                          TIMESTAMP_LENGTH,
                                          req->buffer + TIMESTAMP_LENGTH,
                                          ENC_TIMESTAMP_LENGTH);
                break;

            case CMD_TIMESTAMP_DEC:
                req->resp = decrypt_bytes(req->buffer,
                                          ENC_TIMESTAMP_LENGTH,
                                          req->buffer + ENC_TIMESTAMP_LENGTH,
                                          TIMESTAMP_LENGTH);
                break;
            }
            req->is_done = 1;
        }
    }

    return 0;
}
