#include "untrusted/interface/interface.h"
#include "untrusted/interface/stdafx.h"
#include <unistd.h>

extern sgx_enclave_id_t global_eid;
extern Queue* inQueue;
extern bool status;

int enc_text_concatenate(char* src1,
                         size_t src1_len,
                         char* src2,
                         size_t src2_len,
                         char* dst,
                         size_t* dst_len)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    if (!status)
    {
        resp = initMultithreading();
        resp = loadKey(0);
    }

    int str3_len;
    int len_raw_str1, len_raw_str2, len_raw_str3;

    memcpy(&str3_len, dst_len, sizeof(uint8_t));

    uint8_t* str1 = new uint8_t[src1_len];
    uint8_t* str2 = new uint8_t[src2_len];
    uint8_t* str3 = new uint8_t[str3_len];

    request* req = new request;

    len_raw_str1 = FromBase64Fast((const BYTE*)src1, src1_len, str1, src1_len);
    len_raw_str2 = FromBase64Fast((const BYTE*)src2, src2_len, str2, src2_len);

    if (!len_raw_str1 || !len_raw_str2)
        return BASE64DECODER_ERROR;

    memcpy(req->buffer, &len_raw_str1, INT32_LENGTH);
    memcpy(req->buffer + INT32_LENGTH, str1, len_raw_str1);

    memcpy(
        req->buffer + len_raw_str1 + INT32_LENGTH, &len_raw_str2, INT32_LENGTH);
    memcpy(req->buffer + len_raw_str1 + INT32_LENGTH + INT32_LENGTH,
           str2,
           len_raw_str2);

    req->ocall_index = CMD_STRING_CONCAT;
    req->is_done = -1;

    inQueue->enqueue(req);

    while (true)
    {
        if (req->is_done == -1)
        {
            __asm__("pause");
        }
        else
        {
            memcpy(&len_raw_str3,
                   req->buffer + len_raw_str1 + 2 * INT32_LENGTH + len_raw_str2,
                   INT32_LENGTH);
            if (str3_len < len_raw_str3)
                return MEMORY_ALLOCATION_ERROR;

            memcpy(str3,
                   req->buffer + len_raw_str1 + 3 * INT32_LENGTH + len_raw_str2,
                   len_raw_str3);
            resp = req->resp;
            spin_unlock(&req->is_done);
            break;
        }
    }

    int dst_b64_len = ToBase64Fast((const unsigned char*)str3, len_raw_str3, dst, str3_len);
    if (!dst_b64_len)
        return BASE64DECODER_ERROR;
    dst[dst_b64_len] = '\0';
    memcpy(dst_len, &dst_b64_len, sizeof(uint8_t));

    delete[] str1;
    delete[] str2;
    delete[] str3;
    delete req;

    return resp;
}

int enc_text_substring(char* in1,
                       size_t in1_size,
                       char* in2,
                       size_t in2_size,
                       char* in3,
                       size_t in3_size,
                       char* out,
                       size_t* out_size)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    if (!status)
    {
        resp = initMultithreading();
        resp = loadKey(0);
    }

    request* req = new request;

    uint8_t* str = new uint8_t[in1_size];
    size_t str_size, in_size;

    uint8_t* from = new uint8_t[in2_size];
    uint8_t* n_chars = new uint8_t[in3_size];

    uint8_t* result = new uint8_t[*out_size];
    int result_raw_size = 0;

    int buf_pos = 0;

    str_size = FromBase64Fast((const unsigned char*)in1, in1_size, str, in1_size);
    if (!str_size)
        return BASE64DECODER_ERROR;

    if ((in2_size == INT32_LENGTH) && (in3_size == INT32_LENGTH))
    {
        memcpy(from, in2, in2_size);
        memcpy(n_chars, in3, in3_size);
        in_size = INT32_LENGTH;
    }
    else
    {
        if (!FromBase64Fast((const unsigned char*)in2,
                            ENC_INT32_LENGTH_B64 - 1,
                            from,
                            ENC_INT32_LENGTH))
            return BASE64DECODER_ERROR;

        if (!FromBase64Fast((const unsigned char*)in3,
                            ENC_INT32_LENGTH_B64 - 1,
                            n_chars,
                            ENC_INT32_LENGTH))
            return BASE64DECODER_ERROR;
        in_size = ENC_INT32_LENGTH;
    }

    memcpy(req->buffer + buf_pos, &str_size, INT32_LENGTH);
    buf_pos += INT32_LENGTH;

    memcpy(req->buffer + buf_pos, str, str_size);
    buf_pos += str_size;

    memcpy(req->buffer + buf_pos, &in_size, INT32_LENGTH);
    buf_pos += INT32_LENGTH;

    memcpy(req->buffer + buf_pos, from, in_size);
    buf_pos += in_size;

    memcpy(req->buffer + buf_pos, &in_size, INT32_LENGTH);
    buf_pos += INT32_LENGTH;

    memcpy(req->buffer + buf_pos, n_chars, in_size);
    buf_pos += in_size;

    memcpy(req->buffer + buf_pos, out_size, INT32_LENGTH);
    buf_pos += INT32_LENGTH;

    memcpy(req->buffer + buf_pos, out, *out_size);
    buf_pos += *out_size;

    req->ocall_index = CMD_STRING_SUBSTRING;
    req->is_done = -1;

    inQueue->enqueue(req);

    while (true)
    {
        if (req->is_done == -1)
        {
            __asm__("pause");
        }
        else
        {
            memcpy(&result_raw_size, req->buffer + buf_pos, INT32_LENGTH);
            buf_pos += INT32_LENGTH;
            memcpy(result, req->buffer + buf_pos, result_raw_size + 1);
            resp = req->resp;
            spin_unlock(&req->is_done);
            break;
        }
    }

    size_t result_b64_size = ToBase64Fast((const unsigned char*)result, result_raw_size, out, *out_size);
    if (!result_b64_size)
        return BASE64DECODER_ERROR;
    out[result_b64_size] = '\0';
    *out_size = result_b64_size;
    delete[] str;
    delete[] result;
    delete[] from;
    delete[] n_chars;
    delete req;

    return resp;
}

int enc_text_like(char* in1, size_t in1_size, char* in2, size_t in2_size, int* out)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    if (!status)
    {
        resp = initMultithreading();
        resp = loadKey(0);
    }

    request* req = new request;

    uint8_t* str = new uint8_t[in1_size];
    uint8_t* pattern = new uint8_t[in2_size];

    int str_raw_size = FromBase64Fast((const unsigned char*)in1, in1_size, str, in1_size);
    int pattern_raw_size = FromBase64Fast((const unsigned char*)in2, in2_size, pattern, in2_size);
    if (!str_raw_size || !pattern_raw_size)
        return BASE64DECODER_ERROR;

    size_t buf_pos = 0;
    memcpy(req->buffer + buf_pos, &str_raw_size, INT32_LENGTH);
    buf_pos += INT32_LENGTH;

    memcpy(req->buffer + buf_pos, str, str_raw_size);
    buf_pos += str_raw_size;

    memcpy(req->buffer + buf_pos, &pattern_raw_size, INT32_LENGTH);
    buf_pos += INT32_LENGTH;

    memcpy(req->buffer + buf_pos, pattern, pattern_raw_size);
    buf_pos += pattern_raw_size;

    req->ocall_index = CMD_STRING_LIKE;
    req->is_done = -1;

    inQueue->enqueue(req);

    while (true)
    {
        if (req->is_done == -1)
        {
            __asm__("pause");
        }
        else
        {
            resp = req->resp;
            std::copy(
                &req->buffer[buf_pos], &req->buffer[buf_pos + INT32_LENGTH], out);
            spin_unlock(&req->is_done);
            break;
        }
    }

    delete req;
    delete[] str;
    delete[] pattern;

    return resp;
}

int enc_text_encrypt(char* pSrc, size_t src_len, char* pDst, size_t dst_len)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    if (!status)
    {
        resp = initMultithreading();
        resp = loadKey(0);
    }

    int len, raw_dst_len;

    request* req = new request;
    uint8_t* dst = new uint8_t[dst_len + 1];

    memcpy(req->buffer, &src_len, INT32_LENGTH);
    memcpy(req->buffer + INT32_LENGTH, pSrc, src_len);

    req->ocall_index = CMD_STRING_ENC;
    req->is_done = -1;

    inQueue->enqueue(req);

    while (true)
    {
        if (req->is_done == -1)
        {
            __asm__("pause");
        }
        else
        {
            memcpy(&raw_dst_len, req->buffer + src_len + INT32_LENGTH, INT32_LENGTH);
            memcpy(dst, req->buffer + src_len + 2 * INT32_LENGTH, raw_dst_len);
            resp = req->resp;
            spin_unlock(&req->is_done);
            break;
        }
    }

    len = ToBase64Fast((const unsigned char*)dst, raw_dst_len, pDst, dst_len + 1);
    if (!len)
        return BASE64DECODER_ERROR;
    pDst[dst_len] = '\0';

    delete req;
    delete[] dst;

    return resp;
}
int enc_text_cmp(char* src1,
                 size_t src1_len,
                 char* src2,
                 size_t src2_len,
                 char* res)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    if (!status)
    {
        resp = initMultithreading();
        resp = loadKey(0);
    }

    request* req = new request;

    uint8_t* arg1 = new uint8_t[src1_len];
    uint8_t* arg2 = new uint8_t[src2_len];

    int len_raw_str1 = FromBase64Fast((const BYTE*)src1, src1_len, arg1, src1_len);
    int len_raw_str2 = FromBase64Fast((const BYTE*)src2, src2_len, arg2, src2_len);

    if (!len_raw_str1 || !len_raw_str2)
        return BASE64DECODER_ERROR;

    memcpy(req->buffer, &len_raw_str1, INT32_LENGTH);
    memcpy(req->buffer + INT32_LENGTH, arg1, len_raw_str1);
    memcpy(
        req->buffer + len_raw_str1 + INT32_LENGTH, &len_raw_str2, INT32_LENGTH);
    memcpy(req->buffer + len_raw_str1 + INT32_LENGTH + INT32_LENGTH,
           arg2,
           len_raw_str2);

    req->ocall_index = CMD_STRING_CMP;
    req->is_done = -1;

    inQueue->enqueue(req);

    while (true)
    {
        if (req->is_done == -1)
        {
            __asm__("pause");
        }
        else
        {
            resp = req->resp;
            std::copy(&req->buffer[len_raw_str1 + 2 * INT32_LENGTH + len_raw_str2],
                      &req->buffer[len_raw_str1 + 2 * INT32_LENGTH + len_raw_str2 + INT32_LENGTH],
                      &res[0]);
            spin_unlock(&req->is_done);
            break;
        }
    }

    delete req;
    delete[] arg1;
    delete[] arg2;

    return resp;
}

int enc_text_decrypt(char* pSrc, size_t src_len, char* pDst, size_t dst_len)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    if (!status)
    {
        resp = initMultithreading();
        resp = loadKey(0);
    }

    int src_decrypted_len, src_bytearray_len;
    request* req = new request;
    uint8_t* dst = new uint8_t[src_len];

    src_bytearray_len = FromBase64Fast((const BYTE*)pSrc, src_len, dst, src_len);
    src_decrypted_len = src_bytearray_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

    if (src_decrypted_len > dst_len)
        return MEMORY_ALLOCATION_ERROR;

    memcpy(req->buffer, &src_bytearray_len, INT32_LENGTH);
    memcpy(req->buffer + INT32_LENGTH, dst, src_bytearray_len);

    req->ocall_index = CMD_STRING_DEC;
    req->is_done = -1;

    inQueue->enqueue(req);

    while (true)
    {
        if (req->is_done == -1)
        {
            __asm__("pause");
        }
        else
        {
            memcpy(
                &dst_len, req->buffer + src_bytearray_len + INT32_LENGTH, INT32_LENGTH);
            memcpy(pDst,
                   req->buffer + src_bytearray_len + 2 * INT32_LENGTH,
                   src_bytearray_len);
            resp = req->resp;
            spin_unlock(&req->is_done);
            break;
        }
    }

    pDst[dst_len] = '\0';

    delete req;
    delete[] dst;

    return resp;
}
