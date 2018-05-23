#include "untrusted/interface/interface.h"
#include "untrusted/interface/stdafx.h"
#include <algorithm> // for copy
#include <unistd.h>

extern sgx_enclave_id_t global_eid;
extern Queue* inQueue;
extern bool status;

int enc_float32_sum_bulk(size_t bulk_size, char* arg1, char* res)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //  return resp;//IS_NOT_INITIALIZE;
    }
    int current_position = 0, arg_position = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;

    uint8_t* int2_v = (uint8_t*)malloc(bulk_size * ENC_FLOAT4_LENGTH);
    uint8_t* int3_v = (uint8_t*)malloc(ENC_FLOAT4_LENGTH);

    memcpy(req->buffer, &bulk_size, FLOAT4_LENGTH);
    current_position += FLOAT4_LENGTH;

    size_t counter = 0;

    if (req->max_buffer_size < bulk_size * ENC_FLOAT4_LENGTH)
        return TOO_MANY_ELEMENTS_IN_BULK;

    while (counter < bulk_size)
    {
        if (!FromBase64Fast((const BYTE*)arg1 + arg_position,
                            ENC_FLOAT4_LENGTH_B64 - 1,
                            int2_v,
                            ENC_FLOAT4_LENGTH))
            return BASE64DECODER_ERROR;

        memcpy(req->buffer + current_position, int2_v, ENC_FLOAT4_LENGTH);
        current_position += ENC_FLOAT4_LENGTH;
        arg_position += ENC_FLOAT4_LENGTH_B64;
        counter++;
    }

    req->ocall_index = CMD_FLOAT4_SUM_BULK;
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
            memcpy(int3_v, req->buffer + current_position, ENC_FLOAT4_LENGTH);
            resp = req->resp;
            if (!ToBase64Fast(
                    (const BYTE*)int3_v, ENC_FLOAT4_LENGTH, res, ENC_FLOAT4_LENGTH_B64))
                resp = BASE64DECODER_ERROR;
            spin_unlock(&req->is_done);
            break;
        }
    }

    delete req;
    return resp;
}

int enc_float32_ops(int cmd, char* src1, char* src2, char* res)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //  return resp;//IS_NOT_INITIALIZE;
    }

    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;

    std::array<BYTE, ENC_FLOAT4_LENGTH> src1_decoded;
    std::array<BYTE, ENC_FLOAT4_LENGTH> src2_decoded;
    std::array<BYTE, ENC_FLOAT4_LENGTH> dst_decoded;

    if (!FromBase64Fast((const BYTE*)src1,
                        ENC_FLOAT4_LENGTH_B64 - 1,
                        src1_decoded.begin(),
                        ENC_FLOAT4_LENGTH))
        return BASE64DECODER_ERROR;

    if (!FromBase64Fast((const BYTE*)src2,
                        ENC_FLOAT4_LENGTH_B64 - 1,
                        src2_decoded.begin(),
                        ENC_FLOAT4_LENGTH))
        return BASE64DECODER_ERROR;

    std::copy(src1_decoded.begin(), src1_decoded.end(), &req->buffer[0]);
    std::copy(
        src2_decoded.begin(), src2_decoded.end(), &req->buffer[ENC_FLOAT4_LENGTH]);

    req->ocall_index = cmd;
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
            std::copy(&req->buffer[2 * ENC_FLOAT4_LENGTH],
                      &req->buffer[3 * ENC_FLOAT4_LENGTH],
                      dst_decoded.begin());
            resp = req->resp;
            if (!ToBase64Fast((const BYTE*)dst_decoded.begin(),
                              ENC_FLOAT4_LENGTH,
                              res,
                              ENC_FLOAT4_LENGTH_B64))
                resp = BASE64DECODER_ERROR;
            spin_unlock(&req->is_done);
            break;
        }
    }

    delete req;
    return resp;
}

int enc_float32_add(char* src1, char* src2, char* res)
{
    int resp = enc_float32_ops(CMD_FLOAT4_PLUS, src1, src2, res);
    return resp;
}

int enc_float32_sub(char* src1, char* src2, char* res)
{
    int resp = enc_float32_ops(CMD_FLOAT4_MINUS, src1, src2, res);
    return resp;
}

int enc_float32_mult(char* src1, char* src2, char* res)
{
    int resp = enc_float32_ops(CMD_FLOAT4_MULT, src1, src2, res);
    return resp;
}

int enc_float32_div(char* src1, char* src2, char* res)
{
    int resp = enc_float32_ops(CMD_FLOAT4_DIV, src1, src2, res);
    return resp;
}

int enc_float32_pow(char* src1, char* src2, char* res)
{
    int resp = enc_float32_ops(CMD_FLOAT4_EXP, src1, src2, res);
    return resp;
}

int enc_float32_mod(char* src1, char* src2, char* res)
{
    int resp = enc_float32_ops(CMD_FLOAT4_MOD, src1, src2, res);
    return resp;
}

int enc_float32_cmp(char* src1, char* src2, char* res)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //  return resp;//IS_NOT_INITIALIZE;
    }

    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;

    std::array<BYTE, ENC_FLOAT4_LENGTH> src1_decoded;
    std::array<BYTE, ENC_FLOAT4_LENGTH> src2_decoded;

    if (!FromBase64Fast((const BYTE*)src1,
                        ENC_FLOAT4_LENGTH_B64 - 1,
                        src1_decoded.begin(),
                        ENC_FLOAT4_LENGTH))
        return BASE64DECODER_ERROR;

    if (!FromBase64Fast((const BYTE*)src2,
                        ENC_FLOAT4_LENGTH_B64 - 1,
                        src2_decoded.begin(),
                        ENC_FLOAT4_LENGTH))
        return BASE64DECODER_ERROR;

    std::copy(src1_decoded.begin(), src1_decoded.end(), &req->buffer[0]);
    std::copy(
        src2_decoded.begin(), src2_decoded.end(), &req->buffer[ENC_FLOAT4_LENGTH]);
    req->ocall_index = CMD_FLOAT4_CMP;
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
            std::copy(&req->buffer[2 * ENC_FLOAT4_LENGTH],
                      &req->buffer[2 * ENC_FLOAT4_LENGTH + FLOAT4_LENGTH],
                      &res[0]);
            spin_unlock(&req->is_done);

            // res[0] = req->ocall_index;
            break;
        }
    }
    delete req;

    return resp;
}

int enc_float32_encrypt(float pSrc, char* pDst)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //  return resp;//IS_NOT_INITIALIZE;
    }

    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request();
    std::array<BYTE, ENC_FLOAT4_LENGTH> encrypted_src;

    memcpy(req->buffer, &pSrc, FLOAT4_LENGTH);
    req->ocall_index = CMD_FLOAT4_ENC;
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
            std::copy(&req->buffer[FLOAT4_LENGTH],
                      &req->buffer[FLOAT4_LENGTH + ENC_FLOAT4_LENGTH],
                      encrypted_src.begin());
            resp = req->resp;
            spin_unlock(&req->is_done);
            break;
        }
    }

    if (!ToBase64Fast((const BYTE*)encrypted_src.begin(),
                      ENC_FLOAT4_LENGTH,
                      pDst,
                      ENC_FLOAT4_LENGTH_B64))
        resp = BASE64DECODER_ERROR;

    pDst[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';
    delete req;

    return resp;
}

int enc_float32_decrypt(char* pSrc, char* pDst)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //  return resp;//IS_NOT_INITIALIZE;
    }

    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;

    std::array<BYTE, ENC_FLOAT4_LENGTH> src_decoded;
    if (!FromBase64Fast((const BYTE*)pSrc,
                        ENC_FLOAT4_LENGTH_B64 - 1,
                        src_decoded.begin(),
                        ENC_FLOAT4_LENGTH))
        return BASE64DECODER_ERROR;

    std::copy(src_decoded.begin(), src_decoded.end(), &req->buffer[0]);
    req->ocall_index = CMD_FLOAT4_DEC;
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
            std::copy(&req->buffer[ENC_FLOAT4_LENGTH],
                      &req->buffer[ENC_FLOAT4_LENGTH + FLOAT4_LENGTH],
                      &pDst[0]);
            resp = req->resp;
            spin_unlock(&req->is_done);
            break;
        }
    }

    delete req;

    return resp;
}
