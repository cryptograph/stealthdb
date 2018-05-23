#include "untrusted/interface/interface.h"
#include "untrusted/interface/stdafx.h"

extern sgx_enclave_id_t global_eid;
extern Queue* inQueue;
extern bool status;

int enc_int32_sum_bulk(size_t bulk_size, char* arg1, char* res)
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

    uint8_t* int2_v = (uint8_t*)malloc(bulk_size * ENC_INT32_LENGTH);
    uint8_t* int3_v = (uint8_t*)malloc(ENC_INT32_LENGTH);

    memcpy(req->buffer, &bulk_size, INT32_LENGTH);
    current_position += INT32_LENGTH;

    size_t counter = 0;

    if (req->max_buffer_size < bulk_size * ENC_INT32_LENGTH)
        return TOO_MANY_ELEMENTS_IN_BULK;

    while (counter < bulk_size)
    {
        if (!FromBase64Fast((const BYTE*)arg1 + arg_position,
                            ENC_INT32_LENGTH_B64 - 1,
                            int2_v,
                            ENC_INT32_LENGTH))
            return BASE64DECODER_ERROR;

        memcpy(req->buffer + current_position, int2_v, ENC_INT32_LENGTH);
        current_position += ENC_INT32_LENGTH;
        arg_position += ENC_INT32_LENGTH_B64;
        counter++;
    }

    req->ocall_index = CMD_INT32_SUM_BULK;
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
            memcpy(int3_v, req->buffer + current_position, ENC_INT32_LENGTH);
            resp = req->resp;
            if (!ToBase64Fast(
                    (const BYTE*)int3_v, ENC_INT32_LENGTH, res, ENC_INT32_LENGTH_B64))
                resp = BASE64DECODER_ERROR;
            spin_unlock(&req->is_done);
            break;
        }
    }

    delete req;

    return resp;
}

int enc_int32_ops(int cmd, char* int1, char* int2, char* res)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //  return resp;//IS_NOT_INITIALIZE;
    }

    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;

    std::array<BYTE, ENC_INT32_LENGTH> int1_v;
    std::array<BYTE, ENC_INT32_LENGTH> int2_v;
    std::array<BYTE, ENC_INT32_LENGTH> int3_v;

    if (!FromBase64Fast((const BYTE*)int1,
                        ENC_INT32_LENGTH_B64 - 1,
                        int1_v.begin(),
                        ENC_INT32_LENGTH))
        return BASE64DECODER_ERROR;

    if (!FromBase64Fast((const BYTE*)int2,
                        ENC_INT32_LENGTH_B64 - 1,
                        int2_v.begin(),
                        ENC_INT32_LENGTH))
        return BASE64DECODER_ERROR;

    std::copy(int1_v.begin(), int1_v.end(), &req->buffer[0]);
    std::copy(int2_v.begin(), int2_v.end(), &req->buffer[ENC_INT32_LENGTH]);

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
            std::copy(&req->buffer[2 * ENC_INT32_LENGTH],
                      &req->buffer[3 * ENC_INT32_LENGTH],
                      int3_v.begin());
            resp = req->resp;
            if (!ToBase64Fast((const BYTE*)int3_v.begin(),
                              ENC_INT32_LENGTH,
                              res,
                              ENC_INT32_LENGTH_B64))
                resp = BASE64DECODER_ERROR;
            spin_unlock(&req->is_done);
            break;
        }
    }

    delete req;

    return resp;
}

int enc_int32_add(char* int1, char* int2, char* res)
{
    return enc_int32_ops(CMD_INT64_PLUS, int1, int2, res);
}

int enc_int32_sub(char* int1, char* int2, char* res)
{
    int resp = enc_int32_ops(CMD_INT64_MINUS, int1, int2, res);
    return resp;
}

int enc_int32_mult(char* int1, char* int2, char* res)
{
    int resp = enc_int32_ops(CMD_INT64_MULT, int1, int2, res);
    return resp;
}

int enc_int32_div(char* int1, char* int2, char* res)
{
    int resp = enc_int32_ops(CMD_INT64_DIV, int1, int2, res);
    return resp;
}

int enc_int32_pow(char* int1, char* int2, char* res)
{
    int resp = enc_int32_ops(CMD_INT64_EXP, int1, int2, res);
    return resp;
}

int enc_int32_mod(char* int1, char* int2, char* res)
{
    int resp = enc_int32_ops(CMD_INT64_MOD, int1, int2, res);
    return resp;
}

int enc_int32_cmp(char* int1, char* int2, char* res)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //      return resp;//IS_NOT_INITIALIZE;
    }
    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;

    std::array<BYTE, ENC_INT32_LENGTH> int1_v;
    std::array<BYTE, ENC_INT32_LENGTH> int2_v;

    if (!FromBase64Fast((const BYTE*)int1,
                        ENC_INT32_LENGTH_B64 - 1,
                        int1_v.begin(),
                        ENC_INT32_LENGTH))
        return BASE64DECODER_ERROR;

    if (!FromBase64Fast((const BYTE*)int2,
                        ENC_INT32_LENGTH_B64 - 1,
                        int2_v.begin(),
                        ENC_INT32_LENGTH))
        return BASE64DECODER_ERROR;

    std::copy(int1_v.begin(), int1_v.end(), &req->buffer[0]);
    std::copy(int2_v.begin(), int2_v.end(), &req->buffer[ENC_INT32_LENGTH]);

    req->ocall_index = CMD_INT64_CMP;
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
            std::copy(&req->buffer[2 * ENC_INT32_LENGTH],
                      &req->buffer[2 * ENC_INT32_LENGTH + INT32_LENGTH],
                      &res[0]);
            spin_unlock(&req->is_done);
            break;
        }
    }
    delete req;
    return resp;
}

int enc_int32_encrypt(int pSrc, char* pDst)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //      return resp;//IS_NOT_INITIALIZE;
    }

    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;
    std::array<BYTE, ENC_INT32_LENGTH> int1_v;

    memcpy(req->buffer, &pSrc, INT32_LENGTH);
    req->ocall_index = CMD_INT64_ENC;
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
            std::copy(&req->buffer[INT32_LENGTH],
                      &req->buffer[INT32_LENGTH + ENC_INT32_LENGTH],
                      int1_v.begin());
            resp = req->resp;
            // spin_unlock(&req->is_done);
            break;
        }
    }

    if (!ToBase64Fast((const BYTE*)int1_v.begin(),
                      ENC_INT32_LENGTH,
                      pDst,
                      ENC_INT32_LENGTH_B64))
        resp = BASE64DECODER_ERROR;
    pDst[ENC_INT32_LENGTH_B64 - 1] = '\0';

    delete req;
    return resp;
}

int enc_int32_decrypt(char* pSrc, char* pDst)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //      return resp;//IS_NOT_INITIALIZE;
    }

    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;

    std::array<BYTE, ENC_INT32_LENGTH> int1_v;
    if (!FromBase64Fast((const BYTE*)pSrc,
                        ENC_INT32_LENGTH_B64 - 1,
                        int1_v.begin(),
                        ENC_INT32_LENGTH))
        return BASE64DECODER_ERROR;

    std::copy(int1_v.begin(), int1_v.end(), &req->buffer[0]);
    req->ocall_index = CMD_INT64_DEC;
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
            std::copy(&req->buffer[ENC_INT32_LENGTH],
                      &req->buffer[ENC_INT32_LENGTH + INT32_LENGTH],
                      &pDst[0]);
            resp = req->resp;
            spin_unlock(&req->is_done);
            break;
        }
    }

    delete req;
    return resp;
}
