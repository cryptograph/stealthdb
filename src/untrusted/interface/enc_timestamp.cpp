#include "untrusted/interface/interface.h"
#include "untrusted/interface/stdafx.h"

extern sgx_enclave_id_t global_eid;
extern Queue* inQueue;
extern bool status;

int enc_timestamp_extract_year(char* in, char* result)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
    }
    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;
    size_t buf_pos = 0;
    std::array<BYTE, ENC_TIMESTAMP_LENGTH> timestamp;

    if (!FromBase64Fast((const BYTE*)in,
                        ENC_TIMESTAMP_LENGTH_B64 - 1,
                        timestamp.begin(),
                        ENC_TIMESTAMP_LENGTH))
        return BASE64DECODER_ERROR;

    std::copy(timestamp.begin(), timestamp.end(), &req->buffer[buf_pos]);
    buf_pos += ENC_TIMESTAMP_LENGTH;

    req->ocall_index = CMD_TIMESTAMP_EXTRACT_YEAR;
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
            if (!ToBase64Fast((const BYTE*)&req->buffer[buf_pos],
                              ENC_INT32_LENGTH,
                              result,
                              ENC_INT32_LENGTH_B64))
                resp = BASE64DECODER_ERROR;

            spin_unlock(&req->is_done);
            break;
        }
    }
    delete req;
    return resp;
}

int enc_timestamp_cmp(char* src1, char* src2, char* res)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //      return resp;//IS_NOT_INITIALIZE;
    }
    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;

    std::array<BYTE, ENC_TIMESTAMP_LENGTH> src1_decoded;
    std::array<BYTE, ENC_TIMESTAMP_LENGTH> src2_decoded;

    if (!FromBase64Fast((const BYTE*)src1,
                        ENC_TIMESTAMP_LENGTH_B64 - 1,
                        src1_decoded.begin(),
                        ENC_TIMESTAMP_LENGTH))
        return BASE64DECODER_ERROR;

    if (!FromBase64Fast((const BYTE*)src2,
                        ENC_TIMESTAMP_LENGTH_B64 - 1,
                        src2_decoded.begin(),
                        ENC_TIMESTAMP_LENGTH))
        return BASE64DECODER_ERROR;

    std::copy(src1_decoded.begin(), src1_decoded.end(), &req->buffer[0]);
    std::copy(src2_decoded.begin(),
              src2_decoded.end(),
              &req->buffer[ENC_TIMESTAMP_LENGTH]);

    req->ocall_index = CMD_TIMESTAMP_CMP;
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
            std::copy(&req->buffer[2 * ENC_TIMESTAMP_LENGTH],
                      &req->buffer[2 * ENC_TIMESTAMP_LENGTH + INT32_LENGTH],
                      &res[0]);
            spin_unlock(&req->is_done);
            break;
        }
    }
    delete req;

    return resp;
}

int enc_timestamp_encrypt(char* src, char* dst)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //      return resp;//IS_NOT_INITIALIZE;
    }

    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;
    std::array<BYTE, ENC_TIMESTAMP_LENGTH> src_encrypted;

    memcpy(req->buffer, src, TIMESTAMP_LENGTH);
    req->ocall_index = CMD_TIMESTAMP_ENC;
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
            std::copy(&req->buffer[TIMESTAMP_LENGTH],
                      &req->buffer[TIMESTAMP_LENGTH + ENC_TIMESTAMP_LENGTH],
                      src_encrypted.begin());
            resp = req->resp;
            spin_unlock(&req->is_done);
            break;
        }
    }

    if (!ToBase64Fast((const BYTE*)src_encrypted.begin(),
                      ENC_TIMESTAMP_LENGTH,
                      dst,
                      ENC_TIMESTAMP_LENGTH_B64))
        return BASE64DECODER_ERROR;

    dst[ENC_TIMESTAMP_LENGTH_B64 - 1] = '\0';

    delete req;
    return resp;
}

int enc_timestamp_decrypt(char* src, char* dst)
{
    if (!status)
    {
        int resp = initMultithreading();
        resp = loadKey(0);
        //      return resp;//IS_NOT_INITIALIZE;
    }

    int resp = ENCLAVE_IS_NOT_RUNNING;
    request* req = new request;

    std::array<BYTE, ENC_TIMESTAMP_LENGTH> src_decoded;
    if (!FromBase64Fast((const BYTE*)src,
                        ENC_TIMESTAMP_LENGTH_B64 - 1,
                        src_decoded.begin(),
                        ENC_TIMESTAMP_LENGTH))
        return BASE64DECODER_ERROR;

    std::copy(src_decoded.begin(), src_decoded.end(), req->buffer);
    req->ocall_index = CMD_TIMESTAMP_DEC;
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
            std::copy(&req->buffer[ENC_TIMESTAMP_LENGTH],
                      &req->buffer[ENC_TIMESTAMP_LENGTH + TIMESTAMP_LENGTH],
                      dst);
            resp = req->resp;
            spin_unlock(&req->is_done);
            break;
        }
    }

    delete req;
    return resp;
}
