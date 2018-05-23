#pragma once

#include "sgx_eid.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include <assert.h>
#include <stdlib.h>

#include "math.h"
#include <stdio.h>
#include <string.h>

#include "defs.h"
#include "enclave/Queue.hpp"
#include "enclave/enc_float32_ops.hpp"
#include "enclave/enc_int32_ops.hpp"
#include "enclave/enc_text_ops.hpp"
#include "enclave/enc_timestamp_ops.hpp"
#include "tools/sync_utils.hpp"

#if defined(__cplusplus)
extern "C"
{
#endif

    void free_allocated_memory(void* pointer);

    // FUNCTIONS
    int decrypt_bytes(uint8_t* pSrc, size_t srcLen, uint8_t* pDst, size_t dstLen);
    int encrypt_bytes(uint8_t* pSrc, size_t srcLen, uint8_t* pDst, size_t dstLen);
#if defined(__cplusplus)
}
#endif
