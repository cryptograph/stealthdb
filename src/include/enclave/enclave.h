#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include "sgx_eid.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#include "math.h"
#include <string.h>
#include <vector>
#include <stdio.h>

#include "enclave/Queue.h"
#include "utils/SyncUtils.h"
#include "defs.h"
#include "enclave/enc_float32_ops.h"
#include "enclave/enc_int32_ops.h"
#include "enclave/enc_text_ops.h"
#include "enclave/enc_timestamp_ops.h"

#if defined(__cplusplus)
extern "C" {
#endif

void free_allocated_memory(void *pointer);

// FUNCTIONS
int decrypt_bytes(uint8_t *pSrc, size_t srcLen, uint8_t *pDst, size_t dstLen);
int encrypt_bytes(uint8_t *pSrc, size_t srcLen, uint8_t *pDst, size_t dstLen);;
#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
