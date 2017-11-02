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

#include "../common/Queue.h"
#include "../common/SyncUtils.h"
#include "../common/def.h"


#if defined(__cplusplus)
extern "C" {
#endif

void free_allocated_memory(void *pointer);

// FUNCTIONS
int encryptGCM(uint8_t *pSrc, size_t srcLen, uint8_t *pDst, size_t dstLen);
int decryptGCM(uint8_t *pSrc, size_t srcLen, uint8_t *pDst, size_t dstLen);
#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
