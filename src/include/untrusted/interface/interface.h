#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "enclave_u.h"

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif


#define TOKEN_FILENAME   "/usr/local/lib/stealthdb/enclave.token"
#define ENCLAVE_FILENAME "/usr/local/lib/stealthdb/enclave.signed.so"
#define DATA_FILENAME "/usr/local/lib/stealthdb/stealthDB.data"


#if defined(__cplusplus)
extern "C" {
#endif
extern sgx_enclave_id_t global_eid;    /* global enclave id */

int generateKey();
int loadKey(int item);

int initMultithreading();
int enc_int32_add(char *int1, char *int2, char *res);
int enc_int32_sub(char *int1, char *int2, char *res);
int enc_int32_mult(char *int1, char *int2, char *res);
int enc_int32_div(char *int1, char *int2, char *res);
int enc_int32_pow(char *int1, char *int2, char *res);
int enc_int32_mod(char *int1, char *int2, char *res);
int enc_int32_cmp(char *int1, char *int2, char *res);
int enc_int32_encrypt(int pSrc, char *pDst);
int enc_int32_decrypt(char *pSrc, char *pDst);

int enc_text_cmp(char *arg1, size_t arg1_len, char *arg2, size_t arg2_len, char *res);
int enc_text_concatenate(char *arg1, size_t arg1_len, char *arg2, size_t arg2_len, char *dst, size_t* dst_len);
int enc_text_substring(char * arg1, size_t arg1_len, char *arg2, size_t arg2_len, char *res);
int enc_text_encrypt(char* arg1, size_t arg1_len, char* res, size_t dst_len);
int enc_text_decrypt(char* arg1, size_t arg1_len, char* res, size_t dst_len);

int enc_float32_cmp(char *int1, char *int2, char *res);
int enc_float32_encrypt(float pSrc, char *pDst);
int enc_float32_decrypt(char *pSrc, char *pDst);
int enc_float32_add(char *int1, char *int2, char *res);
int enc_float32_sub(char *int1, char *int2, char *res);
int enc_float32_mult(char *int1, char *int2, char *res);
int enc_float32_div(char *int1, char *int2, char *res);
int enc_float32_pow(char *int1, char *int2, char *res);
int enc_float32_mod(char *int1, char *int2, char *res);

int enc_timestamp_decrypt(char* src, char *dst);
int enc_timestamp_encrypt(char* src, char *dst);
int enc_timestamp_cmp(char* src1, char *src2, char *dst);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
