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
int enc_int32_sum_bulk(size_t bulk_size, char *arg1, char *res);

int enc_text_cmp(char *arg1, size_t arg1_len, char *arg2, size_t arg2_len, char *res);
int enc_text_concatenate(char *arg1, size_t arg1_len, char *arg2, size_t arg2_len, char *dst, size_t* dst_len);
int enc_text_substring(char* in1, size_t in1_size, char* in2, size_t in2_size, char* in3, size_t in3_size, char* out, size_t* out_size);

int enc_text_like(char* in1, size_t in1_size, char* in2, size_t in2_size, int* out);

int enc_text_encrypt(char* arg1, size_t arg1_len, char* res, size_t dst_len);
int enc_text_decrypt(char* arg1, size_t arg1_len, char* res, size_t dst_len);

int enc_float32_cmp(char *arg1, char *arg2, char *res);
int enc_float32_encrypt(float pSrc, char *pDst);
int enc_float32_decrypt(char *pSrc, char *pDst);
int enc_float32_add(char *arg1, char *arg2, char *res);
int enc_float32_sub(char *arg1, char *arg2, char *res);
int enc_float32_mult(char *arg1, char *arg2, char *res);
int enc_float32_div(char *arg1, char *arg2, char *res);
int enc_float32_pow(char *arg1, char *arg2, char *res);
int enc_float32_mod(char *arg1, char *arg2, char *res);
int enc_float32_sum_bulk(size_t bulk_size, char *arg1, char *res);

int enc_timestamp_decrypt(char* src, char *dst);
int enc_timestamp_encrypt(char* src, char *dst);
int enc_timestamp_cmp(char* src1, char *src2, char *dst);
int enc_timestamp_extract_year(char* in, char* out);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
