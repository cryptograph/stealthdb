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
int plusInt64(char *int1, char *int2, char *res);
int minusInt64(char *int1, char *int2, char *res);
int multInt64(char *int1, char *int2, char *res);
int divInt64(char *int1, char *int2, char *res);
int expInt64(char *int1, char *int2, char *res);
int modInt64(char *int1, char *int2, char *res);
int compareInt64(char *int1, char *int2, char *res);
int encryptInt64(int pSrc, char *pDst);
int decryptInt64(char *pSrc, char *pDst);

int compareEncString(char * int1, char *int2, int *res);
int concatEncString(char * int1, char *int2, char *res);
int substringEncString(char * int1, char *int2, int *res);
int encryptString(char* int1, char* res);
int decryptString(char* int1, char* res);

int compareFloat4(char *int1, char *int2, int *res);
int encryptFloat4(float pSrc, char *pDst);
int decryptFloat4(char *pSrc, float *pDst);
int plusFloat4(char *int1, char *int2, char *res);
int minusFloat4(char *int1, char *int2, char *res);
int multFloat4(char *int1, char *int2, char *res);
int divFloat4(char *int1, char *int2, char *res);
int expFloat4(char *int1, char *int2, char *res);
int modFloat4(char *int1, char *int2, char *res);

int decryptTimestamp(char* pSrc, double *dst);
int encryptTimestamp(double src, char *pDst);
int compareTimestamp(char* src1, char *src2, int *res);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
