#include "stdafx.h"
#include "interface.h"
#include <unistd.h>

extern sgx_enclave_id_t global_eid;
extern Queue* inQueue;
extern bool status;

/////////////////////////////////////////////////////////
// FUNCTIONS DISCRIBING ENCRYPTED STRINGS
//////////////////////////////////////////////////////////

int concatEncString(char * str1, char *str2, char *res) {
	if (!status)
		return IS_NOT_INITIALIZE;
	
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *raw_str1, *raw_str2, *raw_str3, *dst_b64;
	int len_raw_str1, len_raw_str2, len_raw_str3;

	int len_str1 = strlen(str1);
	int len_str2 = strlen(str2);
	request* req = new request;

	try {
		raw_str1 = new char[len_str1];
		raw_str2 = new char[len_str2];
		// TODO: the real size is less than it is nesseccary
		raw_str3 = new char[len_str1 + len_str2];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	// decode arrays from base64 forms to byte arrays
	len_raw_str1 = FromBase64Fast((const BYTE*) str1, len_str1, (raw_str1), len_str1);
	len_raw_str2 = FromBase64Fast((const BYTE*) str2, len_str2, (raw_str2), len_str2);
	len_raw_str3 = len_raw_str1 + len_raw_str2 - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	
	if (!len_raw_str1 || !len_raw_str2)
		return BASE64DECODER_ERROR;



	memcpy(req->buffer, &len_raw_str1, INT_LENGTH);
	memcpy(req->buffer + INT_LENGTH, raw_str1, len_raw_str1);

	memcpy(req->buffer + len_raw_str1 + INT_LENGTH, &len_raw_str2, INT_LENGTH);
	memcpy(req->buffer + len_raw_str1 + INT_LENGTH + INT_LENGTH, raw_str2, len_raw_str2);

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
				memcpy(&len_raw_str3, req->buffer, INT_LENGTH);
				memcpy(raw_str3, req->buffer + INT_LENGTH, len_raw_str3);
				//res[0] = req->ocall_index;
				spin_unlock(&req->is_done);
				break;
			}
	}

	int dst_b64_len = (((4 * len_raw_str3 / 3) + 3) & ~3) + 1 ;
	
	try {
		dst_b64 = new char[dst_b64_len + 1];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	dst_b64_len = ToBase64Fast((const unsigned char*) raw_str3, len_raw_str3, res, dst_b64_len);
	if (!dst_b64_len)
		return BASE64DECODER_ERROR;
	res[dst_b64_len] = '\0';
	
	delete raw_str1;
	delete raw_str2;
	delete raw_str3;

	return 0;
}

int substringEncString(char * str1, char *str2, int *res) {
	if (!status)
		return IS_NOT_INITIALIZE;
	
	int resp = ENCLAVE_IS_NOT_RUNNIG;	
	char *raw_str1, *raw_str2, *answer;
	int len_raw_str1, len_raw_str2, dst_len = 1;

	int len_str1 = strlen(str1);
	int len_str2 = strlen(str2);
	request* req = new request;

	try {
		raw_str1 = new char[len_str1];
		raw_str2 = new char[len_str2];
		answer = new char[dst_len];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	// decode arrays from base64 forms to byte arrays
	len_raw_str1 = FromBase64Fast((const BYTE*) str1, len_str1, (raw_str1), len_str1);
	len_raw_str2 = FromBase64Fast((const BYTE*) str2, len_str2, (raw_str2), len_str2);
	
	if (!len_raw_str1 || !len_raw_str2)
		return BASE64DECODER_ERROR;


	memcpy(req->buffer, &len_raw_str1, INT_LENGTH);
	memcpy(req->buffer + INT_LENGTH, raw_str1, len_raw_str1);

	memcpy(req->buffer + len_raw_str1 + INT_LENGTH, &len_raw_str2, INT_LENGTH);
	memcpy(req->buffer + len_raw_str1 + INT_LENGTH + INT_LENGTH, raw_str2, len_raw_str2);

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
				//memcpy(&dst_len, req->buffer, INT_LENGTH);
				//memcpy(answer, req->buffer + INT_LENGTH, dst_len);
				res[0] = req->ocall_index;
				spin_unlock(&req->is_done);
				break;
			}
	}

	delete raw_str1;
	delete raw_str2;
	delete answer;
	delete req;

	return 0;


}

int compareEncString(char *src1, char *src2, int *res) {

	if (!status)
		return IS_NOT_INITIALIZE;

	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *raw_str1, *raw_str2, *answer;
	int len_raw_str1, len_raw_str2, dst_len = 1;

	request* req = new request;


	int len_str1 = strlen(src1);
	int len_str2 = strlen(src2);

	try {
		raw_str1 = new char[len_str1];
		raw_str2 = new char[len_str2];
		answer = new char[dst_len];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	// decode arrays from base64 forms to byte arrays
	len_raw_str1 = FromBase64Fast((const BYTE*) src1, len_str1, (raw_str1), len_str1);
	len_raw_str2 = FromBase64Fast((const BYTE*) src2, len_str2, (raw_str2), len_str2);

	if (!len_raw_str1 || !len_raw_str2)
			return BASE64DECODER_ERROR;


	memcpy(req->buffer, &len_raw_str1, INT_LENGTH);
	memcpy(req->buffer+ INT_LENGTH, raw_str1, len_raw_str1);

	memcpy(req->buffer + len_raw_str1 + INT_LENGTH, &len_raw_str2, INT_LENGTH);
	memcpy(req->buffer + len_raw_str1 + INT_LENGTH + INT_LENGTH, raw_str2, len_raw_str2);

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
//						memcpy(&dst_len, req->buffer + len_raw_str1 + len_raw_str2 + 2*INT_LENGTH, INT_LENGTH);
//						memcpy(answer, req->buffer + len_raw_str1 + len_raw_str2 + 3*INT_LENGTH, dst_len);
						res[0] = req->ocall_index;
						spin_unlock(&req->is_done);
						break;
					}

				}

	delete req;
	delete raw_str1;
	delete raw_str2;
	delete answer;

	return 0;
}

int encryptString(char* pSrc, char *pDst) {
	if (!status)
		return IS_NOT_INITIALIZE;

	int len_src = strlen(pSrc);
	char *raw_dst;
	int resp, len;
	int raw_dst_len = len_src + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
	int dst_b64_len = (((4 * raw_dst_len / 3) + 3) & ~3) + 1 ;
	request* req = new request;

	try {
		raw_dst = new char[raw_dst_len];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}


	memcpy(req->buffer, &len_src, INT_LENGTH);
	memcpy(req->buffer+ INT_LENGTH, pSrc, len_src);

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
						memcpy(&raw_dst_len, req->buffer+ len_src + INT_LENGTH, INT_LENGTH);
						memcpy(raw_dst, req->buffer+ len_src + 2*INT_LENGTH, raw_dst_len);
//						res[0] = req->ocall_index;
						spin_unlock(&req->is_done);
						break;
					}

				}



	len = ToBase64Fast((const unsigned char*) raw_dst, raw_dst_len, pDst, dst_b64_len);
	if (!len)
			return BASE64DECODER_ERROR;

	pDst[len] = '\0';
	delete req;
	delete raw_dst;

	return 0;


}

int decryptString(char *pSrc, char *pDst) {
	if (!status)
		return IS_NOT_INITIALIZE;
	int resp, dst_len, len_int1_dec;
	int len_src = strlen(pSrc);
	char *raw_dst, *dst;
	request* req = new request;

	try {
		raw_dst = new char[len_src];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	len_int1_dec = FromBase64Fast((const BYTE*) pSrc, len_src, (raw_dst), len_src);
	dst_len = len_int1_dec - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

	try {
		dst = new char [dst_len];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	memcpy(req->buffer, &len_int1_dec, INT_LENGTH);
	memcpy(req->buffer+ INT_LENGTH, raw_dst, len_int1_dec);

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
						memcpy(&dst_len, req->buffer+ len_int1_dec+INT_LENGTH, INT_LENGTH);
						memcpy(pDst, req->buffer+ len_int1_dec + 2*INT_LENGTH, dst_len);
//						res[0] = req->ocall_index;
						spin_unlock(&req->is_done);
						break;
					}
				}


	pDst[dst_len] = '\0';

	delete req;
	delete dst;
	delete raw_dst;

	return 0;
}
