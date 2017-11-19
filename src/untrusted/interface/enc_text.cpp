#include "untrusted/interface/stdafx.h"
#include "untrusted/interface/interface.h"
#include <unistd.h>

extern sgx_enclave_id_t global_eid;
extern Queue* inQueue;
extern bool status;

/////////////////////////////////////////////////////////
// FUNCTIONS DISCRIBING ENCRYPTED STRINGS
//////////////////////////////////////////////////////////

int enc_text_concatenate(char *src1, size_t src1_len, char *src2, size_t src2_len, char *dst, size_t* dst_len) {

	int resp = ENCLAVE_IS_NOT_RUNNIG;
	if (!status) {
		resp = initMultithreading();
		resp = loadKey(0);
//		return resp;//IS_NOT_INITIALIZE;
	}
	
	int str3_len;
	int len_raw_str1, len_raw_str2, len_raw_str3;

	memcpy(&str3_len, dst_len, sizeof(uint8_t));

	uint8_t* str1 = new uint8_t[src1_len];
	uint8_t* str2 = new uint8_t[src2_len];
	uint8_t* str3 = new uint8_t[str3_len];

	request* req = new request;

	// decode arrays from base64 forms to byte arrays
	len_raw_str1 = FromBase64Fast((const BYTE*) src1, src1_len, str1, src1_len);
	len_raw_str2 = FromBase64Fast((const BYTE*) src2, src2_len, str2, src2_len);
	
	if (!len_raw_str1 || !len_raw_str2)
		return BASE64DECODER_ERROR;

	memcpy(req->buffer, &len_raw_str1, INT32_LENGTH);
	memcpy(req->buffer + INT32_LENGTH, str1, len_raw_str1);

	memcpy(req->buffer + len_raw_str1 + INT32_LENGTH, &len_raw_str2, INT32_LENGTH);
	memcpy(req->buffer + len_raw_str1 + INT32_LENGTH + INT32_LENGTH, str2, len_raw_str2);

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
			memcpy(&len_raw_str3, req->buffer + len_raw_str1 + 2*INT32_LENGTH + len_raw_str2, INT32_LENGTH);
			if (str3_len < len_raw_str3)
				return MEMORY_ALLOCATION_ERROR;

			memcpy(str3, req->buffer + len_raw_str1 + 3*INT32_LENGTH + len_raw_str2, len_raw_str3);
			resp = req->resp;
			spin_unlock(&req->is_done);
			break;
		}
	}

	int dst_b64_len = ToBase64Fast((const unsigned char*) str3, len_raw_str3, dst, str3_len);
	if (!dst_b64_len)
		return BASE64DECODER_ERROR;
	dst[dst_b64_len] = '\0';
	memcpy(dst_len, &dst_b64_len, sizeof(uint8_t));
	
	delete[] str1;
	delete[] str2;
	delete[] str3;
	delete req;

	return resp;
}

int enc_text_substring(char * src1, size_t src1_len, char *src2, size_t src2_len, char *res) {
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	if (!status) {
		resp = initMultithreading();
		resp = loadKey(0);
//		return resp;//IS_NOT_INITIALIZE;
	}
	
	int len_raw_str1, len_raw_str2, dst_len = 1;

	request* req = new request;
	uint8_t* str1 = new uint8_t[src1_len];
	uint8_t* str2 = new uint8_t[src2_len];

	// decode arrays from base64 forms to byte arrays
	len_raw_str1 = FromBase64Fast((const BYTE*) src1, src1_len, str1, src1_len);
	len_raw_str2 = FromBase64Fast((const BYTE*) src2, src2_len, str2, src2_len);
	
	if (!len_raw_str1 || !len_raw_str2)
		return BASE64DECODER_ERROR;


	memcpy(req->buffer, &len_raw_str1, INT32_LENGTH);
	memcpy(req->buffer + INT32_LENGTH, str1, len_raw_str1);

	memcpy(req->buffer + len_raw_str1 + INT32_LENGTH, &len_raw_str2, INT32_LENGTH);
	memcpy(req->buffer + len_raw_str1 + INT32_LENGTH + INT32_LENGTH, str2, len_raw_str2);

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
			resp = req->resp;
			std::copy(&req->buffer[len_raw_str1 + 2*INT32_LENGTH + len_raw_str2], &req->buffer[len_raw_str1 + 2*INT32_LENGTH + len_raw_str2 + INT32_LENGTH], &res[0]);
			spin_unlock(&req->is_done);
			break;
		}
	}

	delete[] str1;
	delete[] str2;
	delete req;

	return resp;


}

int enc_text_cmp(char *src1, size_t src1_len, char *src2, size_t src2_len, char *res) {

	int resp = ENCLAVE_IS_NOT_RUNNIG;
	if (!status) {
		resp = initMultithreading();
		resp = loadKey(0);
//		return resp;//IS_NOT_INITIALIZE;
	}

	request* req = new request;

	uint8_t* arg1 = new uint8_t[src1_len];
	uint8_t* arg2 = new uint8_t[src2_len];

	int len_raw_str1 = FromBase64Fast((const BYTE*) src1, src1_len, arg1, src1_len);
	int len_raw_str2 = FromBase64Fast((const BYTE*) src2, src2_len, arg2, src2_len);

	if (!len_raw_str1 || !len_raw_str2)
		return BASE64DECODER_ERROR;

	memcpy(req->buffer, &len_raw_str1, INT32_LENGTH);
	memcpy(req->buffer + INT32_LENGTH, arg1, len_raw_str1);
	memcpy(req->buffer + len_raw_str1 + INT32_LENGTH, &len_raw_str2, INT32_LENGTH);
	memcpy(req->buffer + len_raw_str1 + INT32_LENGTH + INT32_LENGTH, arg2, len_raw_str2);

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
			resp = req->resp;
			std::copy(&req->buffer[len_raw_str1 + 2*INT32_LENGTH + len_raw_str2], &req->buffer[len_raw_str1 + 2*INT32_LENGTH + len_raw_str2 + INT32_LENGTH], &res[0]);
			spin_unlock(&req->is_done);
			break;
		}
	}

	delete req;
	delete[] arg1;
	delete[] arg2;

	return resp;
}

int enc_text_encrypt(char* pSrc, size_t src_len, char *pDst, size_t dst_len) {
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	if (!status) {
		resp = initMultithreading();
		resp = loadKey(0);
//		return resp;//IS_NOT_INITIALIZE;
	}

	int len, raw_dst_len;

	request* req = new request;
	uint8_t* dst = new uint8_t[dst_len + 1];

	memcpy(req->buffer, &src_len, INT32_LENGTH);
	memcpy(req->buffer + INT32_LENGTH, pSrc, src_len);

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
			memcpy(&raw_dst_len, req->buffer+ src_len + INT32_LENGTH, INT32_LENGTH);
			memcpy(dst, req->buffer+ src_len + 2*INT32_LENGTH, raw_dst_len);
			resp = req->resp;
			spin_unlock(&req->is_done);
			break;
		}
	}

	len = ToBase64Fast((const unsigned char*) dst, raw_dst_len, pDst, dst_len+1);
	if (!len)
			return BASE64DECODER_ERROR;
	pDst[dst_len] = '\0';

	delete req;
	delete[] dst;

	return resp;


}

int enc_text_decrypt(char *pSrc, size_t src_len, char *pDst, size_t dst_len) {
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	if (!status) {
		resp = initMultithreading();
		resp = loadKey(0);
//		return resp;//IS_NOT_INITIALIZE;
	}

	int src_decrypted_len, src_bytearray_len;
	request* req = new request;
	uint8_t* dst = new uint8_t[src_len];

	src_bytearray_len = FromBase64Fast((const BYTE*) pSrc, src_len, dst, src_len);
	src_decrypted_len = src_bytearray_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

	if (src_decrypted_len > dst_len)
		return MEMORY_ALLOCATION_ERROR;

	memcpy(req->buffer, &src_bytearray_len, INT32_LENGTH);
	memcpy(req->buffer + INT32_LENGTH, dst, src_bytearray_len);

	req->ocall_index = CMD_STRING_DEC;
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
			memcpy(&dst_len, req->buffer+ src_bytearray_len + INT32_LENGTH, INT32_LENGTH);
			memcpy(pDst, req->buffer+ src_bytearray_len + 2*INT32_LENGTH, src_bytearray_len);
			resp = req->resp;
			spin_unlock(&req->is_done);
			break;
		}
	}

	pDst[dst_len] = '\0';

	delete req;
	delete[] dst;

	return resp;
}
