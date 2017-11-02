#include "stdafx.h"
#include "interface.h"
#include <unistd.h>
#include <algorithm> // for using copy (library function)

extern sgx_enclave_id_t global_eid;
extern Queue* inQueue;
extern bool status;

//////////////////////////////////////////////////////////
// FUNCTION DISCRIBING FLOAT ELEMENTS
//////////////////////////////////////////////////////////

int function4Float4(int cmd, char* int1, char* int2, char *res) {
	if (!status) {
		int resp = initMultithreading();
		resp = loadKey(0);
	//	return resp;//IS_NOT_INITIALIZE;
	}

	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *decoded_int1, *decoded_int2, *decoded_int3;

	request* req = new request;

	try {
		decoded_int1 = new char[ENC_FLOAT_LENGTH];
		decoded_int2 = new char[ENC_FLOAT_LENGTH];
		decoded_int3 = new char[ENC_FLOAT_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	// decode arrays from base64 forms to byte arrays
	if (!FromBase64Fast((const BYTE*) int1, ENC_FLOAT_LENGTH_B64 - 1, (decoded_int1), ENC_FLOAT_LENGTH))
			return BASE64DECODER_ERROR;
	if (!FromBase64Fast((const BYTE*) int2, ENC_FLOAT_LENGTH_B64 - 1, (decoded_int2), ENC_FLOAT_LENGTH))
			return BASE64DECODER_ERROR;


	memcpy(req->buffer, decoded_int1, ENC_FLOAT_LENGTH);
	memcpy(req->buffer + ENC_FLOAT_LENGTH, decoded_int2, ENC_FLOAT_LENGTH);
	//std::copy(decoded_float1.begin(), decoded_float1.end(), req->buffer);
	//std::copy(decoded_float2.begin(), decoded_float2.end(), req->buffer + ENC_FLOAT_LENGTH);

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
				memcpy(decoded_int3, req->buffer+ ENC_FLOAT_LENGTH + ENC_FLOAT_LENGTH, ENC_FLOAT_LENGTH);
				if (cmd == CMD_FLOAT4_CMP)
					res[0] = req->ocall_index;
				else if (!ToBase64Fast((const unsigned char*) decoded_int3, ENC_FLOAT_LENGTH, res, ENC_FLOAT_LENGTH_B64))
						return BASE64DECODER_ERROR;
				spin_unlock(&req->is_done);
				break;
			}
		}

	delete req;
	delete decoded_int1;
	delete decoded_int2;
	delete decoded_int3;
	//fprintf(f," end\n");
	//fclose(f);
	return 0;
}


int plusFloat4(char * src1, char *src2, char *res) {
	int resp = function4Float4(CMD_FLOAT4_PLUS, src1, src2, res);
	return resp;
}

int minusFloat4(char * src1, char *src2, char *res) {
	int resp = function4Float4(CMD_FLOAT4_MINUS, src1, src2, res);
	return resp;
}

int multFloat4(char * src1, char *src2, char *res) {
	int resp = function4Float4(CMD_FLOAT4_MULT, src1, src2, res);
	return resp;
}

int divFloat4(char * src1, char *src2, char *res) {
	int resp = function4Float4(CMD_FLOAT4_DIV, src1, src2, res);
	return resp;
}

int expFloat4(char * src1, char *src2, char *res) {
	int resp = function4Float4(CMD_FLOAT4_EXP, src1, src2, res);
	return resp;
}

int modFloat4(char * src1, char *src2, char *res) {
	int resp = function4Float4(CMD_FLOAT4_MOD, src1, src2, res);
	return resp;
}


int compareFloat4(char * src1, char *src2, int *res) {
	if (!status) {
		int resp = initMultithreading();
		resp = loadKey(0);
	//	return resp;//IS_NOT_INITIALIZE;
	}

	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *decoded_int1, *decoded_int2, *decoded_int3;

	request* req = new request;

	try {
		decoded_int1 = new char[ENC_FLOAT_LENGTH];
		decoded_int2 = new char[ENC_FLOAT_LENGTH];
		decoded_int3 = new char[ENC_FLOAT_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	// decode arrays from base64 forms to byte arrays
	if (!FromBase64Fast((const BYTE*) src1, ENC_FLOAT_LENGTH_B64 - 1, (decoded_int1), ENC_FLOAT_LENGTH))
			return BASE64DECODER_ERROR;
	if (!FromBase64Fast((const BYTE*) src2, ENC_FLOAT_LENGTH_B64 - 1, (decoded_int2), ENC_FLOAT_LENGTH))
			return BASE64DECODER_ERROR;


	memcpy(req->buffer, decoded_int1, ENC_FLOAT_LENGTH);
	memcpy(req->buffer + ENC_FLOAT_LENGTH, decoded_int2, ENC_FLOAT_LENGTH);
	req->ocall_index = CMD_FLOAT4_CMP;
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
				//memcpy(decoded_int3, req->buffer + ENC_INT_LENGTH + ENC_INT_LENGTH, ENC_INT_LENGTH);
				res[0] = req->ocall_index;
				spin_unlock(&req->is_done);
				break;
			}

		}
	delete req;
	delete decoded_int1;
	delete decoded_int2;
	delete decoded_int3;

	return 0;
}

int encryptFloat4(float pSrc, char *pDst) {
	if (!status) {
		int resp = initMultithreading();
		resp = loadKey(0);
	//	return resp;//IS_NOT_INITIALIZE;
	}

	char *decoded_int2, *float_byte;
	int resp;
	request* req = new request();
	try {
		decoded_int2 = new char[ENC_FLOAT_LENGTH];
		float_byte = new char[sizeof(float)];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	memcpy(req->buffer, &pSrc, FLOAT_LENGTH);
	req->ocall_index = CMD_FLOAT4_ENC;
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
					memcpy(decoded_int2, req->buffer + FLOAT_LENGTH, ENC_FLOAT_LENGTH);
					//spin_unlock(&req->is_done);
					break;
				}

			}


	if (!ToBase64Fast((const unsigned char*) decoded_int2, ENC_FLOAT_LENGTH, pDst, ENC_FLOAT_LENGTH_B64))
			return BASE64DECODER_ERROR;
	pDst[ENC_FLOAT_LENGTH_B64-1] = '\0';

	delete req;
	delete decoded_int2;
	delete float_byte;

	return 0;


}

int decryptFloat4(char *pSrc, float *pDst) {
	if (!status) {
		int resp = initMultithreading();
		resp = loadKey(0);
	//	return resp;//IS_NOT_INITIALIZE;
	}

	char *decoded_int1, *decoded_int2;
	int resp=0, ans;
	int len_int1 = strlen(pSrc);
	request* req = new request();
	decoded_int1 = new char[ENC_FLOAT_LENGTH];
	decoded_int2 = new char[FLOAT_LENGTH];

	FromBase64Fast((const BYTE*) pSrc, len_int1, (decoded_int1), ENC_FLOAT_LENGTH);

	memcpy(req->buffer, decoded_int1, ENC_FLOAT_LENGTH);
	req->ocall_index = CMD_FLOAT4_DEC;
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
						memcpy(decoded_int2, req->buffer + ENC_FLOAT_LENGTH, FLOAT_LENGTH);
						spin_unlock(&req->is_done);
						break;
					}

				}
		memcpy(&pDst[0], decoded_int2, FLOAT_LENGTH);

	delete req;
	delete decoded_int1;
	delete decoded_int2;

	return resp;
}
