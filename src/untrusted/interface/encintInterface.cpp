#include "stdafx.h"
#include "interface.h"

extern sgx_enclave_id_t global_eid;
extern Queue* inQueue;
extern bool status;

int function4Int64(int cmd, char * int1, char *int2, char *res) {
	if (!status) {
		int resp = initMultithreading();
		resp = loadKey(0);
	//	return resp;//IS_NOT_INITIALIZE;
	}

	int resp = ENCLAVE_IS_NOT_RUNNIG;
	request* req = new request;

/*
	char *decoded_int1, *decoded_int2, *decoded_int3;
	try {
		decoded_int1 = new char[ENC_INT_LENGTH];
		decoded_int2 = new char[ENC_INT_LENGTH];
		decoded_int3 = new char[ENC_INT_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}
*/
	std::array<BYTE, ENC_INT_LENGTH> int1_v;
	std::array<BYTE, ENC_INT_LENGTH> int2_v;
	std::array<BYTE, ENC_INT_LENGTH> int3_v;

	// decode arrays from base64 forms to byte arrays
//	if (!FromBase64Fast((const BYTE*) int1, ENC_INT_LENGTH_B64 - 1, (decoded_int1), ENC_INT_LENGTH))
//			return BASE64DECODER_ERROR;

	//if (!FromBase64Fast((const BYTE*) int2, ENC_INT_LENGTH_B64 - 1, (decoded_int2), ENC_INT_LENGTH))
//			return BASE64DECODER_ERROR;

	//std::vector<char> int1_v(decoded_int1, decoded_int1 + ENC_INT_LENGTH);
	//std::vector<char> int2_v(decoded_int2, decoded_int2 + ENC_INT_LENGTH);

	if (!FromBase64Fast((const BYTE*) int1, ENC_INT_LENGTH_B64 - 1, int1_v.begin(), ENC_INT_LENGTH))
				return BASE64DECODER_ERROR;

	if (!FromBase64Fast((const BYTE*) int2, ENC_INT_LENGTH_B64 - 1, int2_v.begin(), ENC_INT_LENGTH))
				return BASE64DECODER_ERROR;

	std::copy(int1_v.begin(), int1_v.end(), &req->buffer[0]);
	std::copy(int2_v.begin(), int2_v.end(), &req->buffer[ENC_INT_LENGTH]);


	//memcpy(req->buffer, decoded_int1, ENC_INT_LENGTH);
	//memcpy(req->buffer + ENC_INT_LENGTH, decoded_int2, ENC_INT_LENGTH);
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
				//memcpy(decoded_int3, req->buffer+ ENC_INT_LENGTH + ENC_INT_LENGTH, ENC_INT_LENGTH);
				std::copy(&req->buffer[2*ENC_INT_LENGTH], &req->buffer[3*ENC_INT_LENGTH], int3_v.begin());
				resp = req->resp;
			//	if (cmd == CMD_INT64_CMP)
			//		res[0] = req->ocall_index;
				//else if (!ToBase64Fast((const unsigned char*) decoded_int3, ENC_INT_LENGTH, res, ENC_INT_LENGTH_B64))
				if (!ToBase64Fast((const BYTE*) int3_v.begin(), ENC_INT_LENGTH, res, ENC_INT_LENGTH_B64))
					resp = BASE64DECODER_ERROR;
				spin_unlock(&req->is_done);
				break;
			}
		}

	delete req;
	//delete decoded_int1;
	//delete decoded_int2;
	//delete decoded_int3;

	return resp;
}

int plusInt64(char * int1, char *int2, char *res) {
	return function4Int64(CMD_INT64_PLUS, int1, int2, res);;
}

int minusInt64(char * int1, char *int2, char *res) {
	int resp = function4Int64(CMD_INT64_MINUS, int1, int2, res);
	return resp;
}

int multInt64(char * int1, char *int2, char *res) {
	int resp = function4Int64(CMD_INT64_MULT, int1, int2, res);
	return resp;
}

int divInt64(char * int1, char *int2, char *res) {
	int resp = function4Int64(CMD_INT64_DIV, int1, int2, res);
	return resp;
}

int expInt64(char * int1, char *int2, char *res) {
	int resp = function4Int64(CMD_INT64_EXP, int1, int2, res);
	return resp;
}

int modInt64(char * int1, char *int2, char *res) {
	int resp = function4Int64(CMD_INT64_MOD, int1, int2, res);
	return resp;
}


int compareInt64(char * int1, char *int2, char *res) {

	if (!status) {
		int resp = initMultithreading();
		resp = loadKey(0);
//		return resp;//IS_NOT_INITIALIZE;
	}
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	request* req = new request;

	std::array<BYTE, ENC_INT_LENGTH> int1_v;
	std::array<BYTE, ENC_INT_LENGTH> int2_v;

	if (!FromBase64Fast((const BYTE*) int1, ENC_INT_LENGTH_B64 - 1, int1_v.begin(), ENC_INT_LENGTH))
				return BASE64DECODER_ERROR;

	if (!FromBase64Fast((const BYTE*) int2, ENC_INT_LENGTH_B64 - 1, int2_v.begin(), ENC_INT_LENGTH))
				return BASE64DECODER_ERROR;

	std::copy(int1_v.begin(), int1_v.end(), &req->buffer[0]);
	std::copy(int2_v.begin(), int2_v.end(), &req->buffer[ENC_INT_LENGTH]);

	req->ocall_index = CMD_INT64_CMP;
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
				std::copy(&req->buffer[2*ENC_INT_LENGTH], &req->buffer[2*ENC_INT_LENGTH + INT_LENGTH], &res[0]);
				spin_unlock(&req->is_done);
				break;
			}
		}
	delete req;
	return resp;
}

int encryptInt64(int pSrc, char *pDst) {

	if (!status) {
		int resp = initMultithreading();
		resp = loadKey(0);
//		return resp;//IS_NOT_INITIALIZE;
	}

	int resp = ENCLAVE_IS_NOT_RUNNIG;
	request* req = new request;
	std::array<BYTE, ENC_INT_LENGTH> int1_v;

	memcpy(req->buffer, &pSrc, INT_LENGTH);
	req->ocall_index = CMD_INT64_ENC;
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
				std::copy(&req->buffer[INT_LENGTH], &req->buffer[INT_LENGTH+ ENC_INT_LENGTH], int1_v.begin());
				resp = req->resp;
				//spin_unlock(&req->is_done);
				break;
			}

		}

	if (!ToBase64Fast((const BYTE*) int1_v.begin(), ENC_INT_LENGTH, pDst, ENC_INT_LENGTH_B64))
						resp = BASE64DECODER_ERROR;
	pDst[ENC_INT_LENGTH_B64-1] = '\0';

	delete req;
	return resp;
}

int decryptInt64(char *pSrc, char *pDst) {

	if (!status) {
		int resp = initMultithreading();
		resp = loadKey(0);
//		return resp;//IS_NOT_INITIALIZE;
	}

	int resp=0, ans;
	int len_int1 = strlen(pSrc);
	request* req = new request;

	std::array<BYTE, ENC_INT_LENGTH> int1_v;
	std::array<BYTE, ENC_INT_LENGTH> int2_v;

	if (!FromBase64Fast((const BYTE*) pSrc, ENC_INT_LENGTH_B64 - 1, int1_v.begin(), ENC_INT_LENGTH))
					return BASE64DECODER_ERROR;

	std::copy(int1_v.begin(), int1_v.end(), &req->buffer[0]);
	req->ocall_index = CMD_INT64_DEC;
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
				std::copy(&req->buffer[ENC_INT_LENGTH], &req->buffer[ENC_INT_LENGTH + INT_LENGTH], &pDst[0]);
				spin_unlock(&req->is_done);
				break;
		}
	}

	delete req;
	return resp;
}


