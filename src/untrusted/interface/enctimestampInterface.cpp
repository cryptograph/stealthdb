#include "stdafx.h"
#include "interface.h"


extern sgx_enclave_id_t global_eid;
extern Queue* inQueue;
extern bool status;

int compareTimestamp(char * int1, char *int2, int *res) {
	if (!status)
		return IS_NOT_INITIALIZE;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *decoded_int1, *decoded_int2, *decoded_int3;
	request* req = new request();

	try {
		decoded_int1 = new char[ENC_TIMESTAMP_LENGTH];
		decoded_int2 = new char[ENC_TIMESTAMP_LENGTH];
		decoded_int3 = new char[ENC_TIMESTAMP_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	// decode arrays from base64 forms to byte arrays
	if (!FromBase64Fast((const BYTE*) int1, ENC_TIMESTAMP_LENGTH_B64 - 1, (decoded_int1), ENC_TIMESTAMP_LENGTH))
			return BASE64DECODER_ERROR;
	if (!FromBase64Fast((const BYTE*) int2, ENC_TIMESTAMP_LENGTH_B64 - 1, (decoded_int2), ENC_TIMESTAMP_LENGTH))
			return BASE64DECODER_ERROR;

	memcpy(req->buffer, decoded_int1, ENC_TIMESTAMP_LENGTH);
	memcpy(req->buffer + ENC_TIMESTAMP_LENGTH, decoded_int2, ENC_TIMESTAMP_LENGTH);
	req->ocall_index = CMD_TIMESTAMP_CMP;
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

int encryptTimestamp(TIMESTAMP pSrc, char *pDst) {
	if (!status)
		return IS_NOT_INITIALIZE;

	char *decoded_int2, *int_byte;
	int resp;
	request* req = new request();

	try {
		decoded_int2 = new char[ENC_TIMESTAMP_LENGTH];
		int_byte = new char[TIMESTAMP_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	memcpy(req->buffer, &pSrc, TIMESTAMP_LENGTH);
	req->ocall_index = CMD_TIMESTAMP_ENC;
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
					memcpy(decoded_int2, req->buffer + TIMESTAMP_LENGTH, ENC_TIMESTAMP_LENGTH);
					spin_unlock(&req->is_done);
					break;
				}

			}

	if (!ToBase64Fast((const unsigned char*) decoded_int2, ENC_TIMESTAMP_LENGTH, pDst, ENC_TIMESTAMP_LENGTH_B64))
			return BASE64DECODER_ERROR;

	pDst[ENC_TIMESTAMP_LENGTH_B64-1] = '\0';

	delete decoded_int2;
	delete int_byte;

	return resp;


}

int decryptTimestamp(char *pSrc, TIMESTAMP *pDst) {
	if (!status)
		return IS_NOT_INITIALIZE;

	char *decoded_int1, *decoded_int2;
	int resp=0, ans;
	int len_int1 = strlen(pSrc);
	request* req = new request();

	decoded_int1 = new char[ENC_TIMESTAMP_LENGTH];
	decoded_int2 = new char[TIMESTAMP_LENGTH];

	FromBase64Fast((const BYTE*) pSrc, len_int1, (decoded_int1), ENC_TIMESTAMP_LENGTH);

	memcpy(req->buffer, decoded_int1, ENC_TIMESTAMP_LENGTH);
	req->ocall_index = CMD_TIMESTAMP_DEC;
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
							memcpy(decoded_int2, req->buffer + ENC_TIMESTAMP_LENGTH, TIMESTAMP_LENGTH);
							spin_unlock(&req->is_done);
							break;
						}

					}

	memcpy(&pDst[0], decoded_int2, TIMESTAMP_LENGTH);

	delete decoded_int1;
	delete decoded_int2;

	return resp;
}
