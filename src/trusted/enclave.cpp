#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "enclave.h"
#include "enclave_t.h"  /* print_string */

sgx_aes_ctr_128bit_key_t *p_key = NULL;


void free_allocated_memory(void *pointer)
{
    if(pointer != NULL)
    {
        free(pointer);
        pointer = NULL;
    }
}

/* Generate a master key
 @input: uint8_t sealed_key - pointer to sealed master key array
		 size_t - length of the array (= sgx_calc_sealed_data_size(sgx_aes_ctr_128bit_key_t) = 576)
 @return:
	* SGX_error, if there was an error during seal function
	0, otherwise
*/
int generateKeyEnclave(uint8_t *sealed_key, size_t sealedkey_len) {

	int resp = SGX_SUCCESS;
	uint32_t len = sizeof(sgx_aes_ctr_128bit_key_t);
    uint8_t *p_key_tmp = (uint8_t *)malloc(len);

	if (sgx_calc_sealed_data_size(0, len) > sealedkey_len)
		return MEMORY_COPY_ERROR;

	sgx_read_rand(p_key_tmp, len);
    resp = sgx_seal_data(0, NULL, len, p_key_tmp, sealedkey_len, (sgx_sealed_data_t *) sealed_key);

	memset_s(p_key_tmp, len, 0, len);
	free_allocated_memory(p_key_tmp);

	return resp;
}

/* Load the master key from sealed data
 *  @input: uint8_t sealed_key - pointer to a sealed data byte array
		    size_t - length of the array (= sgx_calc_sealed_data_size(sgx_aes_ctr_128bit_key_t) = 576)
 @return:
	* SGX_error, if there was an error during unsealing
	0, otherwise
*/
int loadKeyEnclave(uint8_t *sealed_key, size_t sealedkey_len) {

	int resp = SGX_SUCCESS;
	uint32_t len = sizeof(sgx_aes_ctr_128bit_key_t);

	if (p_key == NULL)
		p_key = new sgx_aes_ctr_128bit_key_t[len];

	if (sgx_calc_sealed_data_size(0, sizeof(sgx_aes_ctr_128bit_key_t)) > sealedkey_len)
		return MEMORY_COPY_ERROR;

    resp = sgx_unseal_data((const sgx_sealed_data_t *) sealed_key, NULL, NULL, (uint8_t *)p_key, &len);

	return resp;
}

/* Decrypt an array by AES_GCM128
 @input: pSrc - a pointer to an encrypted uint8_t array
		 srcLen - length of the array
		 pDst - pointer to the result array with size = srcLen - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE
 @return:
		SGX_RESPONSE, if there was an error
		0, otherwise
	 */
int decryptGCM(uint8_t *pSrc, size_t srcLen, uint8_t *pDst, size_t dstLen) {

	if (dstLen <  srcLen - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE)
		return SGX_ERROR_MAC_MISMATCH;

	return sgx_rijndael128GCM_decrypt((const sgx_aes_ctr_128bit_key_t* ) p_key,
                                pSrc + SGX_AESGCM_IV_SIZE,           // cipher
                                srcLen - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE,
								pDst,                                // plain out
                                pSrc, SGX_AESGCM_IV_SIZE,            // nonce
                                 NULL, 0,                            // aad
                                 (sgx_aes_gcm_128bit_tag_t *) (pSrc + srcLen - SGX_AESGCM_MAC_SIZE)); // tag

}

int encryptGCM(uint8_t *pSrc, size_t srcLen, uint8_t *pDst, size_t dstLen) {

	unsigned char *nonce;
	nonce  = new unsigned char[SGX_AESGCM_IV_SIZE];

	int resp = sgx_read_rand(nonce, SGX_AESGCM_IV_SIZE);
	if (resp != SGX_SUCCESS)
		return resp;

	memcpy(pDst, nonce, SGX_AESGCM_IV_SIZE);

	resp = sgx_rijndael128GCM_encrypt((const sgx_aes_ctr_128bit_key_t* ) p_key, pSrc, srcLen,
										pDst + SGX_AESGCM_IV_SIZE,
										nonce, SGX_AESGCM_IV_SIZE,
										NULL, 0,
										(sgx_aes_gcm_128bit_tag_t *) (pDst + SGX_AESGCM_IV_SIZE + srcLen));

	delete nonce;

	return resp;

}

/* Decrypts byte array by aesgcm mode
 @input: uint8_t array - pointer to encrypted byte array
		 size_t - length of encrypted  array
		 uint8_t array - pointer to decrypted array
		 size_t - length of decrypted array (length of array - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE)
 @return:
	* SGX_error, if there was an error during encryption/decryption
	0, otherwise
*/
int decryptBytes(uint8_t *pSrc, size_t src_len, uint8_t *pDst, size_t dst_len) {

	int resp = sgx_rijndael128GCM_decrypt(p_key,
                                pSrc + SGX_AESGCM_IV_SIZE,           // cipher
                                src_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE,
								pDst,                                                       // plain out
                                pSrc, SGX_AESGCM_IV_SIZE,                                  // nonce
                                 NULL, 0,                                                   // aad
                                 (sgx_aes_gcm_128bit_tag_t *) (pSrc - SGX_AESGCM_MAC_SIZE + src_len)); // tag

	return resp;
}

/* Encrypts byte array by aesgcm mode
 @input: uint8_t array - pointer to a byte array
		 size_t - length of the array
		 uint8_t array - pointer to result array
		 size_t - length of result array (SGX_AESGCM_IV_SIZE + length of array + SGX_AESGCM_MAC_SIZE)
 @return:
	* SGX_error, if there was an error during encryption/decryption
	0, otherwise
*/
int encryptBytes(uint8_t *pSrc, size_t src_len, uint8_t *pDst, size_t dst_len) {

	unsigned char nonce[SGX_AESGCM_IV_SIZE];
	int resp;
	sgx_read_rand(nonce, 12);
//	strncpy((char *) pDst, (const char *) nonce,12);
	memcpy(pDst, nonce, SGX_AESGCM_IV_SIZE);
	resp = sgx_rijndael128GCM_encrypt(p_key,
                                 pSrc,
								 src_len ,
                                 pDst + SGX_AESGCM_IV_SIZE,
                                 nonce, SGX_AESGCM_IV_SIZE,
                                 NULL, 0,
                                 (sgx_aes_gcm_128bit_tag_t *) (pDst + SGX_AESGCM_IV_SIZE + src_len));


	return resp;
}

int enclaveProcess (void* arg1) {

	int resp = 0;
	int src_len = 0, src2_len = 0, dst_len = 0;
	uint8_t *src1, *src2, *dst;
	src1 = new uint8_t [INPUT_BUFFER_SIZE];
	src2 = new uint8_t [INPUT_BUFFER_SIZE];
	dst = new uint8_t [INPUT_BUFFER_SIZE];

	if (arg1 == NULL)
		return -1;
	Queue* inQueue = (Queue*)arg1;

	while (true) {

		request* req = inQueue->dequeue();

		if (req == NULL)
			__asm__("pause");
		else
		{
			//request* response = new request;

			switch (req->ocall_index)
			{
				case CMD_INT64_PLUS:
					req->resp = addRandEncInt(req->buffer, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH+ENC_INT64_LENGTH, ENC_INT64_LENGTH);
					break;

				case CMD_INT64_MINUS:
					req->resp = subsRandEncInt(req->buffer, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH+ENC_INT64_LENGTH, ENC_INT64_LENGTH);
					break;

				case CMD_INT64_MULT:
					req->resp = multRandEncInt(req->buffer, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH+ENC_INT64_LENGTH, ENC_INT64_LENGTH);
					break;

				case CMD_INT64_DIV:
					req->resp = divRandEncInt(req->buffer, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH+ENC_INT64_LENGTH, ENC_INT64_LENGTH);
					break;

				case CMD_INT64_EXP:
					req->resp = expRandEncInt(req->buffer, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH+ENC_INT64_LENGTH, ENC_INT64_LENGTH);
					break;

				case CMD_INT64_MOD:
					req->resp = modRandEncInt(req->buffer, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH+ENC_INT64_LENGTH, ENC_INT64_LENGTH);
					break;

				case CMD_INT64_CMP:
					req->resp = compareRandEncInt(req->buffer, ENC_INT64_LENGTH, req->buffer+ENC_INT64_LENGTH, ENC_INT64_LENGTH, req->buffer+2*ENC_INT64_LENGTH, INT64_LENGTH);
					break;

				case CMD_INT64_ENC:
					req->resp = encryptRandEncInt(req->buffer, INT64_LENGTH, req->buffer + INT64_LENGTH, ENC_INT64_LENGTH);
					break;

				case CMD_INT64_DEC:
					req->resp = decryptRandEncInt(req->buffer, ENC_INT64_LENGTH, req->buffer + ENC_INT64_LENGTH, INT64_LENGTH);
					break;

				case CMD_FLOAT4_PLUS:
					req->ocall_index = addRandEncFloat(req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer + 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_MINUS:
					req->ocall_index = subsRandEncFloat(req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer + 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_MULT:
					req->ocall_index = multRandEncFloat(req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer + 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_DIV:
					req->ocall_index = divRandEncFloat(req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer+ 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_EXP:
					req->ocall_index = expRandEncFloat(req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer+ 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_MOD:
					req->ocall_index = modRandEncFloat(req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer+ 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_CMP:
					req->ocall_index = compareRandEncFloat(req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_ENC:
					req->resp = encryptRandEncFloat(req->buffer, FLOAT4_LENGTH, req->buffer + FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_DEC:
					req->resp = decryptRandEncFloat(req->buffer, ENC_FLOAT4_LENGTH, req->buffer + ENC_FLOAT4_LENGTH, FLOAT4_LENGTH);
					break;

				case CMD_STRING_CMP:
					memcpy(&src_len, req->buffer,INT64_LENGTH);
					memcpy(src1, req->buffer+INT64_LENGTH,src_len);
					memcpy(&src2_len, req->buffer+INT64_LENGTH + src_len,INT64_LENGTH);
					memcpy(src2, req->buffer+INT64_LENGTH + src_len +INT64_LENGTH,src2_len);
					req->ocall_index = compareRandEncString(src1, src_len, src2, src2_len);
					dst_len = 1;
					//memcpy(req->buffer+INT64_LENGTH + src_len +INT64_LENGTH + src2_len, &dst_len, INT64_LENGTH);
					//memcpy(req->buffer+3*INT64_LENGTH + src_len +src2_len, &req->ocall_index, dst_len);
					break;

				case CMD_STRING_ENC:
					memcpy(&src_len, req->buffer,INT64_LENGTH);
					dst_len = src_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;

					memcpy(src1, req->buffer+INT64_LENGTH,src_len);
					req->ocall_index = encryptRandEncString(src1, src_len, dst, dst_len);
					memcpy(req->buffer + INT64_LENGTH + src_len, &dst_len,INT64_LENGTH);
					memcpy(req->buffer+src_len + 2*INT64_LENGTH,dst,src_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
					break;

				case CMD_STRING_DEC:
					memcpy(&src_len, req->buffer,INT64_LENGTH);
					dst_len = src_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

					memcpy(src1, req->buffer+INT64_LENGTH,src_len);
					req->ocall_index = decryptRandEncString(src1, src_len, dst, dst_len);
					memcpy(req->buffer  + INT64_LENGTH + src_len , &dst_len,INT64_LENGTH);
					memcpy(req->buffer+ src_len + 2*INT64_LENGTH,dst,src_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE);
					break;

				case CMD_STRING_LIKE:
					memcpy(&src_len, req->buffer,INT64_LENGTH);
					memcpy(src1, req->buffer+INT64_LENGTH,src_len);
					memcpy(&src2_len, req->buffer+INT64_LENGTH + src_len,INT64_LENGTH);
					memcpy(src2, req->buffer+INT64_LENGTH + src_len +INT64_LENGTH,src2_len);

					req->ocall_index = substringRandEncString(src1, src_len, src2, src2_len);
					//dst_len = 1;
					//req->ocall_index = 1;
					//memcpy(req->buffer, &dst_len, INT64_LENGTH);
					break;

				case CMD_STRING_CONCAT:
					memcpy(&src_len, req->buffer,INT64_LENGTH);
					memcpy(src1, req->buffer+INT64_LENGTH,src_len);
					memcpy(&src2_len, req->buffer+INT64_LENGTH + src_len,INT64_LENGTH);
					memcpy(src2, req->buffer+INT64_LENGTH + src_len +INT64_LENGTH,src2_len);
					dst_len = src_len + src2_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

					req->ocall_index = concatRandEncString(src1, src_len, src2, src2_len, dst, dst_len);
					memcpy(req->buffer, &dst_len,INT64_LENGTH);
					memcpy(req->buffer+INT64_LENGTH,dst,src_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
					break;

				case CMD_TIMESTAMP_CMP:
					req->ocall_index = compareRandEncTimestamp(req->buffer, ENC_TIMESTAMP_LENGTH, req->buffer+ENC_TIMESTAMP_LENGTH, ENC_TIMESTAMP_LENGTH);
					break;

				case CMD_TIMESTAMP_ENC:
					req->ocall_index = encryptBytes(req->buffer, TIMESTAMP_LENGTH, req->buffer + TIMESTAMP_LENGTH, ENC_TIMESTAMP_LENGTH);
					break;

				case CMD_TIMESTAMP_DEC:
					req->ocall_index = decryptBytes(req->buffer, ENC_TIMESTAMP_LENGTH, req->buffer + ENC_TIMESTAMP_LENGTH, TIMESTAMP_LENGTH);
					break;
			}
			//response->is_done = 1;
			req->is_done = 1;
			//outQueue->enqueue(response);
			//spin_lock(&req->is_done);
			//delete response;
		}
	}

return 0;
}
