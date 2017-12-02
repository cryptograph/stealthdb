#include "enclave/enclave.h"
#include "enclave/enclave_t.h"

void free_allocated_memory(void *pointer)
{
    if(pointer != NULL)
    {
        free(pointer);
        pointer = NULL;
    }
}

/* Generate a master key
 * @input: uint8_t sealed_key - pointer to the sealed master key
 *		 size_t - length of the array (= sgx_calc_sealed_data_size(sgx_aes_ctr_128bit_key_t) = 576)
 * @return:
 *	 SGX_error, if there was an error during seal function
 *	0, otherwise
*/
int generate_enclave_key(uint8_t *sealed_key, size_t sealedkey_len) {

	int resp = SGX_SUCCESS;
	uint32_t len = sizeof(sgx_aes_ctr_128bit_key_t);
    uint8_t *p_key_tmp = (uint8_t *)malloc(len);
	uint8_t sealed_key_b[SEALED_KEY_LENGTH];

	if (sgx_calc_sealed_data_size(0, len) > sealedkey_len)
		return MEMORY_COPY_ERROR;

	sgx_read_rand(p_key_tmp, len);
    resp = sgx_seal_data(0, NULL, len, p_key_tmp, sealedkey_len, (sgx_sealed_data_t *) sealed_key_b);

	memcpy(sealed_key, sealed_key_b, SEALED_KEY_LENGTH);

 	memset_s(p_key_tmp, len, 0, len);
 	memset_s(sealed_key_b, SEALED_KEY_LENGTH, 0, SEALED_KEY_LENGTH);
	free_allocated_memory(p_key_tmp);

	return resp;
}

/* Load the master key from sealed data
 *  @input: uint8_t sealed_key - pointer to a sealed data byte array
 *		    size_t - length of the array (= sgx_calc_sealed_data_size(sgx_aes_ctr_128bit_key_t) = 576)
 *		    sgx_aes_ctr_128bit_key_t key - pointer to an unsealed master key (
 *		    size_t - length of the master key (= sizeof(sgx_aes_ctr_128bit_key_t) = 128)
 * @return:
 *	SGX_error, if there was an error during unsealing
 *	0, otherwise
*/
int load_enclave_key(uint8_t *sealed_key, size_t sealedkey_len, sgx_aes_ctr_128bit_key_t *key, size_t key_len) {

	int resp = ENCLAVE_IS_NOT_RUNNIG;
	uint32_t len = sizeof(sgx_aes_ctr_128bit_key_t);
	uint8_t sealed_key_b[SEALED_KEY_LENGTH];
	memcpy(sealed_key_b, sealed_key, SEALED_KEY_LENGTH);

	if ((sgx_calc_sealed_data_size(0, sizeof(sgx_aes_ctr_128bit_key_t)) > sealedkey_len) || (key_len != len))
		return MEMORY_COPY_ERROR;

	resp = sgx_unseal_data((const sgx_sealed_data_t *) sealed_key_b, NULL, NULL, (uint8_t *) key, &len);

	return resp;
}

/* Decrypts byte array by aesgcm mode
 * @input:
 * 		 sgx_aes_ctr_128bit_key_t key - pointer to the master key
 *       uint8_t array - pointer to encrypted byte array
 *		 size_t - length of encrypted  array
 *		 uint8_t array - pointer to decrypted array
 *		 size_t - length of decrypted array (length of array - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE)
 * @return:
 *	SGX_error, if there was an error during encryption/decryption
 *	0, otherwise
*/
int decrypt_bytes(sgx_aes_ctr_128bit_key_t* key, uint8_t *pSrc, size_t src_len, uint8_t *pDst, size_t dst_len) {

	int resp = sgx_rijndael128GCM_decrypt(key,
                                pSrc + SGX_AESGCM_IV_SIZE,           // cipher
                                src_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE,
								pDst,                                                       // plain out
                                pSrc, SGX_AESGCM_IV_SIZE,                                  // nonce
                                 NULL, 0,                                                   // aad
                                 (sgx_aes_gcm_128bit_tag_t *) (pSrc - SGX_AESGCM_MAC_SIZE + src_len)); // tag

	return resp;
}

/* Encrypts byte array by aesgcm mode
 * @input:
 *      sgx_aes_ctr_128bit_key_t key - pointer to the master key
 *      uint8_t array - pointer to a byte array
 *		size_t - length of the array
 *		 uint8_t array - pointer to result array
 *		 size_t - length of result array (SGX_AESGCM_IV_SIZE + length of array + SGX_AESGCM_MAC_SIZE)
 * @return:
 *  SGX_error, if there was an error during encryption/decryption
 *	0, otherwise
*/
int encrypt_bytes(sgx_aes_ctr_128bit_key_t* key, uint8_t *pSrc, size_t src_len, uint8_t *pDst, size_t dst_len) {

	unsigned char *nonce = new unsigned char[SGX_AESGCM_IV_SIZE];

	int resp = sgx_read_rand(nonce, SGX_AESGCM_IV_SIZE);
	if (resp != SGX_SUCCESS)
		return resp;

	memcpy(pDst, nonce, SGX_AESGCM_IV_SIZE);
	resp = sgx_rijndael128GCM_encrypt(key,
                                 pSrc,
								 src_len ,
                                 pDst + SGX_AESGCM_IV_SIZE,
                                 nonce, SGX_AESGCM_IV_SIZE,
                                 NULL, 0,
                                 (sgx_aes_gcm_128bit_tag_t *) (pDst + SGX_AESGCM_IV_SIZE + src_len));

	delete[] nonce;

	return resp;
}

int enclave_process (void* arg1) {

	int resp = 0;
	size_t src_len = 0, src2_len = 0, dst_len = 0;
	uint8_t *src1, *src2, *dst;
	src1 = new uint8_t [INPUT_BUFFER_SIZE];
	src2 = new uint8_t [INPUT_BUFFER_SIZE];
	dst = new uint8_t [INPUT_BUFFER_SIZE];

	uint32_t key_len = sizeof(sgx_aes_ctr_128bit_key_t);
	sgx_aes_ctr_128bit_key_t* key = new sgx_aes_ctr_128bit_key_t[key_len];

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
				case CMD_KEY_GEN:
					req->resp = generate_enclave_key(req->buffer, SEALED_KEY_LENGTH);
					break;

				case CMD_LOAD_KEY:
					req->resp = load_enclave_key(req->buffer, SEALED_KEY_LENGTH, key, key_len);
					break;

				case CMD_INT64_PLUS:
					req->resp = enc_int32_add(key, req->buffer, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH+ENC_INT32_LENGTH, ENC_INT32_LENGTH);
					break;

				case CMD_INT64_MINUS:
					req->resp = enc_int32_sub(key, req->buffer, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH+ENC_INT32_LENGTH, ENC_INT32_LENGTH);
					break;

				case CMD_INT64_MULT:
					req->resp = enc_int32_mult(key, req->buffer, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH+ENC_INT32_LENGTH, ENC_INT32_LENGTH);
					break;

				case CMD_INT64_DIV:
					req->resp = enc_int32_div(key, req->buffer, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH+ENC_INT32_LENGTH, ENC_INT32_LENGTH);
					break;

				case CMD_INT64_EXP:
					req->resp = enc_int32_pow(key, req->buffer, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH+ENC_INT32_LENGTH, ENC_INT32_LENGTH);
					break;

				case CMD_INT64_MOD:
					req->resp = enc_int32_mod(key, req->buffer, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH+ENC_INT32_LENGTH, ENC_INT32_LENGTH);
					break;

				case CMD_INT64_CMP:
					req->resp = enc_int32_cmp(key, req->buffer, ENC_INT32_LENGTH, req->buffer+ENC_INT32_LENGTH, ENC_INT32_LENGTH, req->buffer+2*ENC_INT32_LENGTH, INT32_LENGTH);
					break;

				case CMD_INT64_ENC:
					req->resp = encrypt_bytes(key, req->buffer, INT32_LENGTH, req->buffer + INT32_LENGTH, ENC_INT32_LENGTH);
					break;

				case CMD_INT64_DEC:
					req->resp = decrypt_bytes(key, req->buffer, ENC_INT32_LENGTH, req->buffer + ENC_INT32_LENGTH, INT32_LENGTH);
					break;

				case CMD_FLOAT4_PLUS:
					req->resp = enc_float32_add(key, req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer + 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_MINUS:
					req->resp = enc_float32_sub(key, req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer + 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_MULT:
					req->resp = enc_float32_mult(key, req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer + 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_DIV:
					req->resp = enc_float32_div(key, req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer+ 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_EXP:
					req->resp = enc_float32_pow(key, req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer+ 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_MOD:
					req->resp = enc_float32_mod(key, req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer+ 2*ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_CMP:
					req->resp = enc_float32_cmp(key, req->buffer, ENC_FLOAT4_LENGTH, req->buffer+ENC_FLOAT4_LENGTH, ENC_FLOAT4_LENGTH, req->buffer+2*ENC_FLOAT4_LENGTH, INT32_LENGTH);
					break;

				case CMD_FLOAT4_ENC:
					req->resp = encrypt_bytes(key, req->buffer, FLOAT4_LENGTH, req->buffer + FLOAT4_LENGTH, ENC_FLOAT4_LENGTH);
					break;

				case CMD_FLOAT4_DEC:
					req->resp = decrypt_bytes(key, req->buffer, ENC_FLOAT4_LENGTH, req->buffer + ENC_FLOAT4_LENGTH, FLOAT4_LENGTH);
					break;

				case CMD_STRING_CMP:
					memcpy(&src_len, req->buffer,INT32_LENGTH);
					memcpy(src1, req->buffer+INT32_LENGTH,src_len);
					memcpy(&src2_len, req->buffer+INT32_LENGTH + src_len,INT32_LENGTH);
					memcpy(src2, req->buffer+INT32_LENGTH + src_len +INT32_LENGTH,src2_len);
					req->resp = enc_text_cmp(key, src1, src_len, src2, src2_len, req->buffer+2*INT32_LENGTH + src_len + src2_len, INT32_LENGTH);
					break;

				case CMD_STRING_ENC:
					memcpy(&src_len, req->buffer, INT32_LENGTH);
					dst_len = src_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;

					memcpy(src1, req->buffer + INT32_LENGTH, src_len);

					memcpy(req->buffer + INT32_LENGTH + src_len, &dst_len, INT32_LENGTH);
					req->resp = encrypt_bytes(key, src1, src_len, req->buffer + src_len + 2*INT32_LENGTH, dst_len);
					//memcpy(req->buffer + INT32_LENGTH + src_len, &dst_len, INT32_LENGTH);
					//memcpy(req->buffer + src_len + 2*INT32_LENGTH, dst, dst_len);
					break;

				case CMD_STRING_DEC:
					memcpy(&src_len, req->buffer,INT32_LENGTH);
					dst_len = src_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
					memcpy(src1, req->buffer + INT32_LENGTH, src_len);
					req->resp = decrypt_bytes(key, src1, src_len, dst, dst_len);
					memcpy(req->buffer  + INT32_LENGTH + src_len , &dst_len, INT32_LENGTH);
					memcpy(req->buffer+ src_len + 2*INT32_LENGTH, dst, dst_len);
					break;

				case CMD_STRING_LIKE:
					memcpy(&src_len, req->buffer,INT32_LENGTH);
					memcpy(src1, req->buffer+INT32_LENGTH,src_len);
					memcpy(&src2_len, req->buffer+INT32_LENGTH + src_len,INT32_LENGTH);
					memcpy(src2, req->buffer+INT32_LENGTH + src_len +INT32_LENGTH, src2_len);
					req->resp = enc_text_substring(key, src1, src_len, src2, src2_len, req->buffer+2*INT32_LENGTH + src_len + src2_len, INT32_LENGTH);
					break;

				case CMD_STRING_CONCAT:
					memcpy(&src_len, req->buffer, INT32_LENGTH);
					memcpy(src1, req->buffer+INT32_LENGTH, src_len);
					memcpy(&src2_len, req->buffer+INT32_LENGTH + src_len,INT32_LENGTH);
					memcpy(src2, req->buffer+INT32_LENGTH + src_len +INT32_LENGTH,src2_len);
					dst_len = src_len + src2_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

					req->resp = enc_text_concatenate(key, src1, src_len, src2, src2_len, dst, dst_len);
					memcpy(req->buffer+ src_len + 2*INT32_LENGTH + src2_len, &dst_len, INT32_LENGTH);
					memcpy(req->buffer+src_len + 3*INT32_LENGTH + src2_len, dst, dst_len);
					break;

				case CMD_TIMESTAMP_CMP:
					req->resp = enc_timestamp_cmp(key, req->buffer, ENC_TIMESTAMP_LENGTH, req->buffer+ENC_TIMESTAMP_LENGTH, ENC_TIMESTAMP_LENGTH, req->buffer+2*ENC_TIMESTAMP_LENGTH, INT32_LENGTH);
					break;

				case CMD_TIMESTAMP_ENC:
					req->resp = encrypt_bytes(key, req->buffer, TIMESTAMP_LENGTH, req->buffer + TIMESTAMP_LENGTH, ENC_TIMESTAMP_LENGTH);
					break;

				case CMD_TIMESTAMP_DEC:
					req->resp = decrypt_bytes(key, req->buffer, ENC_TIMESTAMP_LENGTH, req->buffer + ENC_TIMESTAMP_LENGTH, TIMESTAMP_LENGTH);
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
