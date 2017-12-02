#include "enclave/enclave.h"
#include "enclave/enclave_t.h"  /* print_string */

/* Compare two encrypted by aes_gcm strings
 * @input:
 * 		sgx_aes_ctr_128bit_key_t key - pointer to the master key
 * 		uint8_t array - encrypted string1
		 size_t - length of encrypted string1 (max lenght = SGX_AESGCM_IV_SIZE + ??? + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted string2
		 size_t - length of encrypted string2 (SGX_AESGCM_IV_SIZE + ??? + SGX_AESGCM_MAC_SIZE = 32)

		 uint8_t array - which contains the result  1 (if a > b). -1 (if b > a), 0 (if a == b)
		 size_t - length of result (INT32_LENGTH = 4)

 @return:
 * SGX_error, if there was an error during decryption
*/
int enc_text_cmp(sgx_aes_ctr_128bit_key_t* key, uint8_t *string1, size_t string1_len, uint8_t *string2, size_t string2_len, uint8_t *result, size_t res_len) {

	if ((string1_len < SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE) || (string2_len < SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE))
		return MEMORY_COPY_ERROR;

	int raw_str1_len = string1_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int raw_str2_len = string2_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int resp, cmp;
    uint8_t *dec_string1 = (uint8_t *)malloc(raw_str1_len+1);
    uint8_t *dec_string2 = (uint8_t *)malloc(raw_str2_len+1);

	resp = decrypt_bytes(key, string1, string1_len, dec_string1, raw_str1_len);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decrypt_bytes(key, string2, string2_len, dec_string2, raw_str2_len);
	if (resp != SGX_SUCCESS)
		return resp;

	dec_string1[raw_str1_len] = dec_string2[raw_str2_len] = '\0';

	cmp = strcmp((const char *) dec_string1, (const char *) dec_string2);

	memcpy(result, &cmp, INT32_LENGTH);

	memset_s(dec_string1, raw_str1_len+1, 0, raw_str1_len+1);
	memset_s(dec_string2, raw_str2_len+1, 0, raw_str2_len+1);

	free_allocated_memory(dec_string1);
	free_allocated_memory(dec_string2);

	return resp;

}

/* Concatenation of two encrypted by aes_gcm strings
 @input: sgx_aes_ctr_128bit_key_t key - pointer to the master key
 	 	 uint8_t array - encrypted integer1
		 size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted integer2
		 size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption
	0, otherwise
*/
int enc_text_concatenate(sgx_aes_ctr_128bit_key_t* key, uint8_t *string1, size_t string1_len, uint8_t *string2, size_t string2_len, uint8_t *string3, size_t string3_len){

	int raw_str1_len = string1_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int raw_str2_len = string2_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int raw_str3_len = string3_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int resp;

    uint8_t *dec_string1 = (uint8_t *)malloc(raw_str1_len+1);
    uint8_t *dec_string2 = (uint8_t *)malloc(raw_str2_len+1);
    uint8_t *dec_string3 = (uint8_t *)malloc(raw_str3_len+1);

	resp = decrypt_bytes(key, string1, string1_len, dec_string1, raw_str1_len);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decrypt_bytes(key, string2, string2_len, dec_string2, raw_str2_len);
	if (resp != SGX_SUCCESS)
		return resp;

	memcpy(dec_string3, dec_string1, raw_str1_len);
	memcpy(dec_string3 + raw_str1_len, dec_string2, raw_str2_len);

	resp = encrypt_bytes(key, dec_string3, raw_str3_len, string3, string3_len);

	memset_s(dec_string1, raw_str1_len+1, 0, raw_str1_len+1);
	memset_s(dec_string2, raw_str2_len+1, 0, raw_str2_len+1);
	memset_s(dec_string3, raw_str3_len+1, 0, raw_str3_len+1);

	free_allocated_memory(dec_string1);
	free_allocated_memory(dec_string2);
	free_allocated_memory(dec_string3);

	return resp;

}

/* Search for substring in the string (both are encrypted by aes_gcm)
 @input: sgx_aes_ctr_128bit_key_t key - pointer to the master key
 	 	 uint8_t array - encrypted string
		 size_t - length of encrypted string (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted substring
		 size_t - length of encrypted substring (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
		 @return:
	* SGX_error, if there was an error during encryption/decryption
	0, if the strings contains the substring
	1, it not
*/
int enc_text_substring(sgx_aes_ctr_128bit_key_t* key, uint8_t *string1, size_t string1_len, uint8_t *string2, size_t string2_len, uint8_t *result, size_t res_len){

	int raw_str1_len = string1_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int raw_str2_len = string2_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int resp, cmp;
    uint8_t *dec_string1 = (uint8_t *)malloc(raw_str1_len + 1);
    uint8_t *dec_string2 = (uint8_t *)malloc(raw_str2_len + 1);


	resp = decrypt_bytes(key, string1, string1_len, dec_string1, raw_str1_len);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decrypt_bytes(key, string2, string2_len, dec_string2, raw_str2_len);
	if (resp != SGX_SUCCESS)
		return resp;

	if (strstr((char *)dec_string1, (char *)dec_string2)  != NULL)
		cmp = 0;
	else
		cmp = 1;

	memcpy(result, &cmp, INT32_LENGTH);

	memset_s(dec_string1, raw_str1_len+1, 0, raw_str1_len+1);
	memset_s(dec_string2, raw_str2_len+1, 0, raw_str2_len+1);
	free_allocated_memory(dec_string1);
	free_allocated_memory(dec_string2);

	return resp;

}
