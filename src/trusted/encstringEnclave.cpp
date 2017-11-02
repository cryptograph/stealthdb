#include "enclave.h"
#include "enclave_t.h"  /* print_string */
extern sgx_aes_ctr_128bit_key_t p_key;
// it is a test function, will not be used in future
// decrypt am encrypted char array
int decryptRandEncString(uint8_t *string_src, size_t src_len, uint8_t *string_dst, size_t dst_len) {

	int resp = sgx_rijndael128GCM_decrypt((const sgx_aes_ctr_128bit_key_t*) p_key,
                                string_src + SGX_AESGCM_IV_SIZE,           //cipher
								src_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE,
								string_dst,                                                       // plain out
                                string_src, SGX_AESGCM_IV_SIZE,                                  // nonce
                                 NULL, 0,                                                   // aad
                                 (sgx_aes_gcm_128bit_tag_t *) (string_src + src_len - SGX_AESGCM_MAC_SIZE)); // tag

	return resp;
}

// it is a test function, will not be used in future
// encrypt a string by AES_GCM
int encryptRandEncString(uint8_t *string_src, size_t src_len, uint8_t *string_dst, size_t dst_len) {

	return encryptGCM(string_src, src_len, string_dst, dst_len);

}

/* Compare two encrypted by aes_gcm strings
 @input: uint8_t array - encrypted string1
		 size_t - length of encrypted string1 (max lenght = SGX_AESGCM_IV_SIZE + ??? + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted string2
		 size_t - length of encrypted string2 (SGX_AESGCM_IV_SIZE + ??? + SGX_AESGCM_MAC_SIZE = 32)
 @return:
 * 1, if a > b
 * -1, if b > a
 * 0, if a == b
 * SGX_error, if there was an error during decryption
*/
int compareRandEncString(uint8_t *string1, size_t string1_len, uint8_t *string2, size_t string2_len) {

	uint8_t *dec_string1, *dec_string2;

	if ((string1_len < SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE) || (string2_len < SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE))
		return MEMORY_COPY_ERROR;

	int raw_str1_len = string1_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int raw_str2_len = string2_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int resp;

	try {
		dec_string1 = new uint8_t[raw_str1_len + 1];
		dec_string2 = new uint8_t[raw_str2_len + 1];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	resp = decryptGCM(string1, string1_len, dec_string1, raw_str1_len);
	if (resp != SGX_SUCCESS)
		return resp + 1;

	resp = decryptGCM(string2, string2_len, dec_string2, raw_str2_len);
	if (resp != SGX_SUCCESS)
		return resp + 1;

	dec_string1[raw_str1_len] = dec_string2[raw_str2_len] = '\0';

	resp = strcmp((const char *) dec_string1, (const char *) dec_string2);

	delete dec_string1;
	delete dec_string2;

	return resp;

}

/* Concatenation of two encrypted by aes_gcm strings
 @input: uint8_t array - encrypted integer1
		 size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted integer2
		 size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption
	0, otherwise
*/
int concatRandEncString (	uint8_t *string1, size_t string1_len, uint8_t *string2, size_t string2_len, uint8_t *string3, size_t string3_len){

	uint8_t *dec_string1, *dec_string2, *dec_string3;
	int raw_str1_len = string1_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int raw_str2_len = string2_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int raw_str3_len = raw_str1_len + raw_str2_len;
	int resp;

	try {
		dec_string1 = new uint8_t[raw_str1_len];
		dec_string2 = new uint8_t[raw_str2_len];
		dec_string3 = new uint8_t[raw_str3_len];
		}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	resp = decryptGCM(string1, string1_len, dec_string1, raw_str1_len);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decryptGCM(string2, string2_len, dec_string2, raw_str2_len);
	if (resp != SGX_SUCCESS)
		return resp;

	memcpy(dec_string3, dec_string1, raw_str1_len);
	memcpy(dec_string3+raw_str1_len, dec_string2, raw_str2_len);

	//strncat((char *)dec_string3, (const char *) dec_string2, raw_str2_len);

	resp = encryptGCM(dec_string3, raw_str3_len, string3, string3_len);

	delete dec_string1;
	delete dec_string2;
	delete dec_string3;

	return resp;

}

/* Search for substring in the string (both are encrypted by aes_gcm)
 @input: uint8_t array - encrypted string
		 size_t - length of encrypted string (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted substring
		 size_t - length of encrypted substring (SGX_AESGCM_IV_SIZE + ?? + SGX_AESGCM_MAC_SIZE = 32)
		 @return:
	* SGX_error, if there was an error during encryption/decryption
	0, if the strings contains the substring
	1, it not
*/
int substringRandEncString (uint8_t *string1, size_t string1_len, uint8_t *string2, size_t string2_len){

	uint8_t *dec_string1, *dec_string2;
	int raw_str1_len = string1_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int raw_str2_len = string2_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	int resp = -2;

	try {
		dec_string1 = new uint8_t[raw_str1_len];
		dec_string2 = new uint8_t[raw_str2_len];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}
	resp = decryptGCM(string1, string1_len, dec_string1, raw_str1_len);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decryptGCM(string2, string2_len, dec_string2, raw_str2_len);
	if (resp != SGX_SUCCESS)
		return resp;

	if (strstr((char *)dec_string1, (char *)dec_string2)  != NULL)
		resp = 0;
	else
		resp = 1;

	delete dec_string1;
	delete dec_string2;

	return resp;

}
