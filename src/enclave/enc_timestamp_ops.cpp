//
// ENCRYPTED TIMESTAMPS(8 bytes) FUNCTIONs
//
#include "enclave/enclave.h"
#include "enclave/enclave_t.h"  /* print_string */

/* Compare two encrypted timestamps(int64 - 8 bytes) by aes_gcm algorithm
 * @input:
 * 		 sgx_aes_ctr_128bit_key_t key - pointer to the master key
 * 		 uint8_t array - encrypted source1
		 size_t - length of encrypted source1 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 36)
		 uint8_t array - encrypted source2
		 size_t - length of encrypted source2 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 36)

		 uint8_t array - which contains the result  1 (if a > b). -1 (if b > a), 0 (if a == b)
		 size_t - length of result (TIMESTAMP_LENGTH = 4)

 @return:
 * SGX_error, if there was an error during decryption
*/
int enc_timestamp_cmp(sgx_aes_ctr_128bit_key_t* key, uint8_t *src1, size_t src1_len, uint8_t *src2, size_t src2_len, uint8_t *result, size_t res_len) {

	TIMESTAMP dectm1, dectm2;
	int resp, cmp;

	uint8_t *src1_decrypted = (uint8_t *)malloc(TIMESTAMP_LENGTH);
	uint8_t *src2_decrypted = (uint8_t *)malloc(TIMESTAMP_LENGTH);

	resp = decrypt_bytes(key, src1, src1_len, src1_decrypted, TIMESTAMP_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decrypt_bytes(key, src2, src2_len, src2_decrypted, TIMESTAMP_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	memcpy(&dectm1, src1_decrypted, TIMESTAMP_LENGTH);
	memcpy(&dectm2, src2_decrypted, TIMESTAMP_LENGTH);

	cmp = (dectm1 == dectm2) ? 0 : ((dectm1 < dectm2) ? -1 : 1);

	memcpy(result, &cmp, INT32_LENGTH);

	memset_s(src1_decrypted, TIMESTAMP_LENGTH, 0, TIMESTAMP_LENGTH);
	memset_s(src2_decrypted, TIMESTAMP_LENGTH, 0, TIMESTAMP_LENGTH);
	memset_s(&dectm1, TIMESTAMP_LENGTH, 0, TIMESTAMP_LENGTH);
	memset_s(&dectm2, TIMESTAMP_LENGTH, 0, TIMESTAMP_LENGTH);
	free_allocated_memory(src1_decrypted);
	free_allocated_memory(src2_decrypted);

	return resp;

}
