//
// ENCRYPTED TIMESTAMPS(8 bytes) FUNCTIONs
//
#include "enclave.h"
#include "enclave_t.h"  /* print_string */
extern sgx_aes_ctr_128bit_key_t p_key;
/* Compare two encrypted timestamps(int64 - 8 bytes) by aes_gcm algorithm
 @input: uint8_t array - encrypted source1
		 size_t - length of encrypted source1 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 36)
		 uint8_t array - encrypted source2
		 size_t - length of encrypted source2 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 36)
 @return:
 * 1, if a > b
 * -1, if b > a
 * 0, if a == b
 * SGX_error, if there was an error during decryption
*/
int compareRandEncTimestamp(uint8_t *src1, size_t src1_len, uint8_t *src2, size_t src2_len) {

	uint8_t *dec_src1, *dec_src2;
	long long int dectm1, dectm2;
	int resp;

	try {
		dec_src1 = new uint8_t[TIMESTAMP_LENGTH];
		dec_src2 = new uint8_t[TIMESTAMP_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	resp = decryptGCM(src1, src1_len, dec_src1, TIMESTAMP_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decryptGCM(src2, src2_len, dec_src2, TIMESTAMP_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	memcpy(&dectm1, dec_src1, TIMESTAMP_LENGTH);
	memcpy(&dectm2, dec_src2, TIMESTAMP_LENGTH);

	resp = (dectm1 == dectm2) ? 0 : ((dectm1 < dectm2) ? -1 : 1);

	delete dec_src1;
	delete dec_src2;

	return resp;

}
