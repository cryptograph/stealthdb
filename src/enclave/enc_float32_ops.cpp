#include "enclave/enclave.h"
#include "enclave/enclave_t.h"  /* print_string */

/* Compare two encrypted by aes_gcm algorithm float numbers
 @input: sgx_aes_ctr_128bit_key_t key - pointer to the master key
		 uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted src2
		 size_t - length of encrypted src2 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - which contains the result  1 (if a > b). -1 (if b > a), 0 (if a == b)
		 size_t - length of result (INT64_LENGTH = 4)

 @return:
 * SGX_error, if there was an error during decryption 
*/
int enc_float32_cmp(sgx_aes_ctr_128bit_key_t*  key, uint8_t *src1, size_t src1_len, uint8_t *src2, size_t src2_len, uint8_t *result, size_t res_len) {

	float decfloat1, decfloat2;
	int resp;
	int cmp = 0;

    uint8_t *pSrc1_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pSrc2_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);

	resp = decrypt_bytes(key, src1, src1_len, pSrc1_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decrypt_bytes(key, src2, src2_len, pSrc2_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	memcpy(&decfloat1, pSrc1_decrypted, FLOAT4_LENGTH);
	memcpy(&decfloat2, pSrc2_decrypted, FLOAT4_LENGTH);

	cmp = (decfloat1 == decfloat2) ? 0 : (decfloat1 < decfloat2) ? -1 : 1;

	memcpy(result, &cmp, res_len);
	
	memset_s(pSrc1_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pSrc2_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat1, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat2, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	free_allocated_memory(pSrc1_decrypted);
	free_allocated_memory(pSrc2_decrypted);

	return resp;

}

/* Sum of two encrypted by aes_gcm float numbers
 @input: sgx_aes_ctr_128bit_key_t key - pointer to the master key
		 uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted src2
		 size_t - length of encrypted src2 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int enc_float32_add (sgx_aes_ctr_128bit_key_t*  key, uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	float decfloat1, decfloat2, decfloat3;
	int resp;

    uint8_t *pSrc1_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pSrc2_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pDst_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);

	resp = decrypt_bytes(key, pSrc1, src1_len, pSrc1_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decrypt_bytes(key, pSrc2, src2_len, pSrc2_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, pSrc1_decrypted, FLOAT4_LENGTH);
	memcpy(&decfloat2, pSrc2_decrypted, FLOAT4_LENGTH);

	decfloat3 = decfloat1 + decfloat2;

	// 
	 /* comment from PSQL code 
	  * There isn't any way to check for underflow of addition/subtraction
      * because numbers near the underflow value have already been rounded to
      * the point where we can't detect that the two values were originally
      * different, e.g. on x86, '1e-45'::float4 == '2e-45'::float4 ==
      * 1.4013e-45.
     */
	// we have only 4 bytes for float4 datatype
	// we can check if the result size is less 8^4

	memcpy(pDst_decrypted, &decfloat3, FLOAT4_LENGTH);

	resp = encrypt_bytes(key, pDst_decrypted, FLOAT4_LENGTH, pDst, dst_len);

	memset_s(pSrc1_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pSrc2_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pDst_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	memset_s(&decfloat1, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat2, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat3, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	free_allocated_memory(pSrc1_decrypted);
	free_allocated_memory(pSrc2_decrypted);
	free_allocated_memory(pDst_decrypted);

	return resp;
}

/* Substraction of two encrypted by aes_gcm float numbers
 @input: sgx_aes_ctr_128bit_key_t key - pointer to the master key
		 uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted src2
		 size_t - length of encrypted src2 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int enc_float32_sub (sgx_aes_ctr_128bit_key_t*  key, uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	float decfloat1, decfloat2, decfloat3;
	int resp;

    uint8_t *pSrc1_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pSrc2_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pDst_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);

	resp = decrypt_bytes(key, pSrc1, src1_len, pSrc1_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decrypt_bytes(key, pSrc2, src2_len, pSrc2_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, pSrc1_decrypted, FLOAT4_LENGTH);
	memcpy(&decfloat2, pSrc2_decrypted, FLOAT4_LENGTH);

	decfloat3 = decfloat1 - decfloat2;

	//
	 /* comment from PSQL code
	  * There isn't any way to check for underflow of addition/subtraction
      * because numbers near the underflow value have already been rounded to
      * the point where we can't detect that the two values were originally
      * different, e.g. on x86, '1e-45'::float4 == '2e-45'::float4 ==
      * 1.4013e-45.
     */
	// we have only 4 bytes for float4 datatype
	// we can check if the result size is less 8^4

	memcpy(pDst_decrypted, &decfloat3, FLOAT4_LENGTH);

	resp = encrypt_bytes(key, pDst_decrypted, FLOAT4_LENGTH, pDst, dst_len);

	memset_s(pSrc1_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pSrc2_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pDst_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	memset_s(&decfloat1, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat2, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat3, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	free_allocated_memory(pSrc1_decrypted);
	free_allocated_memory(pSrc2_decrypted);
	free_allocated_memory(pDst_decrypted);

	return resp;
}

/* Multiplication of two encrypted by aes_gcm float numbers
 @input: sgx_aes_ctr_128bit_key_t key - pointer to the master key
		 uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted src2
		 size_t - length of encrypted src2 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int enc_float32_mult (sgx_aes_ctr_128bit_key_t*  key, uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	float decfloat1, decfloat2, decfloat3;
	int resp;

    uint8_t *pSrc1_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pSrc2_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pDst_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);

	resp = decrypt_bytes(key, pSrc1, src1_len, pSrc1_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decrypt_bytes(key, pSrc2, src2_len, pSrc2_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, pSrc1_decrypted, FLOAT4_LENGTH);
	memcpy(&decfloat2, pSrc2_decrypted, FLOAT4_LENGTH);

	//TODO: check postgres implementation for overflow
	decfloat3 = decfloat1 * decfloat2;

	memcpy(pDst_decrypted, &decfloat3, FLOAT4_LENGTH);

	resp = encrypt_bytes(key, pDst_decrypted, FLOAT4_LENGTH, pDst, dst_len);

	memset_s(pSrc1_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pSrc2_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pDst_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	memset_s(&decfloat1, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat2, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat3, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	free_allocated_memory(pSrc1_decrypted);
	free_allocated_memory(pSrc2_decrypted);
	free_allocated_memory(pDst_decrypted);

	return resp;
}


/* Power operation of two encrypted by aes_gcm float numbers
 @input: sgx_aes_ctr_128bit_key_t key - pointer to the master key
	     uint8_t array - encrypted float base
		 size_t - length of encrypted base (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted float exponent
		 size_t - length of encrypted exponent (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int enc_float32_pow (sgx_aes_ctr_128bit_key_t*  key, uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	float decfloat1, decfloat2, decfloat3;
	int resp;

    uint8_t *pSrc1_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pSrc2_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pDst_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);

	resp = decrypt_bytes(key, pSrc1, src1_len, pSrc1_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decrypt_bytes(key, pSrc2, src2_len, pSrc2_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, pSrc1_decrypted, FLOAT4_LENGTH);
	memcpy(&decfloat2, pSrc2_decrypted, FLOAT4_LENGTH);

	//TODO: check postgres implementation for overflow
	decfloat3 = pow(decfloat1, decfloat2);

	memcpy(pDst_decrypted, &decfloat3, FLOAT4_LENGTH);

	resp = encrypt_bytes(key, pDst_decrypted, FLOAT4_LENGTH, pDst, dst_len);

	memset_s(pSrc1_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pSrc2_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pDst_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	memset_s(&decfloat1, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat2, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat3, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	free_allocated_memory(pSrc1_decrypted);
	free_allocated_memory(pSrc2_decrypted);
	free_allocated_memory(pDst_decrypted);

	return resp;

}
		
/* Division of two encrypted by aes_gcm float numbers
 @input: sgx_aes_ctr_128bit_key_t key - pointer to the master key
		 uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted src2
		 size_t - length of encrypted src3 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int enc_float32_div (sgx_aes_ctr_128bit_key_t*  key, uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	float decfloat1, decfloat2, decfloat3;
	int resp;

    uint8_t *pSrc1_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pSrc2_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pDst_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);

	resp = decrypt_bytes(key, pSrc1, src1_len, pSrc1_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decrypt_bytes(key, pSrc2, src2_len, pSrc2_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, pSrc1_decrypted, FLOAT4_LENGTH);
	memcpy(&decfloat2, pSrc2_decrypted, FLOAT4_LENGTH);

	if (decfloat2 == 0)
		return ARITHMETIC_ERROR;
	decfloat3 = decfloat1 / decfloat2;

	memcpy(pDst_decrypted, &decfloat3, FLOAT4_LENGTH);

	resp = encrypt_bytes(key, pDst_decrypted, FLOAT4_LENGTH, pDst, dst_len);

	memset_s(pSrc1_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pSrc2_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pDst_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	memset_s(&decfloat1, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat2, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat3, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	free_allocated_memory(pSrc1_decrypted);
	free_allocated_memory(pSrc2_decrypted);
	free_allocated_memory(pDst_decrypted);

	return resp;

}

/* Module operation of two encrypted by aes_gcm float numbers
 @input: sgx_aes_ctr_128bit_key_t key - pointer to the master key
	     uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted module 
		 size_t - length of encrypted module (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result 
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int enc_float32_mod (sgx_aes_ctr_128bit_key_t*  key, uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	float decfloat1, decfloat2, decfloat3;
	int resp;

    uint8_t *pSrc1_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pSrc2_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);
    uint8_t *pDst_decrypted = (uint8_t *)malloc(FLOAT4_LENGTH);

	resp = decrypt_bytes(key, pSrc1, src1_len, pSrc1_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decrypt_bytes(key, pSrc2, src2_len, pSrc2_decrypted, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, pSrc1_decrypted, FLOAT4_LENGTH);
	memcpy(&decfloat2, pSrc2_decrypted, FLOAT4_LENGTH);

	//TODO: not sure it is right, check postgres implementation
	decfloat3 = (int)decfloat1 % (int)decfloat2;

	memcpy(pDst_decrypted, &decfloat3, FLOAT4_LENGTH);

	resp = encrypt_bytes(key, pDst_decrypted, FLOAT4_LENGTH, pDst, dst_len);

	memset_s(pSrc1_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pSrc2_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(pDst_decrypted, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	memset_s(&decfloat1, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat2, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);
	memset_s(&decfloat3, FLOAT4_LENGTH, 0, FLOAT4_LENGTH);

	free_allocated_memory(pSrc1_decrypted);
	free_allocated_memory(pSrc2_decrypted);
	free_allocated_memory(pDst_decrypted);

	return resp;

}
