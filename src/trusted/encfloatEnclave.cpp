#include "enclave.h"
#include "enclave_t.h"  /* print_string */
extern sgx_aes_ctr_128bit_key_t p_key;

//
// ENCRYPTED FLOAT(4 bytes) FUNCTIONs
//
// it is a test function, will not be used in future
// decrypt a char array and return an float
float decryptRandEncFloat(uint8_t *fl1, size_t fl1_len, uint8_t *fl2, size_t fl2_len) {

	float decfloat1;
	int resp = decryptGCM(fl1, fl1_len, fl2, fl2_len);

	if (fl2_len < FLOAT4_LENGTH)
		return MEMORY_COPY_ERROR;
	memcpy(&decfloat1, fl2, FLOAT4_LENGTH);

	return decfloat1;
}

// it is a test function, will not be used in future
// encrypt a float number by AES_GCM
int encryptRandEncFloat(uint8_t *pSrc, size_t src_len, uint8_t *pDst, size_t dst_len) {

	if (src_len != FLOAT4_LENGTH) 
		return MEMORY_COPY_ERROR;

	return encryptGCM(pSrc, src_len, pDst, dst_len);
}

/* Compare two encrypted by aes_gcm algorithm float numbers
 @input: uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted src2
		 size_t - length of encrypted src2 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
 * 1, if a > b 
 * -1, if b > a 
 * 0, if a == b
 * SGX_error, if there was an error during decryption 
*/
int compareRandEncFloat(uint8_t *src1, size_t src1_len, uint8_t *src2, size_t src2_len) {
	uint8_t *dec_fl1, *dec_fl2;
	float decfloat1, decfloat2;
	int resp;

	try {
		dec_fl1 = new uint8_t[FLOAT4_LENGTH];
		dec_fl2 = new uint8_t[FLOAT4_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	resp = decryptGCM(src1, src1_len, dec_fl1, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decryptGCM(src2, src2_len, dec_fl2, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	memcpy(&decfloat1, dec_fl1, FLOAT4_LENGTH);
	memcpy(&decfloat2, dec_fl2, FLOAT4_LENGTH);

	resp = (decfloat1 == decfloat2) ? 0 : (decfloat1 < decfloat2) ? -1 : 1;
	
	delete dec_fl1;
	delete dec_fl2;

	return resp;

}

/* Sum of two encrypted by aes_gcm float numbers
 @input: uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted src2
		 size_t - length of encrypted src2 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int addRandEncFloat (uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	uint8_t *dec_src1, *dec_src2, *dec_src3;
	float decfloat1, decfloat2, decfloat3;
	int resp;

	try {
		dec_src1 = new uint8_t[FLOAT4_LENGTH];
		dec_src2 = new uint8_t[FLOAT4_LENGTH];
		dec_src3 = new uint8_t[FLOAT4_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	resp = decryptGCM(pSrc1, src1_len, dec_src1, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decryptGCM(pSrc2, src2_len, dec_src2, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, dec_src1, FLOAT4_LENGTH);
	memcpy(&decfloat2, dec_src2, FLOAT4_LENGTH);

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

	memcpy(dec_src3, &decfloat3, FLOAT4_LENGTH);

	resp = encryptGCM(dec_src3, FLOAT4_LENGTH, pDst, dst_len);

	delete dec_src1;
	delete dec_src2;
	delete dec_src3;

	return resp;
}

/* Substraction of two encrypted by aes_gcm float numbers
 @input: uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted src2
		 size_t - length of encrypted src2 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int subsRandEncFloat (uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	uint8_t *dec_src1, *dec_src2, *dec_src3;
	float decfloat1, decfloat2, decfloat3;
	int resp;

	try {
		dec_src1 = new uint8_t[FLOAT4_LENGTH];
		dec_src2 = new uint8_t[FLOAT4_LENGTH];
		dec_src3 = new uint8_t[FLOAT4_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	resp = decryptGCM(pSrc1, src1_len, dec_src1, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decryptGCM(pSrc2, src2_len, dec_src2, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, dec_src1, FLOAT4_LENGTH);
	memcpy(&decfloat2, dec_src2, FLOAT4_LENGTH);

	decfloat3 = decfloat1 - decfloat2;

	memcpy(dec_src3, &decfloat3, FLOAT4_LENGTH);

	resp = encryptGCM(dec_src3, FLOAT4_LENGTH, pDst, dst_len);

	delete dec_src1;
	delete dec_src2;
	delete dec_src3;

	return resp;
}

/* Multiplication of two encrypted by aes_gcm float numbers
 @input: uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted src2
		 size_t - length of encrypted src2 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int multRandEncFloat (uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	uint8_t *dec_src1, *dec_src2, *dec_src3;
	float decfloat1, decfloat2, decfloat3;
	int resp;

	try {
		dec_src1 = new uint8_t[FLOAT4_LENGTH];
		dec_src2 = new uint8_t[FLOAT4_LENGTH];
		dec_src3 = new uint8_t[FLOAT4_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	resp = decryptGCM(pSrc1, src1_len, dec_src1, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decryptGCM(pSrc2, src2_len, dec_src2, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, dec_src1, FLOAT4_LENGTH);
	memcpy(&decfloat2, dec_src2, FLOAT4_LENGTH);

	decfloat3 = decfloat1 * decfloat2;

	memcpy(dec_src3, &decfloat3, FLOAT4_LENGTH);

	resp = encryptGCM(dec_src3, FLOAT4_LENGTH, pDst, dst_len);

	delete dec_src1;
	delete dec_src2;
	delete dec_src3;

	return resp;
}

/* Power operation of two encrypted by aes_gcm float numbers
 @input: uint8_t array - encrypted float base
		 size_t - length of encrypted base (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted float exponent
		 size_t - length of encrypted exponent (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int expRandEncFloat (uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	uint8_t *dec_src1, *dec_src2, *dec_src3;
	float decfloat1, decfloat2, decfloat3;
	int resp;

	try {
		dec_src1 = new uint8_t[FLOAT4_LENGTH];
		dec_src2 = new uint8_t[FLOAT4_LENGTH];
		dec_src3 = new uint8_t[FLOAT4_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	resp = decryptGCM(pSrc1, src1_len, dec_src1, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decryptGCM(pSrc2, src2_len, dec_src2, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, dec_src1, FLOAT4_LENGTH);
	memcpy(&decfloat2, dec_src2, FLOAT4_LENGTH);

	decfloat3 = pow(decfloat1, decfloat2);

	memcpy(dec_src3, &decfloat3, FLOAT4_LENGTH);

	resp = encryptGCM(dec_src3, FLOAT4_LENGTH, pDst, dst_len);

	delete dec_src1;
	delete dec_src2;
	delete dec_src3;

	return resp;
}
		
/* Division of two encrypted by aes_gcm float numbers
 @input: uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted src2
		 size_t - length of encrypted src3 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int divRandEncFloat (uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	uint8_t *dec_src1, *dec_src2, *dec_src3;
	float decfloat1, decfloat2, decfloat3;
	int resp;

	try {
		dec_src1 = new uint8_t[FLOAT4_LENGTH];
		dec_src2 = new uint8_t[FLOAT4_LENGTH];
		dec_src3 = new uint8_t[FLOAT4_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	resp = decryptGCM(pSrc1, src1_len, dec_src1, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decryptGCM(pSrc2, src2_len, dec_src2, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, dec_src1, FLOAT4_LENGTH);
	memcpy(&decfloat2, dec_src2, FLOAT4_LENGTH);

	if (decfloat2 == 0)
		return ARITHMETIC_ERROR;
	decfloat3 = decfloat1 / decfloat2;

	memcpy(dec_src3, &decfloat3, FLOAT4_LENGTH);

	resp = encryptGCM(dec_src3, FLOAT4_LENGTH, pDst, dst_len);

	delete dec_src1;
	delete dec_src2;
	delete dec_src3;

	return resp;
}

/* Module operation of two encrypted by aes_gcm float numbers
 @input: uint8_t array - encrypted src1
		 size_t - length of encrypted src1 (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted module 
		 size_t - length of encrypted module (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result 
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int modRandEncFloat (uint8_t *pSrc1, size_t src1_len, uint8_t *pSrc2, size_t src2_len, uint8_t *pDst, size_t dst_len){

	uint8_t *dec_src1, *dec_src2, *dec_src3;
	float decfloat1, decfloat2, decfloat3;
	int resp;

	try {
		dec_src1 = new uint8_t[FLOAT4_LENGTH];
		dec_src2 = new uint8_t[FLOAT4_LENGTH];
		dec_src3 = new uint8_t[FLOAT4_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}

	resp = decryptGCM(pSrc1, src1_len, dec_src1, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decryptGCM(pSrc2, src2_len, dec_src2, FLOAT4_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	memcpy(&decfloat1, dec_src1, FLOAT4_LENGTH);
	memcpy(&decfloat2, dec_src2, FLOAT4_LENGTH);

	decfloat3 = (int)decfloat1 % (int)decfloat2;

	memcpy(dec_src3, &decfloat3, FLOAT4_LENGTH);

	resp = encryptGCM(dec_src3, FLOAT4_LENGTH, pDst, dst_len);

	delete dec_src1;
	delete dec_src2;
	delete dec_src3;

	return resp;
}
