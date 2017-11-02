#include "enclave.h"
#include "enclave_t.h"  /* print_string */
extern sgx_aes_ctr_128bit_key_t p_key;

/* Convert an integer to a byte array.
	Should pay attention to the endian.
	@input: src - integer 
		 pDst - pointer to the result array with size INT64_LENGTH
		 dstLen - length of the array
	@return:
		1, if the size of array is less than INT64_LENGTH
		0 otherwise
*/
int int2bytearray(int src, uint8_t *pDst, size_t dstLen) {

	if (dstLen <  INT64_LENGTH)
		return 1;

	memcpy(pDst, &src, INT64_LENGTH);

	/*pDst[0] = (src >> 24) & 0xFF;
	pDst[1] = (src >> 16) & 0xFF;
	pDst[2] = (src >> 8) & 0xFF;
	pDst[3] = src & 0xFF;
	*/
	return 0;
}

/* Convert an array to an integer.
	Should pay attention to the endian.
	@input: 
		pDst - pointer to the result array with size INT64_LENGTH
		src - output integer  
		dstLen - length of the array
	@return:
		1, if the size of array is less than INT64_LENGTH
		0 otherwise

		*/
int bytearray2int(uint8_t *pSrc, int &dst, size_t srcLen) {
	
	if (srcLen <  INT64_LENGTH)
		return 1;
	
	memcpy(&dst, pSrc, INT64_LENGTH);
	
	/*src = int((unsigned char)(pDst[0]) << 24 |
            (unsigned char)(pDst[1]) << 16 |
            (unsigned char)(pDst[2]) << 8 |
            (unsigned char)(pDst[3]));
			*/
	return 0;
}

// it is a test function, will not be used in future
// decrypt a char array and return an integer
int decryptRandEncInt(uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len) {

	int decint1_int;
	int resp = decryptGCM(int1, int1_len, int2, int2_len);

	return resp;
}

// it is a test function, will not be used in future
// encrypt the integer by AES_GCM
int encryptRandEncInt(uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len) {

	if (int1_len != INT64_LENGTH) 
		return MEMORY_COPY_ERROR;

	return encryptGCM(int1, int1_len, int2, int2_len);
}

/* Compare two encrypted by aes_gcm algorithm integers
 @input: uint8_t array - encrypted integer1
		 size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted integer2
		 size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
 * 1, if a > b 
 * -1, if b > a 
 * 0, if a == b
 * SGX_error, if there was an error during decryption 
 * -MEMORY_COPY_ERROR, if there was an memory copy error
*/

int compareRandEncInt(uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *result, size_t res_len) {
	
	uint8_t *dec_int1, *dec_int2;
	int32_t decint1_int, decint2_int;
	int resp, cmp;

    uint8_t *dec_int1_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int2_v = (uint8_t *)malloc(INT64_LENGTH);

	resp = decryptGCM(int1, int1_len, dec_int1_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decryptGCM(int2, int2_len, dec_int2_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	if (bytearray2int(dec_int1_v, decint1_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	if (bytearray2int(dec_int2_v, decint2_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	cmp = (decint1_int == decint2_int) ? 0 : (decint1_int < decint2_int) ? -1 : 1;

	memcpy(result, &cmp, res_len);
	
	memset_s(dec_int1_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int2_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(&decint1_int, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(&decint2_int, INT64_LENGTH, 0, INT64_LENGTH);
	free_allocated_memory(dec_int1_v);
	free_allocated_memory(dec_int2_v);

	return resp;

}
/* Sum of two encrypted by aes_gcm integers
 @input: uint8_t array - encrypted integer1
		 size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted integer2
		 size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int addRandEncInt (	uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *int3, size_t int3_len){

	uint8_t *dec_int1, *dec_int2, *dec_int3;
	int32_t decint1_int, decint2_int;
	int64_t decint3_int;
	int resp;
	/*
	try {
		dec_int1 = new uint8_t[INT64_LENGTH];
		dec_int2 = new uint8_t[INT64_LENGTH];
		dec_int3 = new uint8_t[INT64_LENGTH];
	}
	catch (std::bad_alloc) {
		return MEMORY_ALLOCATION_ERROR;
	}
*/
    uint8_t *dec_int1_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int2_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int3_v = (uint8_t *)malloc(INT64_LENGTH);

    if(!dec_int1_v || !dec_int2_v || !dec_int3_v)
    {
    	return MEMORY_ALLOCATION_ERROR;;
    }

	resp = decryptGCM(int1, int1_len, dec_int1_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decryptGCM(int2, int2_len, dec_int2_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	if (bytearray2int(dec_int1_v, decint1_int, INT64_LENGTH))
		return MEMORY_COPY_ERROR;
	if (bytearray2int(dec_int2_v, decint2_int, INT64_LENGTH))
		return MEMORY_COPY_ERROR;

	decint3_int = (int64_t) decint1_int + (int64_t) decint2_int;

	if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) || 
		(decint2_int > INT32_MAX || decint2_int < INT32_MIN) || 
		(decint3_int > INT32_MAX || decint3_int < INT32_MIN))
		 return OUT_OF_THE_RANGE_ERROR;

	if (int2bytearray((int32_t) decint3_int, dec_int3_v, INT64_LENGTH))
		return MEMORY_COPY_ERROR;

	resp = encryptGCM(dec_int3_v, INT64_LENGTH, int3, int3_len);

	memset_s(dec_int1_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int2_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int3_v, INT64_LENGTH, 0, INT64_LENGTH);

	memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));


	free_allocated_memory(dec_int1_v);
	free_allocated_memory(dec_int2_v);
	free_allocated_memory(dec_int3_v);
	/*delete dec_int1;
	delete dec_int2;
	delete dec_int3;
*/
	return resp;

}

/* Substraction of two encrypted by aes_gcm integers
 @input: uint8_t array - encrypted integer1
		 size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted integer2
		 size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/

int subsRandEncInt (uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *int3, size_t int3_len){

	int32_t decint1_int, decint2_int;
	int64_t decint3_int;
	int resp;

    uint8_t *dec_int1_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int2_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int3_v = (uint8_t *)malloc(INT64_LENGTH);

	resp = decryptGCM(int1, int1_len, dec_int1_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
	
	resp = decryptGCM(int2, int2_len, dec_int2_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;
		
	if (bytearray2int(dec_int1_v, decint1_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	if (bytearray2int(dec_int2_v, decint2_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	decint3_int = (int64_t) decint1_int - (int64_t) decint2_int;

	if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) || 
		(decint2_int > INT32_MAX || decint2_int < INT32_MIN) || 
		(decint3_int > INT32_MAX || decint3_int < INT32_MIN))
		 return OUT_OF_THE_RANGE_ERROR;

	if (int2bytearray((int32_t) decint3_int, dec_int3_v, INT64_LENGTH))
		return MEMORY_COPY_ERROR;

	resp = encryptGCM(dec_int3_v, INT64_LENGTH, int3, int3_len);

	memset_s(dec_int1_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int2_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int3_v, INT64_LENGTH, 0, INT64_LENGTH);

	memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));

	free_allocated_memory(dec_int1_v);
	free_allocated_memory(dec_int2_v);
	free_allocated_memory(dec_int3_v);
		
	return resp;
}

/* Multiplication of two encrypted by aes_gcm integers
 @input: uint8_t array - encrypted integer1
		 size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted integer2
		 size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int multRandEncInt (	uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *int3, size_t int3_len){

	int32_t decint1_int, decint2_int;
	int64_t decint3_int;
	int resp;

    uint8_t *dec_int1_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int2_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int3_v = (uint8_t *)malloc(INT64_LENGTH);

	resp = decryptGCM(int1, int1_len, dec_int1_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decryptGCM(int2, int2_len, dec_int2_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	if (bytearray2int(dec_int1_v, decint1_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	if (bytearray2int(dec_int2_v, decint2_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	decint3_int = decint1_int * decint2_int;

	if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) ||
		(decint2_int > INT32_MAX || decint2_int < INT32_MIN) ||
		(decint1_int != 0 && decint3_int/decint1_int != decint2_int ))
		 return OUT_OF_THE_RANGE_ERROR;

	if (int2bytearray((int32_t) decint3_int, dec_int3_v, INT64_LENGTH))
		return MEMORY_COPY_ERROR;

	resp = encryptGCM(dec_int3_v, INT64_LENGTH, int3, int3_len);

	memset_s(dec_int1_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int2_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int3_v, INT64_LENGTH, 0, INT64_LENGTH);

	memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));

	free_allocated_memory(dec_int1_v);
	free_allocated_memory(dec_int2_v);
	free_allocated_memory(dec_int3_v);

	return resp;
}

/* Module operation of two encrypted by aes_gcm integers
 @input: uint8_t array - encrypted integer1
		 size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted module
		 size_t - length of encrypted module (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int modRandEncInt (	uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *int3, size_t int3_len){

	int32_t decint1_int, decint2_int;
	int64_t decint3_int;
	int resp;

    uint8_t *dec_int1_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int2_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int3_v = (uint8_t *)malloc(INT64_LENGTH);

	resp = decryptGCM(int1, int1_len, dec_int1_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decryptGCM(int2, int2_len, dec_int2_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	if (bytearray2int(dec_int1_v, decint1_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	if (bytearray2int(dec_int2_v, decint2_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	if (decint2_int == 0)
		return ARITHMETIC_ERROR;

	decint3_int = decint1_int % decint2_int;

	if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) || 
		(decint2_int > INT32_MAX || decint2_int < INT32_MIN) )
		 return OUT_OF_THE_RANGE_ERROR;

	if (int2bytearray((int32_t) decint3_int, dec_int3_v, INT64_LENGTH))
		return MEMORY_COPY_ERROR;

	resp = encryptGCM(dec_int3_v, INT64_LENGTH, int3, int3_len);

	memset_s(dec_int1_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int2_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int3_v, INT64_LENGTH, 0, INT64_LENGTH);

	memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));

	free_allocated_memory(dec_int1_v);
	free_allocated_memory(dec_int2_v);
	free_allocated_memory(dec_int3_v);

	return resp;

}

/* Power operation of two encrypted by aes_gcm integers
 @input: uint8_t array - encrypted integer base
		 size_t - length of encrypted base (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted integer exponent
		 size_t - length of encrypted exponent (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
// TODO: should be changed. Compute power using a binary representation of a power.Check that the result is an int.
int expRandEncInt (	uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *int3, size_t int3_len){

	int32_t decint1_int, decint2_int;
	int64_t decint3_int;
	int resp;

    uint8_t *dec_int1_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int2_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int3_v = (uint8_t *)malloc(INT64_LENGTH);

	resp = decryptGCM(int1, int1_len, dec_int1_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decryptGCM(int2, int2_len, dec_int2_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	if (bytearray2int(dec_int1_v, decint1_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	if (bytearray2int(dec_int2_v, decint2_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	decint3_int = (int64_t) pow((double)decint1_int, decint2_int);

	if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) ||
		(decint2_int > INT32_MAX || decint2_int < INT32_MIN) ||
		(decint3_int > (int64_t) INT32_MAX || decint3_int < (int64_t) INT32_MIN))
		 return OUT_OF_THE_RANGE_ERROR;

	if (int2bytearray((int32_t) decint3_int, dec_int3_v, INT64_LENGTH))
		return MEMORY_COPY_ERROR;

	resp = encryptGCM(dec_int3_v, INT64_LENGTH, int3, int3_len);

	memset_s(dec_int1_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int2_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int3_v, INT64_LENGTH, 0, INT64_LENGTH);

	memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));

	free_allocated_memory(dec_int1_v);
	free_allocated_memory(dec_int2_v);
	free_allocated_memory(dec_int3_v);

	return resp;

}

/* Division of two encrypted by aes_gcm integers
 @input: uint8_t array - encrypted integer1
		 size_t - length of encrypted integer1 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted integer2
		 size_t - length of encrypted integer2 (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
		 uint8_t array - encrypted result
		 size_t - length of encrypted result (SGX_AESGCM_IV_SIZE + INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 32)
 @return:
	* SGX_error, if there was an error during encryption/decryption 
	0, otherwise
*/
int divRandEncInt (	uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *int3, size_t int3_len){

	int32_t decint1_int, decint2_int;
	int64_t decint3_int;
	int resp;

    uint8_t *dec_int1_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int2_v = (uint8_t *)malloc(INT64_LENGTH);
    uint8_t *dec_int3_v = (uint8_t *)malloc(INT64_LENGTH);

	resp = decryptGCM(int1, int1_len, dec_int1_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	resp = decryptGCM(int2, int2_len, dec_int2_v, INT64_LENGTH);
	if (resp != SGX_SUCCESS)
		return resp;

	if (bytearray2int(dec_int1_v, decint1_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	if (bytearray2int(dec_int2_v, decint2_int, INT64_LENGTH) == -1)
		return MEMORY_COPY_ERROR;

	if (decint2_int == 0)
		return ARITHMETIC_ERROR;

	if (decint2_int == 0)
		return ARITHMETIC_ERROR;
	
	decint3_int = decint1_int / decint2_int;
	
	if ((decint1_int > INT32_MAX || decint1_int < INT32_MIN) || 
		(decint2_int > INT32_MAX || decint2_int < INT32_MIN))
		 return OUT_OF_THE_RANGE_ERROR;

	if (int2bytearray((int32_t) decint3_int, dec_int3_v, INT64_LENGTH))
		return MEMORY_COPY_ERROR;

	resp = encryptGCM(dec_int3_v, INT64_LENGTH, int3, int3_len);

	memset_s(dec_int1_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int2_v, INT64_LENGTH, 0, INT64_LENGTH);
	memset_s(dec_int3_v, INT64_LENGTH, 0, INT64_LENGTH);

	memset_s(&decint1_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint2_int, sizeof(int32_t), 0, sizeof(int32_t));
	memset_s(&decint3_int, sizeof(int64_t), 0, sizeof(int64_t));

	free_allocated_memory(dec_int1_v);
	free_allocated_memory(dec_int2_v);
	free_allocated_memory(dec_int3_v);

	return resp;

}
