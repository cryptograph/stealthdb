int enc_float32_add (sgx_aes_ctr_128bit_key_t* key, uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *int3, size_t int3_len);
int enc_float32_cmp (sgx_aes_ctr_128bit_key_t* key, uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *result, size_t res_len);
int enc_float32_sub (sgx_aes_ctr_128bit_key_t* key, uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *result, size_t res_len);
int enc_float32_mult (sgx_aes_ctr_128bit_key_t* key, uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *result, size_t res_len);
int enc_float32_div (sgx_aes_ctr_128bit_key_t* key, uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *result, size_t res_len);
int enc_float32_mod (sgx_aes_ctr_128bit_key_t* key, uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *result, size_t res_len);
int enc_float32_pow (sgx_aes_ctr_128bit_key_t* key, uint8_t *int1, size_t int1_len, uint8_t *int2, size_t int2_len, uint8_t *result, size_t res_len);
