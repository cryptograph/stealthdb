int enc_text_cmp (sgx_aes_ctr_128bit_key_t* key, uint8_t *src1, size_t src1_len, uint8_t *src2, size_t src2_len, uint8_t *dst, size_t dst_len);
int enc_text_concatenate (sgx_aes_ctr_128bit_key_t* key, uint8_t *src1, size_t src1_len, uint8_t *src2, size_t src2_len, uint8_t *dst, size_t dst_len);
int enc_text_substring (sgx_aes_ctr_128bit_key_t* key, uint8_t *src1, size_t src1_len, uint8_t *src2, size_t src2_len, uint8_t *dst, size_t dst_len);
