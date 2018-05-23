#include "enclave/enc_timestamp_ops.hpp"

/* Compare two encrypted timestamps(int64 - 8 bytes) by aes_gcm algorithm
 @input: uint8_t array - encrypted source1
         size_t - sizegth of encrypted source1 (SGX_AESGCM_IV_SIZE +
 INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 36) 
         uint8_t array - encrypted source2
         size_t - sizegth of encrypted source2 (SGX_AESGCM_IV_SIZE +
 INT64_LENGTH + SGX_AESGCM_MAC_SIZE = 36)
         uint8_t array - which contains the result  1 (if a > b). -1 (if b > a),
 0 (if a == b)
         size_t - size of result (TIMESTAMP_LENGTH = 4)

 @return:
 * SGX_error, if there was an error during decryption
*/
int enc_timestamp_cmp(uint8_t* in1,
                      size_t in1_size,
                      uint8_t* in2,
                      size_t in2_size,
                      uint8_t* out,
                      size_t out_size)
{
    int resp, cmp;

    union {
        TIMESTAMP ts;
        unsigned char bytes[TIMESTAMP_LENGTH];
    } lhs, rhs;

    resp = decrypt_bytes(in1, in1_size, lhs.bytes, TIMESTAMP_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    resp = decrypt_bytes(in2, in2_size, rhs.bytes, TIMESTAMP_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    cmp = (lhs.ts == rhs.ts) ? 0 : ((lhs.ts < rhs.ts) ? -1 : 1);

    memcpy(out, &cmp, out_size);

    memset_s(lhs.bytes, TIMESTAMP_LENGTH, 0, TIMESTAMP_LENGTH);
    memset_s(rhs.bytes, TIMESTAMP_LENGTH, 0, TIMESTAMP_LENGTH);

    return resp;
}

int enc_timestamp_extract_year(uint8_t* in,
                               size_t in_size,
                               uint8_t* out,
                               size_t out_size)
{
    union {
        int val;
        unsigned char bytes[INT32_LENGTH];
    } year;

    union {
        TIMESTAMP val;
        unsigned char bytes[TIMESTAMP_LENGTH];
    } timestamp;

    int resp = decrypt_bytes(in, in_size, timestamp.bytes, TIMESTAMP_LENGTH);
    if (resp != SGX_SUCCESS)
        return resp;

    year.val = year_from_timestamp(timestamp.val);

    resp = encrypt_bytes(year.bytes, INT32_LENGTH, out, out_size);
    memset_s(timestamp.bytes, TIMESTAMP_LENGTH, 0, TIMESTAMP_LENGTH);
    memset_s(year.bytes, INT32_LENGTH, 0, INT32_LENGTH);

    return resp;
}
