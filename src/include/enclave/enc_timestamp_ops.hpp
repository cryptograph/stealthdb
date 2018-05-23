#pragma once
#include "enclave/enclave.hpp"
#include "enclave/enclave_t.h"
#include "tools/timestamp.h"

int enc_timestamp_cmp(uint8_t* src1,
                      size_t src1_len,
                      uint8_t* src2,
                      size_t src2_len,
                      uint8_t* result,
                      size_t res_len);
int enc_timestamp_extract_year(uint8_t* in1,
                               size_t in1_len,
                               uint8_t* out,
                               size_t out_size);
