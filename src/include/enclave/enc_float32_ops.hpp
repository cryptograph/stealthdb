#pragma once

#include "enclave/enclave.hpp"
#include "enclave/enclave_t.h"

typedef union {
    float val;
    unsigned char bytes[FLOAT4_LENGTH];
} union_float4;

int enc_float32_add(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size);
int enc_float32_cmp(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size);
int enc_float32_sub(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size);
int enc_float32_mult(uint8_t* in1,
                     size_t in1_size,
                     uint8_t* in2,
                     size_t in2_size,
                     uint8_t* out,
                     size_t out_size);
int enc_float32_div(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size);
int enc_float32_mod(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size);
int enc_float32_pow(uint8_t* in1,
                    size_t in1_size,
                    uint8_t* in2,
                    size_t in2_size,
                    uint8_t* out,
                    size_t out_size);
int enc_float32_sum_bulk(uint8_t* in1,
                         size_t in1_size,
                         uint8_t* in2,
                         size_t in2_size,
                         uint8_t* out,
                         size_t out_size);
