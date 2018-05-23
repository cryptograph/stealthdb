#pragma once

#include "defs.h"
#include "enclave/enclave.hpp"
#include "tools/like_match.h"
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

    int enc_text_cmp(uint8_t* in1,
                     size_t in1_size,
                     uint8_t* in2,
                     size_t in2_size,
                     uint8_t* out,
                     size_t out_size);
    int enc_text_like(uint8_t* in1,
                      size_t in1_size,
                      uint8_t* in2,
                      size_t in2_size,
                      uint8_t* out,
                      size_t out_size);
    int enc_text_concatenate(uint8_t* in1,
                             size_t in1_size,
                             uint8_t* in2,
                             size_t in2_size,
                             uint8_t* out,
                             size_t out_size);
    int enc_text_substring(uint8_t* in1,
                           size_t in1_size,
                           uint8_t* in2,
                           size_t in2_size,
                           uint8_t* in3,
                           size_t in3_size,
                           uint8_t* out,
                           size_t* out_size);

#ifdef __cplusplus
}
#endif
