#pragma once
#include "defs.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int int2bytearray(int, uint8_t*, size_t);
int bytearray2int(uint8_t*, int&, size_t);
