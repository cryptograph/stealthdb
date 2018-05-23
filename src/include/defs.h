// not sure what is better to use
// #define(appropriate in c) or const int (c++ standard)
// my vote for 'const int'

typedef unsigned char BYTE; // 1byte
typedef unsigned short WORD; // 2bytes
typedef unsigned long DWORD; //4bytes

#define SEALED_KEY_LENGTH 576

#define ENC_INT32_LENGTH_B64 45 //((4 * n / 3) + 3) & ~3
#define ENC_INT32_LENGTH 32
#define INT32_LENGTH sizeof(int)

#define ENC_FLOAT4_LENGTH_B64 45 //((4 * n / 3) + 3) & ~3
#define ENC_FLOAT4_LENGTH 32
#define FLOAT4_LENGTH sizeof(float)

#define ENC_TIMESTAMP_LENGTH_B64 49 //((4 * n / 3) + 3) & ~3
#define ENC_TIMESTAMP_LENGTH 36
#define TIMESTAMP int64_t
#define TIMESTAMP_LENGTH sizeof(int64_t)

#define ENC_STRING_LENGTH_B64 1405 //((4 * n / 3) + 3) & ~3
#define ENC_STRING_LENGTH 1052
#define STRING_LENGTH 1024
#define INPUT_BUFFER_SIZE ENC_STRING_LENGTH_B64 + ENC_STRING_LENGTH_B64 + 1

#define BULK_SIZE 256

// errors
#define ENCLAVE_IS_NOT_RUNNING -2
#define MEMORY_COPY_ERROR -3
#define ARITHMETIC_ERROR -4
#define MEMORY_ALLOCATION_ERROR -5
#define OUT_OF_THE_RANGE_ERROR -6
#define BASE64DECODER_ERROR -7
#define IS_NOT_INITIALIZE -8
#define NO_KEYS_STORAGE -9
#define NO_KEY_ID -10
#define NOT_IMPLEMENTED_OPERATOR -11
#define TOO_MANY_ELEMENTS_IN_BULK -12

// COMMANDS
#define CMD_INT64_PLUS 1
#define CMD_INT64_MINUS 2
#define CMD_INT64_MULT 3
#define CMD_INT64_DIV 4
#define CMD_INT64_CMP 5
#define CMD_INT64_ENC 6
#define CMD_INT64_DEC 7
#define CMD_INT64_EXP 8
#define CMD_INT64_MOD 9
#define CMD_INT32_SUM_BULK 10

#define CMD_FLOAT4_PLUS 101
#define CMD_FLOAT4_MINUS 102
#define CMD_FLOAT4_MULT 103
#define CMD_FLOAT4_DIV 104
#define CMD_FLOAT4_CMP 105
#define CMD_FLOAT4_ENC 106
#define CMD_FLOAT4_DEC 107
#define CMD_FLOAT4_EXP 108
#define CMD_FLOAT4_MOD 109
#define CMD_FLOAT4_SUM_BULK 110

#define CMD_STRING_CMP 201
#define CMD_STRING_ENC 202
#define CMD_STRING_DEC 203
#define CMD_STRING_SUBSTRING 204
#define CMD_STRING_CONCAT 205
#define CMD_STRING_LIKE 206

#define CMD_TIMESTAMP_CMP 150
#define CMD_TIMESTAMP_ENC 151
#define CMD_TIMESTAMP_DEC 152
#define CMD_TIMESTAMP_EXTRACT_YEAR 153
