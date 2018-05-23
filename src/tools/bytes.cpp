#include "tools/bytes.hpp"

/* Convert an integer to a byte array.
        Should pay attention to the endian.
        @input: src - integer
                 pDst - pointer to the result array with size INT32_LENGTH
                 dstLen - length of the array
        @return:
                1, if the size of array is less than INT32_LENGTH
                0 otherwise
*/
int int2bytearray(int src, uint8_t* pDst, size_t dstLen)
{
    if (dstLen < INT32_LENGTH)
        return 1;

    memcpy(pDst, &src, INT32_LENGTH);

    return 0;
}

/* Convert an array to an integer.
        Should pay attention to the endian.
        @input:
                pDst - pointer to the result array with size INT32_LENGTH
                src - output integer
                dstLen - length of the array
        @return:
                1, if the size of array is less than INT32_LENGTH
                0 otherwise

                */
int bytearray2int(uint8_t* pSrc, int& dst, size_t srcLen)
{
    if (srcLen < INT32_LENGTH)
        return 1;

    memcpy(&dst, pSrc, INT32_LENGTH);

    return 0;
}
