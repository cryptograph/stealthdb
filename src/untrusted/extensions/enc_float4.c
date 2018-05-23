/*
 * enc_float4.c : This library defines exported functions for the encrypted float(4 bytes) datatype.
 * The library contains functions for the Postgresql extension 'encdb', including:
 *
 * encrypted float type, format: BASE64(IV[12bytes]||AES-GCM(int)[4 bytes]||AUTHTAG[16 bytes])
 *          (input size: 4 bytes; output size: 44 bytes; operators: +,-,*,/,%,>=,>,<=,<,=,!=; functions: SUM, AVG, MAX, MIN)
 */
#include "untrusted/extensions/stdafx.h"
#include "utils/int8.h"
#include "utils/numeric.h"
#include <float.h>

extern bool debugMode;

/*
 * The function converts enc_float4 element to a string. If flag debugDecryption is true it decrypts the string and return unencrypted result.
 * @input: enc_float4 element
 * @return: string
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_out);
Datum
    pg_enc_float4_out(PG_FUNCTION_ARGS)
{
    char* pSrc = PG_GETARG_CSTRING(0);
    char* str = (char*)palloc(ENC_FLOAT4_LENGTH_B64 * sizeof(char));
    char* pDst = (char*)palloc((FLOAT4_LENGTH) * sizeof(char));
    int resp = ENCLAVE_IS_NOT_RUNNING;
    float ans;

    memcpy(str, pSrc, ENC_FLOAT4_LENGTH_B64);
    if (debugMode == true)
    {
        resp = enc_float32_decrypt(pSrc, pDst);
        memcpy(&ans, pDst, FLOAT4_LENGTH);
        sgxErrorHandler(resp);
        sprintf(str, "%f", ans);
        //ereport(INFO, (errmsg("auto decryption: DEC('%s') = %f", pSrc, ans)));
    }

    pfree(pDst);
    PG_RETURN_CSTRING(str);
}

//TODO
// DEBUG FUNCTION
// WILL BE DELETED IN THE PRODUCT
PG_FUNCTION_INFO_V1(pg_enc_float4_encrypt);
Datum
    pg_enc_float4_encrypt(PG_FUNCTION_ARGS)
{
    float src = PG_GETARG_FLOAT4(0);
    int ans;
    char* pDst = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));
    ans = enc_float32_encrypt(src, pDst);

    sgxErrorHandler(ans);
    PG_RETURN_CSTRING(pDst);
}

//TODO
// DEBUG FUNCTION
// WILL BE DELETED IN THE PRODUCT
PG_FUNCTION_INFO_V1(pg_enc_float4_decrypt);
Datum
    pg_enc_float4_decrypt(PG_FUNCTION_ARGS)
{
    float dst = 0;
    char* c1 = PG_GETARG_CSTRING(0);
    char* pDst = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));
    int resp = ENCLAVE_IS_NOT_RUNNING;
    resp = enc_float32_decrypt(c1, pDst);
    memcpy(&dst, pDst, FLOAT4_LENGTH);
    sgxErrorHandler(resp);

    pfree(pDst);
    PG_RETURN_FLOAT4(dst);
}

/*
 * The function calculates the sum of elements from input array
 * It is called by sql aggregate command SUM, which is firstly appends needed enc_float4 elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'enc_float32_add' from the 'interface' library.
 * @input: an array of enc_float4 values which should be summarize
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_addfinal);
Datum
    pg_enc_float4_addfinal(PG_FUNCTION_ARGS)
{
    ArrayType* v = PG_GETARG_ARRAYTYPE_P(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool isnull;
    Datum value;
    char* pSrc1 = (char*)palloc((ENC_FLOAT4_LENGTH_B64 + 1) * sizeof(char));
    char* pSrc2 = (char*)palloc((ENC_FLOAT4_LENGTH_B64 + 1) * sizeof(char));
    char* pTemp = (char*)palloc((ENC_FLOAT4_LENGTH_B64 + 1) * sizeof(char));
    ArrayMetaState* my_extra = (ArrayMetaState*)fcinfo->flinfo->fn_extra;
    ArrayIterator array_iterator = array_create_iterator(v, 0, my_extra);

    array_iterate(array_iterator, &value, &isnull);
    memcpy(pSrc1, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
    pSrc1[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(pTemp, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
        pTemp[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';
        resp = enc_float32_add(pSrc1, pTemp, pSrc2);
        sgxErrorHandler(resp);

        memcpy(pSrc1, pSrc2, ENC_FLOAT4_LENGTH_B64);
        pSrc1[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';
    }

    pfree(pTemp);
    pfree(pSrc2);

    PG_RETURN_CSTRING(pSrc1);
}

PG_FUNCTION_INFO_V1(pg_enc_float4_sum_bulk);
Datum
    pg_enc_float4_sum_bulk(PG_FUNCTION_ARGS)
{
    ArrayType* v = PG_GETARG_ARRAYTYPE_P(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    ArrayIterator array_iterator;
    ArrayMetaState* my_extra = (ArrayMetaState*)fcinfo->flinfo->fn_extra;
    bool isnull;
    Datum value;
    size_t bulk_size = BULK_SIZE;
    unsigned long current_position = 0, counter = 0;
    char* pSrc2 = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));
    char* pTemp = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char) * bulk_size);

    array_iterator = array_create_iterator(v, 0, my_extra);
    while (array_iterate(array_iterator, &value, &isnull))
    {
        //      ereport(INFO, (errmsg("add %d:  %s", current_position, DatumGetCString(value))));
        memcpy(pTemp + current_position, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
        current_position += ENC_FLOAT4_LENGTH_B64;
        counter++;

        if (counter % (bulk_size) == 0)
        {
            resp = enc_float32_sum_bulk(bulk_size, pTemp, pSrc2);
            //ereport(INFO, (errmsg("ret %d", resp)));
            sgxErrorHandler(resp);

            memcpy(pTemp, pSrc2, ENC_FLOAT4_LENGTH_B64);
            current_position = ENC_FLOAT4_LENGTH_B64;
            counter++;
            //          ereport(INFO, (errmsg("res %s", pSrc2)));
        }
    }

    //        ereport(INFO, (errmsg("send rest %d: bulk %d,  %s", current_position, counter%bulk_size, pTemp)));
    resp = enc_float32_sum_bulk(counter % bulk_size, pTemp, pSrc2);
    sgxErrorHandler(resp);

    pfree(pTemp);
    PG_RETURN_CSTRING(pSrc2);
}

/*
 * The function computes the average of elements from array of enc_float4 elements.
 * It is called by sql aggregate command AVG, which is firstly appends needed enc_float4 elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'enc_float32_add', 'enc_float32_div', 'enc_float32_encrypt' from the 'interface' library.
 * @input: an array of enc_float4 elements
 * @return: an encrypted result (encrypted float4). output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_avgfinal);
Datum
    pg_enc_float4_avgfinal(PG_FUNCTION_ARGS)
{
    ArrayType* v = PG_GETARG_ARRAYTYPE_P(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool isnull;
    Datum value;
    int ndims1 = ARR_NDIM(v); //array dimension
    int* dims1 = ARR_DIMS(v);
    int nitems = ArrayGetNItems(ndims1, dims1); //number of items in array
    char* pSrc1 = palloc((ENC_FLOAT4_LENGTH_B64 + 1) * sizeof(*pSrc1));
    char* pSrc2 = palloc((ENC_FLOAT4_LENGTH_B64 + 1) * sizeof(*pSrc2));
    char* pTemp = palloc((ENC_FLOAT4_LENGTH_B64 + 1) * sizeof(*pTemp));
    ArrayMetaState* my_extra = (ArrayMetaState*)fcinfo->flinfo->fn_extra;
    ArrayIterator array_iterator = array_create_iterator(v, 0, my_extra);

    array_iterate(array_iterator, &value, &isnull);
    memcpy(pSrc1, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
    pSrc1[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(pTemp, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
        pTemp[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';
        resp = enc_float32_add(pSrc1, pTemp, pSrc2);
        sgxErrorHandler(resp);

        memcpy(pSrc1, pSrc2, ENC_FLOAT4_LENGTH_B64);
        pSrc1[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';
    }

    resp = enc_float32_encrypt(nitems, pTemp);
    sgxErrorHandler(resp);

    resp = enc_float32_div(pSrc1, pTemp, pSrc2);
    sgxErrorHandler(resp);

    pfree(pTemp);
    pfree(pSrc1);

    PG_RETURN_CSTRING(pSrc2);
}

PG_FUNCTION_INFO_V1(pg_enc_float4_avg_bulk);
Datum
    pg_enc_float4_avg_bulk(PG_FUNCTION_ARGS)
{
    ArrayType* v = PG_GETARG_ARRAYTYPE_P(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    ArrayIterator array_iterator;
    ArrayMetaState* my_extra = (ArrayMetaState*)fcinfo->flinfo->fn_extra;
    bool isnull;
    size_t bulk_size = BULK_SIZE;
    unsigned long current_position = 0, counter = 0;
    Datum value;
    int ndims1 = ARR_NDIM(v); //array dimension
    int* dims1 = ARR_DIMS(v);
    int nitems = ArrayGetNItems(ndims1, dims1); //number of items in array
    char* pSrc1 = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));
    char* pSrc2 = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));
    char* pTemp = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char) * bulk_size);

    array_iterator = array_create_iterator(v, 0, my_extra);

    while (array_iterate(array_iterator, &value, &isnull))
    {
        //ereport(INFO, (errmsg("add %d:  %s", current_position, DatumGetCString(value))));
        memcpy(pTemp + current_position, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
        current_position += ENC_FLOAT4_LENGTH_B64;
        counter++;

        if (counter % (bulk_size) == 0)
        {
            resp = enc_float32_sum_bulk(bulk_size, pTemp, pSrc2);
            //ereport(INFO, (errmsg("ret %d", resp)));
            sgxErrorHandler(resp);

            memcpy(pTemp, pSrc2, ENC_FLOAT4_LENGTH_B64);
            current_position = ENC_FLOAT4_LENGTH_B64;
            counter++;
            //ereport(INFO, (errmsg("res %s", pSrc2)));
        }
    }

    // ereport(INFO, (errmsg("send rest %d: bulk %d,  %s", current_position, counter%bulk_size, pTemp)));
    resp = enc_float32_sum_bulk(counter % bulk_size, pTemp, pSrc1);
    sgxErrorHandler(resp);

    resp = enc_float32_encrypt(nitems, pTemp);
    sgxErrorHandler(resp);

    resp = enc_float32_div(pSrc1, pTemp, pSrc2);
    sgxErrorHandler(resp);

    pfree(pTemp);
    pfree(pSrc1);

    PG_RETURN_CSTRING(pSrc2);
}

/*
 * The function computes the maximal element of array of enc_float4 elements
 * It is called by sql aggregate command MAX, which first appends needed enc_float4 elements to an array and then calls this function.
 * It requires a running SGX enclave and uses the function 'enc_float32_cmp' from the 'interface' library.
 * @input: array of enc_float4 elements
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_maxfinal);
Datum
    pg_enc_float4_maxfinal(PG_FUNCTION_ARGS)
{
    ArrayType* v = PG_GETARG_ARRAYTYPE_P(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    int ans = 0;
    ArrayIterator array_iterator;
    ArrayMetaState* my_extra = (ArrayMetaState*)fcinfo->flinfo->fn_extra;
    bool isnull;
    Datum value;

    int item_count = ArrayGetNItems(ARR_NDIM(v), ARR_DIMS(v)); //number of items in array

    char* max = palloc(ENC_FLOAT4_LENGTH_B64 * sizeof(*max));
    char* value_bytes = palloc(ENC_FLOAT4_LENGTH_B64 * sizeof(*value_bytes));
    char* res = palloc(FLOAT4_LENGTH * sizeof(*res));

    array_iterator = array_create_iterator(v, 0, my_extra);
    array_iterate(array_iterator, &value, &isnull);

    memcpy(max, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
    max[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(value_bytes, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
        value_bytes[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

        resp = enc_float32_cmp(max, value_bytes, res);
        sgxErrorHandler(resp);
        memcpy(&ans, res, FLOAT4_LENGTH);

        if (ans == -1)
        {
            memcpy(max, value_bytes, ENC_FLOAT4_LENGTH_B64);
            max[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';
        }
    }

    pfree(value_bytes);
    pfree(res);

    PG_RETURN_CSTRING(max);
}

PG_FUNCTION_INFO_V1(pg_enc_float4_max_bulk);
Datum
    pg_enc_float4_max_bulk(PG_FUNCTION_ARGS)
{
    ArrayType* v = PG_GETARG_ARRAYTYPE_P(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    int ans = 0;
    ArrayIterator array_iterator;
    ArrayMetaState* my_extra = (ArrayMetaState*)fcinfo->flinfo->fn_extra;
    bool isnull;
    Datum value;

    int item_count = ArrayGetNItems(ARR_NDIM(v), ARR_DIMS(v)); //number of items in array

    char* max = palloc(ENC_FLOAT4_LENGTH_B64 * sizeof(*max));
    char* value_bytes = palloc(ENC_FLOAT4_LENGTH_B64 * sizeof(*value_bytes));
    char* res = palloc(FLOAT4_LENGTH * sizeof(*res));

    array_iterator = array_create_iterator(v, 0, my_extra);
    array_iterate(array_iterator, &value, &isnull);

    memcpy(max, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
    max[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(value_bytes, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
        value_bytes[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

        resp = enc_float32_cmp(max, value_bytes, res);
        sgxErrorHandler(resp);
        memcpy(&ans, res, FLOAT4_LENGTH);

        if (ans == -1)
        {
            memcpy(max, value_bytes, ENC_FLOAT4_LENGTH_B64);
            max[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';
        }
    }

    pfree(value_bytes);
    pfree(res);

    PG_RETURN_CSTRING(max);
}

/*
 * The function computes the minimal element of array of enc_float4 elements
 * It is called by sql aggregate command MIN, which first appends needed enc_float4 elements to an array and then calls this function.
 * It requires a running SGX enclave and uses the function 'enc_float32_cmp' from the 'interface' library.
 * @input: array of enc_float4 elements
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_minfinal);
Datum
    pg_enc_float4_minfinal(PG_FUNCTION_ARGS)
{
    ArrayType* v = PG_GETARG_ARRAYTYPE_P(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    int ans = 0;
    ArrayIterator array_iterator;
    ArrayMetaState* my_extra = (ArrayMetaState*)fcinfo->flinfo->fn_extra;
    bool isnull;
    Datum value;

    int ndims1 = ARR_NDIM(v); //array dimension
    int* dims1 = ARR_DIMS(v);
    int nitems = ArrayGetNItems(ndims1, dims1); //number of items in array

    char* pSrc1 = palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(*pSrc1));
    char* pTemp = palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(*pTemp));
    char* pDst = palloc((FLOAT4_LENGTH) * sizeof(*pDst));

    array_iterator = array_create_iterator(v, 0, my_extra);
    array_iterate(array_iterator, &value, &isnull);

    memcpy(pSrc1, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
    pSrc1[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(pTemp, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
        pTemp[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

        resp = enc_float32_cmp(pSrc1, pTemp, pDst);
        sgxErrorHandler(resp);
        memcpy(&ans, pDst, FLOAT4_LENGTH);

        if (ans == 1)
        {
            memcpy(pSrc1, pTemp, ENC_FLOAT4_LENGTH_B64);
        }
        pSrc1[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';
    }

    pfree(pDst);
    pfree(pTemp);

    PG_RETURN_CSTRING(pSrc1);
}

PG_FUNCTION_INFO_V1(pg_enc_float4_min_bulk);
Datum
    pg_enc_float4_min_bulk(PG_FUNCTION_ARGS)
{
    ArrayType* v = PG_GETARG_ARRAYTYPE_P(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    int ans = 0;
    ArrayIterator array_iterator;
    ArrayMetaState* my_extra = (ArrayMetaState*)fcinfo->flinfo->fn_extra;
    bool isnull;
    Datum value;

    int ndims1 = ARR_NDIM(v); //array dimension
    int* dims1 = ARR_DIMS(v);
    int nitems = ArrayGetNItems(ndims1, dims1); //number of items in array

    char* pSrc1 = palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(*pSrc1));
    char* pTemp = palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(*pTemp));
    char* pDst = palloc((FLOAT4_LENGTH) * sizeof(*pDst));

    array_iterator = array_create_iterator(v, 0, my_extra);
    array_iterate(array_iterator, &value, &isnull);

    memcpy(pSrc1, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
    pSrc1[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(pTemp, DatumGetCString(value), ENC_FLOAT4_LENGTH_B64);
        pTemp[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

        resp = enc_float32_cmp(pSrc1, pTemp, pDst);
        sgxErrorHandler(resp);
        memcpy(&ans, pDst, FLOAT4_LENGTH);

        if (ans == 1)
        {
            memcpy(pSrc1, pTemp, ENC_FLOAT4_LENGTH_B64);
        }
        pSrc1[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';
    }

    pfree(pDst);
    pfree(pTemp);

    PG_RETURN_CSTRING(pSrc1);
}
/*
 * The function calculates the sum of two enc_float4 values. It is called by binary operator '+' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_add' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: encrypted sum of input values
 * output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
*/

PG_FUNCTION_INFO_V1(pg_enc_float4_add);
Datum
    pg_enc_float4_add(PG_FUNCTION_ARGS)
{
    char* lhs = PG_GETARG_CSTRING(0);
    char* rhs = PG_GETARG_CSTRING(1);
    int result_size = ENC_FLOAT4_LENGTH_B64 * sizeof(char);
    char* result = palloc(result_size);
    int resp = ENCLAVE_IS_NOT_RUNNING;

    resp = enc_float32_add(lhs, rhs, result);
    sgxErrorHandler(resp);

    result[result_size - 1] = '\0';
    PG_RETURN_CSTRING(result);
}

/*
 * The function calculates the subtraction of two enc_float4 values. It is called by binary operator '-' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_sub' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_subs);
Datum
    pg_enc_float4_subs(PG_FUNCTION_ARGS)
{
    char* lhs = PG_GETARG_CSTRING(0);
    char* rhs = PG_GETARG_CSTRING(1);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    int result_size = ENC_FLOAT4_LENGTH_B64 * sizeof(char);
    char* result = palloc(result_size);

    resp = enc_float32_sub(lhs, rhs, result);
    sgxErrorHandler(resp);

    result[result_size - 1] = '\0';
    PG_RETURN_CSTRING(result);
}

/*
 * The function calculates the product of two enc_float4 values. It is called by binary operator '*' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_mult' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_mult);
Datum
    pg_enc_float4_mult(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* pDst = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));

    resp = enc_float32_mult(c1, c2, pDst);
    sgxErrorHandler(resp);
    pDst[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

    PG_RETURN_CSTRING(pDst);
}

/*
 * The function calculates the division of two enc_float4 values. It is called by binary operator '/' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_div' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */

PG_FUNCTION_INFO_V1(pg_enc_float4_div);
Datum
    pg_enc_float4_div(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* pDst = palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(*pDst));

    resp = enc_float32_div(c1, c2, pDst);
    sgxErrorHandler(resp);
    pDst[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

    PG_RETURN_CSTRING(pDst);
}

/*
 * The function calculates the first input enc_float4 value to the power of the second input enc_float4 value.
 * It is called by binary operator '^' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_pow' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_exp);
Datum
    pg_enc_float4_exp(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* pDst = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));

    resp = enc_float32_pow(c1, c2, pDst);
    sgxErrorHandler(resp);
    pDst[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

    PG_RETURN_CSTRING(pDst);
}

/*
 * The function checks if the first input enc_float4 is equal to the second one.
 * It is called by binary operator '=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_cmp' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: true, if the first decrypted float is equal to the second one.
 *       false, otherwise
*/
PG_FUNCTION_INFO_V1(pg_enc_float4_eq);
Datum
    pg_enc_float4_eq(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((FLOAT4_LENGTH) * sizeof(char));
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp = false;

    resp = enc_float32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, FLOAT4_LENGTH);

    cmp = (ans == 0) ? true : false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input enc_float4 is not equal to the second one.
 * It is called by binary operator '!=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_cmp' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: true, if the first decrypted float is not equal to the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_ne);
Datum
    pg_enc_float4_ne(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((FLOAT4_LENGTH) * sizeof(char));
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp = false;

    resp = enc_float32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, FLOAT4_LENGTH);

    if (ans == 0)
        cmp = false;
    else
        cmp = true;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input enc_float4 is less than the second one.
 * It is called by binary operator '<' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_cmp' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: true, if the first decrypted float is less the the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_lt);
Datum
    pg_enc_float4_lt(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((FLOAT4_LENGTH) * sizeof(char));
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp;

    resp = enc_float32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, FLOAT4_LENGTH);

    if (ans == -1)
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input enc_float4 is less or equal than the second one.
 * It is called by binary operator '<=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_cmp' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: true, if the first enc_float4 is less or equal than the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_le);
Datum
    pg_enc_float4_le(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((FLOAT4_LENGTH) * sizeof(char));
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp;

    resp = enc_float32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, FLOAT4_LENGTH);

    if ((ans == -1) || (ans == 0))
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input enc_float4 is greater than the second one.
 * It is called by binary operator '>' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_cmp' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: true, if the first decrypted float is greater than the second one.
 *          false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_gt);
Datum
    pg_enc_float4_gt(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((FLOAT4_LENGTH) * sizeof(char));
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp;

    resp = enc_float32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, FLOAT4_LENGTH);

    if (ans == 1)
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input enc_float4 is greater or equal than the second one.
 * It is called by binary operator '>=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_cmp' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: true, if the first decrypted float is greater or equal than the second one.
 *          false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_ge);
Datum
    pg_enc_float4_ge(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((FLOAT4_LENGTH) * sizeof(char));
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp;

    resp = enc_float32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, FLOAT4_LENGTH);

    if ((ans == 0) || (ans == 1))
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

/*
 * The function compares two enc_float4 values. It is called mostly during index building.
 * It requires a running SGX enclave and uses the function 'enc_float32_cmp' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: -1, 0 ,1
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_cmp);
Datum
    pg_enc_float4_cmp(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((FLOAT4_LENGTH) * sizeof(char));
    int resp = ENCLAVE_IS_NOT_RUNNING;
    int ans = 0;

    resp = enc_float32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, FLOAT4_LENGTH);

    pfree(pDst);
    PG_RETURN_INT32(ans);
}

/*
 * The function calculates the first input enc_float4 value by module the second input enc_float4 value.
 * It is called by binary operator '%' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_float32_mod' from the 'interface' library.
 * @input: two enc_float4 values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_mod);
Datum
    pg_enc_float4_mod(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* pDst = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));

    resp = enc_float32_mod(c1, c2, pDst);
    sgxErrorHandler(resp);
    pDst[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';

    pfree(pDst);
    PG_RETURN_CSTRING(pDst);
}

/*
 * The function converts a float to enc_float4 value. This function is called by sql function CAST.
 * It requires a running SGX enclave and uses the function 'enc_float32_encrypt' from the 'interface' library.
 * @input: float4
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(float4_to_enc_float4);
Datum
    float4_to_enc_float4(PG_FUNCTION_ARGS)
{
    float src = PG_GETARG_FLOAT4(0);
    int ans;
    char* pDst = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));

    ans = enc_float32_encrypt(src, pDst);
    sgxErrorHandler(ans);
    //ereport(INFO, (errmsg("auto encryption: ENC(%f) = %s", src, pDst)));

    PG_RETURN_CSTRING((const char*)pDst);
}

float4 pg_float4_in(char* num)
{

    char* orig_num;
    double val;
    char* endptr;

    /*
     * endptr points to the first character _after_ the sequence we recognized
     * as a valid floating point number. orig_num points to the original input
     * string.
     */
    orig_num = num;

    /* skip leading whitespace */
    while (*num != '\0' && isspace((unsigned char)*num))
        num++;

    /*
     * Check for an empty-string input to begin with, to avoid the vagaries of
     * strtod() on different platforms.
     */
    if (*num == '\0')
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                 errmsg("invalid input syntax for type %s: \"%s\"",
                        "real", orig_num)));

    errno = 0;
    val = strtod(num, &endptr);

    /* did we not see anything that looks like a double? */
    if (endptr == num || errno != 0)
    {
        int save_errno = errno;

        /*
         * C99 requires that strtod() accept NaN, [+-]Infinity, and [+-]Inf,
         * but not all platforms support all of these (and some accept them
         * but set ERANGE anyway...)  Therefore, we check for these inputs
         * ourselves if strtod() fails.
         *
         * Note: C99 also requires hexadecimal input as well as some extended
         * forms of NaN, but we consider these forms unportable and don't try
         * to support them.  You can use 'em if your strtod() takes 'em.
         */
        if (pg_strncasecmp(num, "NaN", 3) == 0)
        {
            val = get_float4_nan();
            endptr = num + 3;
        }
        else if (pg_strncasecmp(num, "Infinity", 8) == 0)
        {
            val = get_float4_infinity();
            endptr = num + 8;
        }
        else if (pg_strncasecmp(num, "+Infinity", 9) == 0)
        {
            val = get_float4_infinity();
            endptr = num + 9;
        }
        else if (pg_strncasecmp(num, "-Infinity", 9) == 0)
        {
            val = -get_float4_infinity();
            endptr = num + 9;
        }
        else if (pg_strncasecmp(num, "inf", 3) == 0)
        {
            val = get_float4_infinity();
            endptr = num + 3;
        }
        else if (pg_strncasecmp(num, "+inf", 4) == 0)
        {
            val = get_float4_infinity();
            endptr = num + 4;
        }
        else if (pg_strncasecmp(num, "-inf", 4) == 0)
        {
            val = -get_float4_infinity();
            endptr = num + 4;
        }
        else if (save_errno == ERANGE)
        {
            /*
             * Some platforms return ERANGE for denormalized numbers (those
             * that are not zero, but are too close to zero to have full
             * precision).  We'd prefer not to throw error for that, so try to
             * detect whether it's a "real" out-of-range condition by checking
             * to see if the result is zero or huge.
             */
            if (val == 0.0 || val >= HUGE_VAL || val <= -HUGE_VAL)
                ereport(ERROR,
                        (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                         errmsg("\"%s\" is out of range for type real",
                                orig_num)));
        }
        else
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                     errmsg("invalid input syntax for type %s: \"%s\"",
                            "real", orig_num)));
    }
#ifdef HAVE_BUGGY_SOLARIS_STRTOD
    else
    {
        /*
         * Many versions of Solaris have a bug wherein strtod sets endptr to
         * point one byte beyond the end of the string when given "inf" or
         * "infinity".
         */
        if (endptr != num && endptr[-1] == '\0')
            endptr--;
    }
#endif /* HAVE_BUGGY_SOLARIS_STRTOD */

    /* skip trailing whitespace */
    while (*endptr != '\0' && isspace((unsigned char)*endptr))
        endptr++;

    /* if there is any junk left at the end of the string, bail out */
    if (*endptr != '\0')
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                 errmsg("invalid input syntax for type %s: \"%s\"",
                        "real", orig_num)));

    /*
     * if we get here, we have a legal double, still need to check to see if
     * it's a legal float4
     */
    //CHECKFLOATVAL((float4) val, isinf(val), val == 0);

    return ((float4)val);
}

/*
 * The function converts a numeric datatype(postgres variable datatype can be any of int2, int4, int8, float4, float8) to enc_float4 value.
 * This function is called by sql function CAST. It uses function pg_float4_in to convert it to float4 and return an error if it can't
 * It requires a running SGX enclave and uses the function 'enc_float32_encrypt' from the 'interface' library.
 * @input: float4
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(numeric_to_enc_float4);
Datum
    numeric_to_enc_float4(PG_FUNCTION_ARGS)
{
    Numeric num = PG_GETARG_NUMERIC(0);
    char* pDst = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));
    int ans;
    float4 src;
    char* tmp = DatumGetCString(DirectFunctionCall1(numeric_out, NumericGetDatum(num)));

    if (debugMode == true)
    {
        src = pg_float4_in(tmp);
        ans = enc_float32_encrypt(src, pDst);
        sgxErrorHandler(ans);
    }
    else
        ereport(ERROR, (errmsg("Cannot convert numeric to enc_float4, try 'select enable_debug_mode(1)' to allow auto encryption/decryption or select pg_enc_float4_encrypt()")));

    pfree(tmp);

    PG_RETURN_CSTRING((const char*)pDst);
}

/*
 * The function converts a double precision datatype to enc_float4 value.
 * This function is called by sql function CAST. It uses function pg_float4_in to convert it to float4 and return an error if it can't
 * It requires a running SGX enclave and uses the function 'enc_float32_encrypt' from the 'interface' library.
 * @input: float8
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(double_to_enc_float4);
Datum
    double_to_enc_float4(PG_FUNCTION_ARGS)
{
    float8 num = PG_GETARG_FLOAT8(0);
    char* pDst = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));
    int ans;
    float4 src;
    char* tmp = DatumGetCString(DirectFunctionCall1(float8out, Float8GetDatum(num)));

    if (debugMode == true)
    {
        src = pg_float4_in(tmp);
        ans = enc_float32_encrypt(src, pDst);
        sgxErrorHandler(ans);
    }
    else
        ereport(ERROR, (errmsg("Cannot convert double to enc_float4, try 'select enable_debug_mode(1)' to allow auto encryption/decryption or select pg_enc_float4_encrypt(%f)", num)));

    pfree(tmp);

    PG_RETURN_CSTRING((const char*)pDst);
}

/*
 * The function converts a bigint (int8) datatype to enc_float4 value.
 * This function is called by sql function CAST. It uses function pg_float4_in to convert it to float4 and return an error if it can't
 * It requires a running SGX enclave and uses the function 'enc_float32_encrypt' from the 'interface' library.
 * @input: int8
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(int8_to_enc_float4);
Datum
    int8_to_enc_float4(PG_FUNCTION_ARGS)
{
    int8 num = PG_GETARG_INT64(0);
    char* pDst = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));
    int ans;
    float4 src;
    char* tmp = DatumGetCString(DirectFunctionCall1(int8out, Int8GetDatum(num)));

    if (debugMode == true)
    {
        src = pg_float4_in(tmp);
        ans = enc_float32_encrypt(src, pDst);
        sgxErrorHandler(ans);
    }
    else
        ereport(ERROR, (errmsg("Cannot convert int8 to enc_float4, try 'select enable_debug_mode(1)' to allow auto encryption/decryption or select pg_enc_float4_encrypt(%d)", num)));

    pfree(tmp);

    PG_RETURN_CSTRING((const char*)pDst);
}

/*
 * The function converts a int (int4) datatype to enc_float4 value.
 * This function is called by sql function CAST. It uses function pg_float4_in to convert it to float4 and return an error if it can't
 * It requires a running SGX enclave and uses the function 'enc_float32_encrypt' from the 'interface' library.
 * @input: int4
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(int4_to_enc_float4);
Datum
    int4_to_enc_float4(PG_FUNCTION_ARGS)
{
    int num = PG_GETARG_INT32(0);
    char* pDst = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));
    int ans;
    float4 src;
    char* tmp = DatumGetCString(DirectFunctionCall1(int4out, Int32GetDatum(num)));

    if (debugMode == true)
    {
        src = pg_float4_in(tmp);
        ans = enc_float32_encrypt(src, pDst);
        sgxErrorHandler(ans);
    }
    else
        ereport(ERROR, (errmsg("Cannot convert int4 to enc_float4, try 'select enable_debug_mode(1)' to allow auto encryption/decryption or select pg_enc_float4_encrypt(%d)", num)));

    pfree(tmp);

    PG_RETURN_CSTRING((const char*)pDst);
}

/*
 * The function converts string to enc_float4. It is called by dbms every time it parses a query and finds an enc_float4 element.
 * It uses function pg_float4_in to convert it to float4 and returns an error if it can't
 * @input: string as a postgres arg
 * @return: enc_float4 element as a string
 */
PG_FUNCTION_INFO_V1(pg_enc_float4_in);
Datum
    pg_enc_float4_in(PG_FUNCTION_ARGS)
{
    char* pSrc = PG_GETARG_CSTRING(0);
    char* pDst = (char*)palloc((ENC_FLOAT4_LENGTH_B64) * sizeof(char));
    float dst;
    int resp;

    if (debugMode == true)
    {
        /*
         * if the length of string isnot expected
         * check if it is an float4 and encrypt it
         * pg_float4_in is almost postgres function that raises an error in case it exists
         */
        if (strlen(pSrc) != ENC_FLOAT4_LENGTH_B64 - 1)
        {
            dst = pg_float4_in(pSrc);
            resp = enc_float32_encrypt(dst, pDst);
            sgxErrorHandler(resp);
            //ereport(INFO, (errmsg("auto encryption: ENC(%f) = %s", dst, pDst)));
            PG_RETURN_CSTRING((const char*)pDst);
        }
        else
        {
            memcpy(pDst, pSrc, ENC_FLOAT4_LENGTH_B64);
            pDst[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';
        }
    }
    else
    {
        if (strlen(pSrc) != ENC_FLOAT4_LENGTH_B64 - 1)
        {
            ereport(ERROR, (errmsg("Incorrect length of enc_float4 element, try 'select enable_debug_mode(1)' to allow auto encryption/decryption or select pg_enc_float4_encrypt")));
        }
        else
        {
            memcpy(pDst, pSrc, ENC_FLOAT4_LENGTH_B64);
            pDst[ENC_FLOAT4_LENGTH_B64 - 1] = '\0';
        }
    }
    PG_RETURN_CSTRING(pDst);
}
