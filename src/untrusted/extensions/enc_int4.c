/*
 * enc_int4.c : This library defines exported functions for the encrypted integer(4 bytes) datatype.
 * The library contains functions for the Postgresql extension 'encdb', including:
 *
 * encrypted integer type, format: BASE64(IV[12bytes]||AES-GCM(int)[4 bytes]||AUTHTAG[16 bytes])
 *          (input size: 4 bytes; output size: 44 bytes; operators: +,-,*,/,%,>=,>,<=,<,=,!=; functions: SUM, AVG, MIN, MAX)
 */
#include "untrusted/extensions/stdafx.h"
extern bool debugMode;

/*
 * The function converts string to enc_int4. It is called by dbms every time it parses a query and finds an enc_int4 element.
 * If flag debugMode is true it tries to convert input to int4 and encrypt it
 * @input: string as a postgres arg
 * @return: enc_int4 element as a string
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_in);
Datum
    pg_enc_int4_in(PG_FUNCTION_ARGS)
{
    char* pSrc = PG_GETARG_CSTRING(0);
    int32 dst_int = 0;
    int ans = ENCLAVE_IS_NOT_RUNNING;
    char* pDst = (char*)palloc(ENC_INT32_LENGTH_B64 * sizeof(char));

    if (debugMode == true)
    {
        /*
         * if the length of string isnot equal to ENC_INT32_LENGTH_B64
         * check if it is an integer and encrypt it
         * pg_atoi is a postgres function that raises an error in case it exists
         */
        if (strlen(pSrc) != ENC_INT32_LENGTH_B64 - 1)
        {
            dst_int = pg_atoi(pSrc, INT32_LENGTH, '\0');
            ans = enc_int32_encrypt(dst_int, pDst);
            sgxErrorHandler(ans);
            //ereport(INFO, (errmsg("auto encryption: ENC(%d) = %s", dst_int, pDst)));
            PG_RETURN_CSTRING((const char*)pDst);
        }
        else
        {
            memcpy(pDst, pSrc, ENC_INT32_LENGTH_B64);
            pDst[ENC_INT32_LENGTH_B64 - 1] = '\0';
        }
    }
    else
    {
        if (strlen(pSrc) != ENC_INT32_LENGTH_B64 - 1)
        {
            ereport(ERROR, (errmsg("Incorrect length of enc_int4 element, try 'select enable_debug_mode(1)' to allow auto encryption/decryption or select pg_enc_int4_encrypt")));
        }
        else
        {
            memcpy(pDst, pSrc, ENC_INT32_LENGTH_B64);
            pDst[ENC_INT32_LENGTH_B64 - 1] = '\0';
        }
    }

    PG_RETURN_CSTRING(pDst);
}

/*
 * The function converts enc_int4 element to a string. If flag debugMode is true it decrypts the string and return unencrypted result.
 * @input: enc_int4 element
 * @return: string
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_out);
Datum
    pg_enc_int4_out(PG_FUNCTION_ARGS)
{
    char* pSrc = PG_GETARG_CSTRING(0);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    char* str = (char*)palloc(ENC_INT32_LENGTH_B64 * sizeof(char));
    int resp = ENCLAVE_IS_NOT_RUNNING;
    int ans;

    memcpy(str, pSrc, ENC_INT32_LENGTH_B64);
    if (debugMode == true)
    {
        resp = enc_int32_decrypt(pSrc, pDst);
        memcpy(&ans, pDst, INT32_LENGTH);
        sgxErrorHandler(resp);
        sprintf(str, "%d", ans);
        //ereport(INFO, (errmsg("auto decryption: DEC('%s') = %d", pSrc, ans)));
    }
    pfree(pDst);
    //pfree(str);

    PG_RETURN_CSTRING(str);
}

/*
 * The function calculates the sum of two enc_int4 values. It is called by binary operator '+' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_add' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: encrypted sum of input values
 * output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
*/
PG_FUNCTION_INFO_V1(pg_enc_int4_add);
Datum
    pg_enc_int4_add(PG_FUNCTION_ARGS)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* pSrc1 = PG_GETARG_CSTRING(0);
    char* pSrc2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));

    resp = enc_int32_add(pSrc1, pSrc2, pDst);
    sgxErrorHandler(resp);

    pDst[ENC_INT32_LENGTH_B64 - 1] = '\0';
    PG_RETURN_CSTRING(pDst);
}

/*
 * The function calculates the subtraction of two enc_int4 values. It is called by binary operator '-' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_sub' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_sub);
Datum
    pg_enc_int4_sub(PG_FUNCTION_ARGS)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));

    resp = enc_int32_sub(c1, c2, pDst);
    sgxErrorHandler(resp);

    pDst[ENC_INT32_LENGTH_B64 - 1] = '\0';
    PG_RETURN_CSTRING(pDst);
}

/*
 * The function calculates the product of two enc_int4 values. It is called by binary operator '*' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_mult' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_mult);
Datum
    pg_enc_int4_mult(PG_FUNCTION_ARGS)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));

    resp = enc_int32_mult(c1, c2, pDst);
    sgxErrorHandler(resp);

    pDst[ENC_INT32_LENGTH_B64 - 1] = '\0';
    PG_RETURN_CSTRING(pDst);
}

/*
 * The function calculates the division of two enc_int4 values. It is called by binary operator '/' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_div' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_div);
Datum
    pg_enc_int4_div(PG_FUNCTION_ARGS)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));

    resp = enc_int32_div(c1, c2, pDst);
    sgxErrorHandler(resp);

    pDst[ENC_INT32_LENGTH_B64 - 1] = '\0';
    PG_RETURN_CSTRING(pDst);
}

/*
 * The function calculates the first input enc_int4 value to the power of the second input enc_int4 value.
 * It is called by binary operator '^' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_pow' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_pow);
Datum
    pg_enc_int4_pow(PG_FUNCTION_ARGS)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));

    resp = enc_int32_pow(c1, c2, pDst);
    sgxErrorHandler(resp);

    pDst[ENC_INT32_LENGTH_B64 - 1] = '\0';
    PG_RETURN_CSTRING(pDst);
}

/*
 * The function calculates the first input enc_int4 value by module the second input enc_int4 value.
 * It is called by binary operator '%' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_mod' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_mod);
Datum
    pg_enc_int4_mod(PG_FUNCTION_ARGS)
{
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));

    resp = enc_int32_mod(c1, c2, pDst);
    sgxErrorHandler(resp);

    pDst[ENC_INT32_LENGTH_B64 - 1] = '\0';
    PG_RETURN_CSTRING(pDst);
}

/*
 * The function compares two enc_int4 values. It is called mostly during index building.
 * It requires a running SGX enclave and uses the function 'enc_int32_cmp' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: -1, 0 ,1
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_cmp);
Datum
    pg_enc_int4_cmp(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    int resp = ENCLAVE_IS_NOT_RUNNING;
    int ans = 0;

    resp = enc_int32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, INT32_LENGTH);

    pfree(pDst);
    PG_RETURN_INT32(ans);
}

/*
 * The function checks if the first input enc_int4 is equal to the second one.
 * It is called by binary operator '=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_cmp' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: true, if the first decrypted integer is equal to the second one.
 *       false, otherwise
*/
PG_FUNCTION_INFO_V1(pg_enc_int4_eq);
Datum
    pg_enc_int4_eq(PG_FUNCTION_ARGS)
{
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp = false;

    resp = enc_int32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, INT32_LENGTH);
    if (ans == 0)
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input enc_int4 is not equal to the second one.
 * It is called by binary operator '!=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_cmp' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: true, if the first decrypted integer is not equal to the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_ne);
Datum
    pg_enc_int4_ne(PG_FUNCTION_ARGS)
{
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp = false;

    resp = enc_int32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);
    memcpy(&ans, pDst, INT32_LENGTH);

    if (ans == 0)
        cmp = false;
    else
        cmp = true;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input enc_int4 is less than the second one.
 * It is called by binary operator '<' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_cmp' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: true, if the first decrypted integer is less the the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_lt);
Datum
    pg_enc_int4_lt(PG_FUNCTION_ARGS)
{
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp = false;

    resp = enc_int32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);
    memcpy(&ans, pDst, INT32_LENGTH);

    if (ans == -1)
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input enc_int4 is less or equal than the second one.
 * It is called by binary operator '<=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_cmp' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: true, if the first decrypted integer is less or equal than the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_le);
Datum
    pg_enc_int4_le(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp;

    resp = enc_int32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);
    memcpy(&ans, pDst, INT32_LENGTH);

    if ((ans == -1) || (ans == 0))
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input enc_int4 is greater than the second one.
 * It is called by binary operator '>' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_cmp' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: true, if the first decrypted integer is greater than the second one.
 *          false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_gt);
Datum
    pg_enc_int4_gt(PG_FUNCTION_ARGS)
{
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp;

    resp = enc_int32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);
    memcpy(&ans, pDst, INT32_LENGTH);

    if (ans == 1)
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input enc_int4 is greater or equal than the second one.
 * It is called by binary operator '>=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_int32_cmp' from the 'interface' library.
 * @input: two enc_int4 values
 * @return: true, if the first decrypted integer is greater or equal than the second one.
 *          false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_ge);
Datum
    pg_enc_int4_ge(PG_FUNCTION_ARGS)
{
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    int ans = 0;
    int resp = ENCLAVE_IS_NOT_RUNNING;
    bool cmp;

    resp = enc_int32_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);
    memcpy(&ans, pDst, INT32_LENGTH);

    if ((ans == 0) || (ans == 1))
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

//TODO
// DEBUG FUNCTION
// WILL BE DELETED IN THE PRODUCT
PG_FUNCTION_INFO_V1(pg_enc_int4_encrypt);
Datum
    pg_enc_int4_encrypt(PG_FUNCTION_ARGS)
{
    char* pDst;
    int c1 = PG_GETARG_INT32(0);
    int ans;
    pDst = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    //pDst = encryptREncInt(c1);
    ans = enc_int32_encrypt(c1, pDst);
    sgxErrorHandler(ans);
    //ereport(LOG, (errmsg("function encrypt, output: %s", ans)));
    PG_RETURN_CSTRING((const char*)pDst);
}

//TODO
// DEBUG FUNCTION
// WILL BE DELETED IN THE PRODUCT
PG_FUNCTION_INFO_V1(pg_enc_int4_decrypt);
Datum
    pg_enc_int4_decrypt(PG_FUNCTION_ARGS)
{
    int resp, ans = 0;
    char* pSrc = PG_GETARG_CSTRING(0);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));

    resp = enc_int32_decrypt(pSrc, pDst);
    memcpy(&ans, pDst, INT32_LENGTH);
    sgxErrorHandler(resp);
    //ereport(LOG, (errmsg("function decrypt, output: %d", ans)));

    pfree(pDst);
    PG_RETURN_INT32(ans);
}

/*
 * The function calculates the sum of elements from input array
 * It is called by sql aggregate command SUM, which is firstly appends needed enc_int4 elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'enc_int32_add' from the 'interface' library.
 * @input: an array of enc_int4 values which should be summarize
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_addfinal);
Datum
    pg_enc_int4_addfinal(PG_FUNCTION_ARGS)
{
    ArrayType* v = PG_GETARG_ARRAYTYPE_P(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    ArrayIterator array_iterator;
    ArrayMetaState* my_extra = (ArrayMetaState*)fcinfo->flinfo->fn_extra;
    bool isnull;
    Datum value;

    char* pSrc1 = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pSrc2 = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pTemp = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));

    array_iterator = array_create_iterator(v, 0, my_extra);
    array_iterate(array_iterator, &value, &isnull);

    memcpy(pSrc1, DatumGetCString(value), ENC_INT32_LENGTH_B64);
    pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';

    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(pTemp, DatumGetCString(value), ENC_INT32_LENGTH_B64);
        pTemp[ENC_INT32_LENGTH_B64 - 1] = '\0';
        resp = enc_int32_add(pSrc1, pTemp, pSrc2);
        sgxErrorHandler(resp);

        memcpy(pSrc1, pSrc2, ENC_INT32_LENGTH_B64);
        pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';
    }

    pfree(pTemp);
    pfree(pSrc2);

    PG_RETURN_CSTRING(pSrc1);
}

PG_FUNCTION_INFO_V1(pg_enc_int4_sum_bulk);
Datum
    pg_enc_int4_sum_bulk(PG_FUNCTION_ARGS)
{
    ArrayType* v = PG_GETARG_ARRAYTYPE_P(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    ArrayIterator array_iterator;
    ArrayMetaState* my_extra = (ArrayMetaState*)fcinfo->flinfo->fn_extra;
    bool isnull;
    Datum value;
    size_t bulk_size = BULK_SIZE;
    unsigned long current_position = 0, counter = 0;
    char* pSrc2 = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pTemp = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char) * bulk_size);

    array_iterator = array_create_iterator(v, 0, my_extra);
    while (array_iterate(array_iterator, &value, &isnull))
    {
        //      ereport(INFO, (errmsg("add %d:  %s", current_position, DatumGetCString(value))));
        memcpy(pTemp + current_position, DatumGetCString(value), ENC_INT32_LENGTH_B64);
        current_position += ENC_INT32_LENGTH_B64;
        counter++;

        if (counter % (bulk_size) == 0)
        {
            resp = enc_int32_sum_bulk(bulk_size, pTemp, pSrc2);
            //ereport(INFO, (errmsg("ret %d", resp)));
            sgxErrorHandler(resp);

            memcpy(pTemp, pSrc2, ENC_INT32_LENGTH_B64);
            current_position = ENC_INT32_LENGTH_B64;
            counter++;
            //          ereport(INFO, (errmsg("res %s", pSrc2)));
        }
    }

    //        ereport(INFO, (errmsg("send rest %d: bulk %d,  %s", current_position, counter%bulk_size, pTemp)));
    resp = enc_int32_sum_bulk(counter % bulk_size, pTemp, pSrc2);
    sgxErrorHandler(resp);

    pfree(pTemp);
    PG_RETURN_CSTRING(pSrc2);
}

/*
 * The function computes the average of elements from array of enc_int4 elements.
 * It is called by sql aggregate command AVG, which is firstly appends needed enc_int4 elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'enc_int32_add', 'enc_int32_div', 'enc_int32_encrypt' from the 'interface' library.
 * @input: an array of enc_int4 elements
 * @return: an encrypted result (encrypted integer). output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_avgfinal);
Datum
    pg_enc_int4_avgfinal(PG_FUNCTION_ARGS)
{
    ArrayType* v = PG_GETARG_ARRAYTYPE_P(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    ArrayIterator array_iterator;
    ArrayMetaState* my_extra = (ArrayMetaState*)fcinfo->flinfo->fn_extra;
    bool isnull;
    Datum value;
    int ndims1 = ARR_NDIM(v); //array dimension
    int* dims1 = ARR_DIMS(v);
    int nitems = ArrayGetNItems(ndims1, dims1); //number of items in array
    char* pSrc1 = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pSrc2 = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pTemp = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));

    array_iterator = array_create_iterator(v, 0, my_extra);
    array_iterate(array_iterator, &value, &isnull);

    memcpy(pSrc1, DatumGetCString(value), ENC_INT32_LENGTH_B64);
    pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';
    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(pTemp, DatumGetCString(value), ENC_INT32_LENGTH_B64);
        pTemp[ENC_INT32_LENGTH_B64 - 1] = '\0';

        resp = enc_int32_add(pSrc1, pTemp, pSrc2);
        sgxErrorHandler(resp);

        memcpy(pSrc1, pSrc2, ENC_INT32_LENGTH_B64);
        pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';
    }

    resp = enc_int32_encrypt(nitems, pTemp);
    sgxErrorHandler(resp);

    resp = enc_int32_div(pSrc1, pTemp, pSrc2);
    sgxErrorHandler(resp);

    pfree(pTemp);
    pfree(pSrc1);

    PG_RETURN_CSTRING(pSrc2);
}

PG_FUNCTION_INFO_V1(pg_enc_int4_avg_bulk);
Datum
    pg_enc_int4_avg_bulk(PG_FUNCTION_ARGS)
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
    char* pSrc1 = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pSrc2 = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pTemp = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char) * bulk_size);

    array_iterator = array_create_iterator(v, 0, my_extra);

    while (array_iterate(array_iterator, &value, &isnull))
    {
        //ereport(INFO, (errmsg("add %d:  %s", current_position, DatumGetCString(value))));
        memcpy(pTemp + current_position, DatumGetCString(value), ENC_INT32_LENGTH_B64);
        current_position += ENC_INT32_LENGTH_B64;
        counter++;

        if (counter % (bulk_size) == 0)
        {
            resp = enc_int32_sum_bulk(bulk_size, pTemp, pSrc2);
            //ereport(INFO, (errmsg("ret %d", resp)));
            sgxErrorHandler(resp);

            memcpy(pTemp, pSrc2, ENC_INT32_LENGTH_B64);
            current_position = ENC_INT32_LENGTH_B64;
            counter++;
            //ereport(INFO, (errmsg("res %s", pSrc2)));
        }
    }

    //ereport(INFO, (errmsg("send rest %d: bulk %d,  %s", current_position, counter%bulk_size, pTemp)));
    resp = enc_int32_sum_bulk(counter % bulk_size, pTemp, pSrc1);
    sgxErrorHandler(resp);

    resp = enc_int32_encrypt(nitems, pTemp);
    sgxErrorHandler(resp);

    resp = enc_float32_div(pSrc1, pTemp, pSrc2);
    sgxErrorHandler(resp);

    pfree(pTemp);
    pfree(pSrc1);

    PG_RETURN_CSTRING(pSrc2);
}

/*
 * The function computes the minimal element of array of enc_int4 elements
 * It is called by sql aggregate command MIN, which is firstly appends needed enc_int4 elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'enc_int32_cmp' from the 'interface' library.
 * @input: an array of enc_int4 elements
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_minfinal);
Datum
    pg_enc_int4_minfinal(PG_FUNCTION_ARGS)
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

    char* pSrc1 = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pTemp = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));

    array_iterator = array_create_iterator(v, 0, my_extra);
    array_iterate(array_iterator, &value, &isnull);

    memcpy(pSrc1, DatumGetCString(value), ENC_INT32_LENGTH_B64);
    pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';

    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(pTemp, DatumGetCString(value), ENC_INT32_LENGTH_B64);
        pTemp[ENC_INT32_LENGTH_B64 - 1] = '\0';

        resp = enc_int32_cmp(pSrc1, pTemp, pDst);
        sgxErrorHandler(resp);
        memcpy(&ans, pDst, INT32_LENGTH);

        if (ans == 1)
            memcpy(pSrc1, pTemp, ENC_INT32_LENGTH_B64);
        pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';
    }

    pfree(pDst);
    pfree(pTemp);

    PG_RETURN_CSTRING(pSrc1);
}

PG_FUNCTION_INFO_V1(pg_enc_int4_min_bulk);
Datum
    pg_enc_int4_min_bulk(PG_FUNCTION_ARGS)
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

    char* pSrc1 = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pTemp = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));

    array_iterator = array_create_iterator(v, 0, my_extra);
    array_iterate(array_iterator, &value, &isnull);

    memcpy(pSrc1, DatumGetCString(value), ENC_INT32_LENGTH_B64);
    pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';

    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(pTemp, DatumGetCString(value), ENC_INT32_LENGTH_B64);
        pTemp[ENC_INT32_LENGTH_B64 - 1] = '\0';

        resp = enc_int32_cmp(pSrc1, pTemp, pDst);
        sgxErrorHandler(resp);
        memcpy(&ans, pDst, INT32_LENGTH);

        if (ans == 1)
            memcpy(pSrc1, pTemp, ENC_INT32_LENGTH_B64);
        pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';
    }

    pfree(pDst);
    pfree(pTemp);

    PG_RETURN_CSTRING(pSrc1);
}
/*
 * The function computes the maximal element of array of enc_int4 elements
 * It is called by sql aggregate command MAX, which is firstly appends needed enc_int4 elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'enc_int32_cmp' from the 'interface' library.
 * @input: array of enc_int4 elements
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_enc_int4_maxfinal);
Datum
    pg_enc_int4_maxfinal(PG_FUNCTION_ARGS)
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

    char* pSrc1 = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pTemp = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));

    array_iterator = array_create_iterator(v, 0, my_extra);
    array_iterate(array_iterator, &value, &isnull);

    memcpy(pSrc1, DatumGetCString(value), ENC_INT32_LENGTH_B64);
    pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';

    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(pTemp, DatumGetCString(value), ENC_INT32_LENGTH_B64);
        pTemp[ENC_INT32_LENGTH_B64 - 1] = '\0';

        resp = enc_int32_cmp(pSrc1, pTemp, pDst);
        sgxErrorHandler(resp);
        memcpy(&ans, pDst, INT32_LENGTH);

        if (ans == -1)
            memcpy(pSrc1, pTemp, ENC_INT32_LENGTH_B64);
        pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';
    }

    pfree(pDst);
    pfree(pTemp);

    PG_RETURN_CSTRING(pSrc1);
}

PG_FUNCTION_INFO_V1(pg_enc_int4_max_bulk);
Datum
    pg_enc_int4_max_bulk(PG_FUNCTION_ARGS)
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

    char* pSrc1 = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pTemp = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));

    array_iterator = array_create_iterator(v, 0, my_extra);
    array_iterate(array_iterator, &value, &isnull);

    memcpy(pSrc1, DatumGetCString(value), ENC_INT32_LENGTH_B64);
    pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';

    while (array_iterate(array_iterator, &value, &isnull))
    {
        memcpy(pTemp, DatumGetCString(value), ENC_INT32_LENGTH_B64);
        pTemp[ENC_INT32_LENGTH_B64 - 1] = '\0';

        resp = enc_int32_cmp(pSrc1, pTemp, pDst);
        sgxErrorHandler(resp);
        memcpy(&ans, pDst, INT32_LENGTH);

        if (ans == -1)
            memcpy(pSrc1, pTemp, ENC_INT32_LENGTH_B64);
        pSrc1[ENC_INT32_LENGTH_B64 - 1] = '\0';
    }

    pfree(pDst);
    pfree(pTemp);

    PG_RETURN_CSTRING(pSrc1);
}

/*
 * The function converts an integer to enc_int4 value. This function is calles by sql function CAST.
 * It requires a running SGX enclave and uses the function 'enc_int32_encrypt' from the 'interface' library.
 * @input: int4
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_int4_to_enc_int4);
Datum
    pg_int4_to_enc_int4(PG_FUNCTION_ARGS)
{
    int c1 = PG_GETARG_INT32(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* pDst = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));

    if (debugMode == true)
    {
        resp = enc_int32_encrypt(c1, pDst);
        sgxErrorHandler(resp);
        //ereport(INFO, (errmsg("auto encryption: ENC(%d) = %s", c1, pDst)));
    }
    else
        ereport(ERROR, (errmsg("Cannot convert int8 to enc_int4, try 'select enable_debug_mode(1)' to allow auto encryption/decryption or select pg_enc_int4_encrypt(%d)", c1)));

    PG_RETURN_CSTRING((const char*)pDst);
}

/*
 * The function converts an integer(8 bytes, known as bigint) to enc_int4 value. This function is calles by sql function CAST.
 * It requires a running SGX enclave and uses the function 'enc_int32_encrypt' from the 'interface' library.
 * @input: int8
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(pg_int8_to_enc_int4);
Datum
    pg_int8_to_enc_int4(PG_FUNCTION_ARGS)
{
    int64 c1 = PG_GETARG_INT64(0);
    int resp = ENCLAVE_IS_NOT_RUNNING;
    char* pDst = (char*)palloc((ENC_INT32_LENGTH_B64) * sizeof(char));

    if (debugMode == true)
    {
        if (c1 < INT_MIN || c1 > INT_MAX)
            ereport(ERROR, (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE), errmsg("value \"%li\" is out of range for type %s", c1, "integer")));
        resp = enc_int32_encrypt((int32)c1, pDst);
        sgxErrorHandler(resp);
        //ereport(INFO, (errmsg("auto encryption: ENC(%d) = %s", c1, pDst)));
    }
    else
        ereport(ERROR, (errmsg("Cannot convert int8 to enc_int4, try 'select enable_debug_mode(1)' to allow auto encryption/decryption or select pg_enc_int4_encrypt(%ld)", c1)));

    PG_RETURN_CSTRING((const char*)pDst);
}
