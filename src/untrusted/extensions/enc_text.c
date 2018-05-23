/*
 * enc_text.c : Defines the exported functions for the encrypted text type.
 * The library contains functions for the Postgresql extension 'encdb', including:
 *
 * enc_text type, format: BASE64(IV[12bytes]||AES-GCM(text)[4 bytes]||AUTHTAG[16 bytes])
 *          (operators: ||, >=,>,<=,<,=,!=; functions: LIKE)
 */
#include "untrusted/extensions/stdafx.h"

// the structure is used to describe an element of the enc_text type
typedef struct enc_str
{
    int length;
    char src[1024];
} enc_str;

extern bool debugMode;

// The input function converts a string to an enc_text element.
// @input: string
// @return: pointer to a structure describing enc_text element.
PG_FUNCTION_INFO_V1(pg_enc_text_in);
Datum
    pg_enc_text_in(PG_FUNCTION_ARGS)
{
    char* pSrc = PG_GETARG_CSTRING(0);
    int srcLen = strlen(pSrc);
    int dst_len = ((int)(4 * (double)(srcLen + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE) / 3) + 3) & ~3;

    enc_str* enc_str_var = (enc_str*)palloc(sizeof(enc_str));
    char* pDst = (char*)palloc(dst_len * sizeof(char));
    int resp = ENCLAVE_IS_NOT_RUNNING;
    int min_enctext_len = 0;
    if (!enc_str_var)
    {
        PG_RETURN_NULL();
    }

    if (srcLen > STRING_LENGTH - 1)
    {
        ereport(ERROR, (errmsg("Error: the length of the element is more than maximum")));
        PG_RETURN_CSTRING("");
    }

    memset(pDst, 0, dst_len);
    // the minimal possible length of encrypted string
    min_enctext_len = ((int)(4 * (double)(SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE) / 3) + 3) & ~3;

    // try to decrypt the string if size less min_enctext_len=40
    // if it returns an error encrypt it
    if (srcLen > min_enctext_len - 1)
    {
        resp = enc_text_decrypt(pSrc, srcLen, pDst, dst_len);
        memset(pDst, 0, dst_len);
        if (resp == SGX_SUCCESS)
        {
            memcpy(pDst, pSrc, srcLen);
            pDst[srcLen] = '\0';
        }
        else
        { //resp != SGX_SUCCESS
            if (resp != SGX_ERROR_MAC_MISMATCH)
                sgxErrorHandler(resp);
            else
            { //resp == SGX_ERROR_MAC_MISMATCH, i.e. decryption error
                if (debugMode == true)
                {
                    resp = enc_text_encrypt(pSrc, srcLen, pDst, dst_len);
                    sgxErrorHandler(resp);
                }
                else // debugMode == false
                    ereport(ERROR, (errmsg("Incorrect input of enc_text element, if you need to encrypt the varchar element try 'select enable_debug_mode(1)' to allow auto encryption/decryption or 'select pg_enc_text_encrypt(%s)'", pSrc)));
            }
        }
    }
    else
    { // srcLen < min_enctext_len-1
        if (debugMode == true)
        {
            resp = enc_text_encrypt(pSrc, srcLen, pDst, dst_len);
            sgxErrorHandler(resp);
        }
        else // debugMode == false
            ereport(ERROR, (errmsg("Incorrect length of enc_text element, if you need to encrypt the varchar element try 'select enable_debug_mode(1)' to allow auto encryption/decryption or 'select pg_enc_text_encrypt(%s)'", pSrc)));
    }

    srcLen = strlen(pDst);
    memcpy(enc_str_var->src, pDst, srcLen);
    enc_str_var->length = srcLen;
    enc_str_var->src[enc_str_var->length] = '\0';

    pfree(pDst);
    PG_RETURN_POINTER(enc_str_var);
}

// The output function converts an enc_text element to a string.
// @input: pointer to a structure describing enc_text element
// @return: string
PG_FUNCTION_INFO_V1(pg_enc_text_out);
Datum
    pg_enc_text_out(PG_FUNCTION_ARGS)
{
    enc_str* pSrc = (enc_str*)PG_GETARG_POINTER(0);
    char* pDst = palloc((pSrc->length + 1) * sizeof(char));
    int resp = ENCLAVE_IS_NOT_RUNNING;

    memset(pDst, 0, pSrc->length + 1);
    memcpy(pDst, pSrc->src, pSrc->length);

    if (debugMode == true)
    {
        resp = enc_text_decrypt(pSrc->src, pSrc->length, pDst, pSrc->length);
        sgxErrorHandler(resp);
        //ereport(INFO, (errmsg("auto decryption: DEC('%s') = %s", pSrc->src, pDst)));
    }

    PG_RETURN_CSTRING(pDst);
}

// The function checks the equality of two encrypted strings.
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if decrypted strings are equal
//       false, otherwise
PG_FUNCTION_INFO_V1(pg_enc_text_eq);
Datum
    pg_enc_text_eq(PG_FUNCTION_ARGS)
{
    enc_str* enc_str1 = (enc_str*)PG_GETARG_POINTER(0);
    enc_str* enc_str2 = (enc_str*)PG_GETARG_POINTER(1);
    char* pDst = palloc((INT32_LENGTH) * sizeof(char));
    bool cmp;
    int ans = 0, resp;

    resp = enc_text_cmp(enc_str1->src, enc_str1->length, enc_str2->src, enc_str2->length, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, INT32_LENGTH);

    if (ans == 0)
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_INT32(cmp);
}

// The function checks the inequality of two encrypted strings.
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if decrypted strings are not equal
//       false, otherwise
PG_FUNCTION_INFO_V1(pg_enc_text_ne);
Datum
    pg_enc_text_ne(PG_FUNCTION_ARGS)
{
    enc_str* enc_str1 = (enc_str*)PG_GETARG_POINTER(0);
    enc_str* enc_str2 = (enc_str*)PG_GETARG_POINTER(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    bool cmp;
    int ans = 0, resp;

    resp = enc_text_cmp(enc_str1->src, enc_str1->length, enc_str2->src, enc_str2->length, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, INT32_LENGTH);

    if (ans != 0)
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

// The function checks if the first input encrypted string is less or equal than the second one.
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if the first decrypted string is less or equal than the second one.
//       false, otherwise
PG_FUNCTION_INFO_V1(pg_enc_text_le);
Datum
    pg_enc_text_le(PG_FUNCTION_ARGS)
{
    enc_str* enc_str1 = (enc_str*)PG_GETARG_POINTER(0);
    enc_str* enc_str2 = (enc_str*)PG_GETARG_POINTER(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    bool cmp;
    int ans = 0, resp;

    resp = enc_text_cmp(enc_str1->src, enc_str1->length, enc_str2->src, enc_str2->length, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, INT32_LENGTH);

    if (ans <= 0)
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

// The function checks if the first input encrypted string is less than the second one.
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if the first decrypted string is less than the second one.
//       false, otherwise
PG_FUNCTION_INFO_V1(pg_enc_text_lt);
Datum
    pg_enc_text_lt(PG_FUNCTION_ARGS)
{
    enc_str* enc_str1 = (enc_str*)PG_GETARG_POINTER(0);
    enc_str* enc_str2 = (enc_str*)PG_GETARG_POINTER(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    bool cmp;
    int ans = 0, resp;

    resp = enc_text_cmp(enc_str1->src, enc_str1->length, enc_str2->src, enc_str2->length, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, INT32_LENGTH);

    if (ans < 0)
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

// The function checks if the first input encrypted string is greater or equal than the second one.
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if the first decrypted string is greater or equal than the second one.
//       false, otherwise
PG_FUNCTION_INFO_V1(pg_enc_text_ge);
Datum
    pg_enc_text_ge(PG_FUNCTION_ARGS)
{
    enc_str* enc_str1 = (enc_str*)PG_GETARG_POINTER(0);
    enc_str* enc_str2 = (enc_str*)PG_GETARG_POINTER(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    bool cmp;
    int ans = 0, resp;

    resp = enc_text_cmp(enc_str1->src, enc_str1->length, enc_str2->src, enc_str2->length, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, INT32_LENGTH);

    if (ans >= 0)
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

// The function checks if the first input encrypted string is greater than the second one.
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if the first decrypted string is greater than the second one.
//       false, otherwise
PG_FUNCTION_INFO_V1(pg_enc_text_gt);
Datum
    pg_enc_text_gt(PG_FUNCTION_ARGS)
{
    enc_str* enc_str1 = (enc_str*)PG_GETARG_POINTER(0);
    enc_str* enc_str2 = (enc_str*)PG_GETARG_POINTER(1);
    char* pDst = palloc((INT32_LENGTH) * sizeof(char));
    bool cmp;
    int ans = 0, resp;

    resp = enc_text_cmp(enc_str1->src, enc_str1->length, enc_str2->src, enc_str2->length, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, INT32_LENGTH);

    if (ans > 0)
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

// The function compares two encrypted strings using the lexgraphical order for decrypted strings
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: -1, if s1 < s2,
//        0, if s1 = s2,
//        1, if s1 > s2
PG_FUNCTION_INFO_V1(pg_enc_text_cmp);
Datum
    pg_enc_text_cmp(PG_FUNCTION_ARGS)
{
    enc_str* enc_str1 = (enc_str*)PG_GETARG_POINTER(0);
    enc_str* enc_str2 = (enc_str*)PG_GETARG_POINTER(1);
    char* pDst = palloc((INT32_LENGTH) * sizeof(char));
    int ans = 0, resp;

    resp = enc_text_cmp(enc_str1->src, enc_str1->length, enc_str2->src, enc_str2->length, pDst);
    sgxErrorHandler(resp);

    memcpy(&ans, pDst, INT32_LENGTH);

    pfree(pDst);
    PG_RETURN_INT32(ans);
}

// The function encrypts the input string.
// IT'S A DEBUG FUNCTION SHOULD BE DELETED IN THE PRODUCT
// !!!!!!!!!!!!!!!!!!!!!!!!!
PG_FUNCTION_INFO_V1(pg_enc_text_encrypt);
Datum
    pg_enc_text_encrypt(PG_FUNCTION_ARGS)
{
    enc_str* enc_str_var = (enc_str*)palloc(sizeof(enc_str));
    int resp;
    char* src = PG_GETARG_CSTRING(0);
    size_t src_len = strlen(src);
    size_t enc_src_len = src_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
    size_t enc_src_b64_len = ((int)(4 * (double)(enc_src_len) / 3) + 3) & ~3;
    char* pDst = (char*)palloc((enc_src_b64_len + 1) * sizeof(char));

    if (src_len > STRING_LENGTH - 1)
    {
        ereport(ERROR, (errmsg("Error: the length of the element is more than maximun")));
        PG_RETURN_CSTRING("");
    }

    resp = enc_text_encrypt(src, src_len, pDst, enc_src_b64_len);
    sgxErrorHandler(resp);

    memcpy(enc_str_var->src, pDst, enc_src_b64_len);
    enc_str_var->length = enc_src_b64_len;

    enc_str_var->src[enc_str_var->length] = '\0';

    PG_RETURN_POINTER(enc_str_var);
}

// The function decrypts the input enc_text element.
// IT'S A DEBUG FUNCTION SHOULD BE DELETED IN THE PRODUCT
// !!!!!!!!!!!!!!!!!!!!!!!!!
PG_FUNCTION_INFO_V1(pg_enc_text_decrypt);
Datum
    pg_enc_text_decrypt(PG_FUNCTION_ARGS)
{
    int ans = 0;
    enc_str* enc_str_var = (enc_str*)PG_GETARG_POINTER(0);
    size_t dst_len = enc_str_var->length - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    char* pDst = palloc(dst_len * sizeof(char));

    ans = enc_text_decrypt(enc_str_var->src, enc_str_var->length, pDst, dst_len);
    sgxErrorHandler(ans);

    PG_RETURN_CSTRING(pDst);
}

// The function decrypts two encrypted strings, concatenates them and encrypts the result.
// It requires a running SGX enclave and uses the function 'concatREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: an encrypted result of a concatenation. output format: BASE64(iv[12 bytes]||AES-GCM(s1||s2)||AUTHTAG[16bytes])
PG_FUNCTION_INFO_V1(pg_enc_text_concatenate);
Datum
    pg_enc_text_concatenate(PG_FUNCTION_ARGS)
{
    enc_str* enc_str1 = (enc_str*)PG_GETARG_POINTER(0);
    enc_str* enc_str2 = (enc_str*)PG_GETARG_POINTER(1);
    enc_str* enc_str_dst = (enc_str*)palloc(sizeof(enc_str));

    int resp;

    // the actual size of dst can be different because of b64 conversion back and forth, but it will be less or equal
    size_t dst_len = enc_str1->length + enc_str2->length + 1 - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    memset(enc_str_dst->src, 0, dst_len);
    if (dst_len > ENC_STRING_LENGTH_B64 - 1)
    {
        ereport(ERROR, (errmsg("Error: the length of the concatenated element is more than maximum")));
        PG_RETURN_CSTRING("");
    }

    resp = enc_text_concatenate(enc_str1->src, enc_str1->length, enc_str2->src, enc_str2->length, enc_str_dst->src, &dst_len);
    sgxErrorHandler(resp);

    enc_str_dst->src[dst_len] = '\0';
    enc_str_dst->length = dst_len;

    PG_RETURN_POINTER(enc_str_dst);
}

PG_FUNCTION_INFO_V1(pg_enc_text_like);
Datum
    pg_enc_text_like(PG_FUNCTION_ARGS)
{
    enc_str* str = (enc_str*)PG_GETARG_POINTER(0);
    enc_str* pattern = (enc_str*)PG_GETARG_POINTER(1);
    int result = 0;
    int resp;

    resp = enc_text_like(str->src, str->length, pattern->src, pattern->length, &result);
    sgxErrorHandler(resp);

    PG_RETURN_BOOL(result);
}

PG_FUNCTION_INFO_V1(pg_enc_text_notlike);
Datum
    pg_enc_text_notlike(PG_FUNCTION_ARGS)
{
    enc_str* str = (enc_str*)PG_GETARG_POINTER(0);
    enc_str* pattern = (enc_str*)PG_GETARG_POINTER(1);
    int result = 0;
    int resp;

    resp = enc_text_like(str->src, str->length, pattern->src, pattern->length, &result);
    sgxErrorHandler(resp);

    PG_RETURN_BOOL(1 ^ result);
}

// This function implements PostgreSQL's substring(encrypted_string, [from encrypted_int], [to encrypted_int]) functionality.
// @input: encrypted string and two encrypted integers
// @return: the substring specified by from and to. output format: BASE64(iv[12 bytes]||AES-GCM(s1||s2)||AUTHTAG[16bytes])
PG_FUNCTION_INFO_V1(substring);
Datum
    substring(PG_FUNCTION_ARGS)
{
    enc_str* str = (enc_str*)PG_GETARG_POINTER(0);
    char* from = PG_GETARG_CSTRING(1);
    char* n_chars = PG_GETARG_CSTRING(2);

    enc_str* out = palloc(sizeof(*out));
    memset(out, 0, sizeof(*out));
    size_t out_size = (str->length + 1);

    if (out_size > ENC_STRING_LENGTH_B64 - 1)
    {
        ereport(ERROR, (errmsg("Error: The length of the input exceeds the maximum.")));
        PG_RETURN_CSTRING("");
    }

    int resp = enc_text_substring(str->src, str->length, from, strlen(from), n_chars, strlen(n_chars), out->src, &out_size);
    sgxErrorHandler(resp);

    out->src[out_size] = '\0';
    out->length = out_size;

    PG_RETURN_POINTER(out);
}

// The input function converts a string to an enc_text element.
// @input: varying char
// @return: pointer to a structure describing enc_text element.
PG_FUNCTION_INFO_V1(varchar_to_enc_text);
Datum
    varchar_to_enc_text(PG_FUNCTION_ARGS)
{
    Datum txt = PG_GETARG_DATUM(0);
    char* src = TextDatumGetCString(txt);
    int len = strlen(src);

    enc_str* enc_str_var = (enc_str*)palloc(sizeof(enc_str));
    ;
    int resp, b64_len, len2;
    char* pDst = (char*)palloc((ENC_STRING_LENGTH_B64) * sizeof(char));

    if (len > STRING_LENGTH - 1)
    {
        ereport(ERROR, (errmsg("Error: the length of the element is more than maximum")));
        PG_RETURN_CSTRING("");
    }
    len2 = len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
    b64_len = ((int)(4 * (double)(len2) / 3) + 3) & ~3;

    if (debugMode == true)
    {
        resp = enc_text_encrypt(src, len, pDst, b64_len);
        sgxErrorHandler(resp);
        len2 = strlen(pDst);

        memcpy(enc_str_var->src, pDst, len2);
        enc_str_var->length = len2;
        enc_str_var->src[enc_str_var->length] = '\0';
    }
    else
        ereport(ERROR, (errmsg("Cannot convert varchar to enc_text, try 'select enable_debug_mode(1)' to allow auto encryption/decryption or select pg_enc_text_encrypt(%s)", src)));

    pfree(pDst);
    PG_RETURN_POINTER(enc_str_var);
}
