/*
 * enc_timestamp.cpp : The library defines exported functions for encrypted timestamp type.
 * The library contains functions for the Postgresql extension 'encdb', including:
 *
 * encrypted timestamp type, format: BASE64(IV[12bytes]||AES-GCM(TIMESTAMP)[8 bytes]||AUTHTAG[16 bytes])
 *          (input size: 8 bytes; output size: 48 bytes; operators: >=,>,<=,<,=,!=; functions: )
 */

#include "untrusted/extensions/stdafx.h"
#include "datatype/timestamp.h"
#include "utils/datetime.h"
#include "utils/timestamp.h"

extern bool debugMode;

static TimeOffset time2t(const int hour, const int min, const int sec, const fsec_t fsec)
{
    return (((hour * MINS_PER_HOUR) + min) * SECS_PER_MINUTE) + sec + fsec;
}

/* Convert a string to internal timestamp type. This function based on native posygres function 'timestamp_in'
 * @input: string as a postgres argument
`* @return: timestamp
*/
Timestamp pg_timestamp_in(char* str)
{

    Timestamp result;
    char workbuf[MAXDATELEN + MAXDATEFIELDS];
    char* field[MAXDATEFIELDS];
    int ftype[MAXDATEFIELDS];
    int dterr;
    int nf;
    int tz;
    int dtype;
    fsec_t fsec;
    struct pg_tm tt, *tm = &tt;
    char buf[MAXDATELEN + 1];
    char src_byte[TIMESTAMP_LENGTH];
    int resp;
    char* pDst = (char*)palloc((ENC_TIMESTAMP_LENGTH_B64) * sizeof(char));

    dterr = ParseDateTime(str, workbuf, sizeof(workbuf), field, ftype, MAXDATEFIELDS, &nf);

    if (dterr == 0)
        dterr = DecodeDateTime(field, ftype, nf, &dtype, tm, &fsec, &tz);
    if (dterr != 0)
        DateTimeParseError(dterr, str, "timestamp");

    switch (dtype)
    {
    case DTK_DATE:
        if (tm2timestamp(tm, fsec, NULL, &result) != 0)
            ereport(ERROR,
                    (errcode(ERRCODE_DATETIME_VALUE_OUT_OF_RANGE),
                     errmsg("timestamp out of range: \"%s\"", str)));
        break;

    case DTK_EPOCH:
        result = SetEpochTimestamp();
        break;

    case DTK_LATE:
        TIMESTAMP_NOEND(result);
        break;

    case DTK_EARLY:
        TIMESTAMP_NOBEGIN(result);
        break;

    case DTK_INVALID:
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("date/time value \"%s\" is no longer supported", str)));

        TIMESTAMP_NOEND(result);
        break;

    default:
        elog(ERROR, "unexpected dtype %d while parsing timestamp \"%s\"",
             dtype, str);
        TIMESTAMP_NOEND(result);
    }

    return result;
}

/*
 * The function converts string to enc_timestamp. It is called by dbms every time it parses a query and finds an enc_timestamp element.
 * @input: string as a postgres arg
 * @return: enc_timestamp element as a string
 */
PG_FUNCTION_INFO_V1(pg_enc_timestamp_in);
Datum
    pg_enc_timestamp_in(PG_FUNCTION_ARGS)
{
    char* pSrc = PG_GETARG_CSTRING(0);
    char* pDst = (char*)palloc(ENC_TIMESTAMP_LENGTH_B64 * sizeof(char));
    TIMESTAMP dst;
    int resp;
    char* src = (char*)palloc(TIMESTAMP_LENGTH * sizeof(char));

    if (debugMode == true)
    {
        if (strlen(pSrc) != ENC_TIMESTAMP_LENGTH_B64 - 1)
        {
            dst = pg_timestamp_in(pSrc);
            memcpy(src, &dst, TIMESTAMP_LENGTH * sizeof(char));
            resp = enc_timestamp_encrypt(src, pDst);
            sgxErrorHandler(resp);
            //ereport(INFO, (errmsg("auto encryption: ENC(%s) = %s", pSrc, pDst)));
            PG_RETURN_CSTRING(pDst);
        }
        else
        {
            memcpy(pDst, pSrc, ENC_TIMESTAMP_LENGTH_B64);
            pDst[ENC_TIMESTAMP_LENGTH_B64 - 1] = '\0';
        }
    }
    else
    {
        if (strlen(pSrc) != ENC_TIMESTAMP_LENGTH_B64 - 1)
        {
            ereport(ERROR, (errmsg("Incorrect length of enc_timestamp element, try 'select enable_debug_mode(1)' to allow auto encryption/decryption or 'select pg_enc_timestamp_encrypt()'")));
        }
        else
        {
            memcpy(pDst, pSrc, ENC_TIMESTAMP_LENGTH_B64);
            pDst[ENC_TIMESTAMP_LENGTH_B64 - 1] = '\0';
        }
    }

    PG_RETURN_CSTRING(pDst);
}
/*
 * The function converts enc_timestamp element to a string. If flag debugDecryption is true it decrypts the string and return unencrypted result.
 * @input: enc_timestamp element
 * @return: string
 */
PG_FUNCTION_INFO_V1(pg_enc_timestamp_out);
Datum
    pg_enc_timestamp_out(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    TIMESTAMP timestamp;
    int resp;
    char* result = (char*)palloc(ENC_TIMESTAMP_LENGTH_B64 * sizeof(char));
    struct pg_tm tt, *tm = &tt;
    fsec_t fsec;
    char buf[MAXDATELEN + 1];
    char* dst = (char*)palloc(TIMESTAMP_LENGTH * sizeof(char));

    memcpy(result, c1, ENC_TIMESTAMP_LENGTH_B64);
    if (debugMode == true)
    {
        resp = enc_timestamp_decrypt(c1, dst);
        sgxErrorHandler(resp);
        memcpy(&timestamp, dst, TIMESTAMP_LENGTH * sizeof(char));

        if (timestamp2tm(timestamp, NULL, tm, &fsec, NULL, NULL) == 0)
            EncodeDateTime(tm, fsec, false, 0, NULL, 1, buf);
        else
        {
            ereport(ERROR,
                    (errcode(ERRCODE_DATETIME_VALUE_OUT_OF_RANGE),
                     errmsg("timestamp out of range")));
        }
        result = pstrdup(buf);
        //ereport(INFO, (errmsg("auto decryption: DEC('%s') = %s", c1, result)));
    }

    PG_RETURN_CSTRING(result);
}

/*
 *  Gets a string as a timestamp element, encrypts it and return enc_timestamp element as a string.
 *   Converts the input string to a int64 element, encrypts one and return base64 encrypted result.
 *    @input: string
 *    @return: a string describing enc_timestamp element.
 */
PG_FUNCTION_INFO_V1(pg_enc_timestamp_encrypt);
Datum
    pg_enc_timestamp_encrypt(PG_FUNCTION_ARGS)
{
    char* arg = PG_GETARG_CSTRING(0);
#ifdef NOT_USED
    Oid typelem = PG_GETARG_OID(1);
#endif
    int32 typmod = PG_GETARG_INT32(2);
    int resp;

    Timestamp result;
    char* dst = (char*)palloc(ENC_TIMESTAMP_LENGTH_B64 * sizeof(char));
    char* src = (char*)palloc(TIMESTAMP_LENGTH);

    result = pg_timestamp_in(arg);
    memcpy(src, &result, sizeof(TIMESTAMP_LENGTH));
    resp = enc_timestamp_encrypt(src, dst);
    sgxErrorHandler(resp);

    pfree(src);
    PG_RETURN_CSTRING(dst);
}

/*
 *  Gets a string as a enc_timestamp element, decrypts it and return timestamp element as a string.
 *  @input: enc_timestamp element
 *   @return: string
 */
PG_FUNCTION_INFO_V1(pg_enc_timestamp_decrypt);
Datum
    pg_enc_timestamp_decrypt(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    Timestamp timestamp;
    int resp;
    char* result;
    struct pg_tm tt,
        *tm = &tt;
    fsec_t fsec;
    char buf[MAXDATELEN + 1];
    char* dst = (char*)palloc(TIMESTAMP_LENGTH * sizeof(char));

    resp = enc_timestamp_decrypt(c1, dst);
    sgxErrorHandler(resp);
    memcpy(&timestamp, dst, TIMESTAMP_LENGTH);

    if (timestamp2tm(timestamp, NULL, tm, &fsec, NULL, NULL) == 0)
        EncodeDateTime(tm, fsec, false, 0, NULL, 1, buf);
    else
    {
        ereport(ERROR,
                (errcode(ERRCODE_DATETIME_VALUE_OUT_OF_RANGE),
                 errmsg("timestamp out of range")));
    }

    result = pstrdup(buf);
    pfree(dst);
    PG_RETURN_CSTRING(result);
}

/*
 * The function checks if the first input enc_timestamp is equal to the second one.
 * It is called by binary operator '=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_timestamp_cmp' from the 'interface' library.
 * @input: two enc_timestamp values
 * @return: true, if the first decrypted integer is equal to the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_timestamp_eq);
Datum
    pg_enc_timestamp_eq(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    int ans = 0;
    int resp = 0;

    resp = enc_timestamp_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);
    memcpy(&ans, pDst, INT32_LENGTH);

    pfree(pDst);
    PG_RETURN_BOOL((ans == 0) ? true : false);
}

/*
 * The function checks if the first input enc_timestamp is not equal to the second one.
 * It is called by binary operator '=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_timestamp_cmp' from the 'interface' library.
 * @input: two enc_timestamp values
 * @return: true, if the first decrypted integer is equal to the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_timestamp_ne);
Datum
    pg_enc_timestamp_ne(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    int ans = 0;
    bool cmp;
    int resp = 0;

    resp = enc_timestamp_cmp(c1, c2, pDst);
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
 * The function checks if the first input enc_timestamp is less to the second one.
 * It is called by binary operator '=' defined in sql extension.
 * It requires a running SGX enclave and use
    //ereport(LOG, (errmsg("enc_timestamp, function IN, input (len %d): %s", strlen(pSrc), pSrc)));s the function 'enc_timestamp_cmp' from the 'interface' library.
 * @input: two enc_timestamp values
 * @return: true, if the first decrypted integer is equal to the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_timestamp_lt);
Datum
    pg_enc_timestamp_lt(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    int ans = 0;
    bool cmp;
    int resp = 0;

    resp = enc_timestamp_cmp(c1, c2, pDst);
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
 * The function checks if the first input enc_timestamp is less or equal to the second one.
 * It is called by binary operator '=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_timestamp_cmp' from the 'interface' library.
 * @input: two enc_timestamp values
 * @return: true, if the first decrypted integer is equal to the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_timestamp_le);
Datum
    pg_enc_timestamp_le(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    int ans = 0;
    bool cmp;
    int resp = 0;

    resp = enc_timestamp_cmp(c1, c2, pDst);
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
 * The function checks if the first input enc_timestamp is greater to the second one.
 * It is called by binary operator '=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_timestamp_cmp' from the 'interface' library.
 * @input: two enc_timestamp values
 * @return: true, if the first decrypted integer is equal to the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_timestamp_gt);
Datum
    pg_enc_timestamp_gt(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    int ans = 0;
    bool cmp;
    int resp = 0;

    resp = enc_timestamp_cmp(c1, c2, pDst);
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
 * The function checks if the first input enc_timestamp is greater or equal to the second one.
 * It is called by binary operator '=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'enc_timestamp_cmp' from the 'interface' library.
 * @input: two enc_timestamp values
 * @return: true, if the first decrypted integer is equal to the second one.
 *       false, otherwise
 */
PG_FUNCTION_INFO_V1(pg_enc_timestamp_ge);
Datum
    pg_enc_timestamp_ge(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    int ans = 0;
    bool cmp;
    int resp = 0;

    resp = enc_timestamp_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);
    memcpy(&ans, pDst, INT32_LENGTH);

    if ((ans == 0) || (ans == 1))
        cmp = true;
    else
        cmp = false;

    pfree(pDst);
    PG_RETURN_BOOL(cmp);
}

PG_FUNCTION_INFO_V1(date_part);
Datum
    date_part(PG_FUNCTION_ARGS)
{
    char* get = text_to_cstring(PG_GETARG_TEXT_P(0));
    if (strcmp(get, "year") != 0)
    {
        ereport(ERROR, (errmsg("Only date_part('year', enc_timestamp) is currently implemented.")));
    }
    char* timestamp = PG_GETARG_CSTRING(1);
    char* result = palloc(ENC_INT32_LENGTH_B64 * sizeof(*result));

    int resp = enc_timestamp_extract_year(timestamp, result);
    sgxErrorHandler(resp);

    result[ENC_INT32_LENGTH_B64 - 1] = '\0';
    PG_RETURN_CSTRING(result);
}

/*
 * The function compares two enc_timestamp values. It is called mostly during index building.
 * It encrypts inputs inside SGX, compare them as a timestamp (int64 elements) and return {-1,0,1} as a result.
 * @input: two enc_timestamp values
 * @return: -1, 0 ,1
 */
PG_FUNCTION_INFO_V1(pg_enc_timestamp_cmp);
Datum
    pg_enc_timestamp_cmp(PG_FUNCTION_ARGS)
{
    char* c1 = PG_GETARG_CSTRING(0);
    char* c2 = PG_GETARG_CSTRING(1);
    char* pDst = (char*)palloc((INT32_LENGTH) * sizeof(char));
    int ans = 0;
    bool cmp;
    int resp = 0;

    resp = enc_timestamp_cmp(c1, c2, pDst);
    sgxErrorHandler(resp);
    memcpy(&ans, pDst, INT32_LENGTH);

    pfree(pDst);
    PG_RETURN_INT32(ans);
}
