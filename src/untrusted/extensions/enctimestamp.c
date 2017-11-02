// enctimestamp.cpp : Defines the exported functions for the encrypted timestamp type.
// The library contains functions for the Postgresql extension 'encdb', including:
//
// encrypted timestamp type, format: BASE64(IV[12bytes]||AES-GCM(Integer)[8 bytes]||AUTHTAG[16 bytes]) 
//			(input size: 8 bytes; output size: 48 bytes; operators: >=,>,<=,<,=,!=; functions: ) 

#include "stdafx.h"
#include "datatype/timestamp.h"
#include "utils/datetime.h"
#include "utils/timestamp.h"

extern bool debugDecryption;

static TimeOffset time2t	(	const int 	hour,const int 	min,const int 	sec,const fsec_t 	fsec ) {		
	return (((hour * MINS_PER_HOUR) + min) * SECS_PER_MINUTE) + sec + fsec;
}

double timestamp_in_pg(char *str) {

	double result;
	//Timestamp   result;
	char        workbuf[MAXDATELEN + MAXDATEFIELDS];
	char       *field[MAXDATEFIELDS];
	int         ftype[MAXDATEFIELDS];
	int         dterr;
	int         nf;
	int         tz;
	int         dtype;
	fsec_t      fsec;
	struct pg_tm tt, *tm = &tt;

	//	#ifdef HAVE_INT64_TIMESTAMP
	//		int         dDate;
	//       int64       time;
	//   #else
		double      dDate,
		time;
	//    #endif

	char        buf[MAXDATELEN + 1];
	char src_byte[TIMESTAMP_LENGTH];
	int resp;
	char *pDst = (char *) palloc((ENC_TIMESTAMP_LENGTH_B64) * sizeof(char));

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


// The input function converts a string to an internal enctimestamp element.
// @input: string
// @return: a string describing enctimestamp element.  
PG_FUNCTION_INFO_V1(enctimestampin);
Datum
enctimestampin(PG_FUNCTION_ARGS)
{

	char *pSrc = PG_GETARG_CSTRING(0);
	char *pDst = (char*) palloc(ENC_TIMESTAMP_LENGTH_B64*sizeof(char));
	double dst;
	int resp;

	//ereport(LOG, (errmsg("enctimestamp, function IN, input (len %d): %s", strlen(pSrc), pSrc)));
	if (strlen(pSrc) != ENC_TIMESTAMP_LENGTH_B64 - 1) {
		dst = timestamp_in_pg(pSrc);
		resp = encryptTimestamp(dst, pDst);
		sgxErrorHandler(resp);
		ereport(INFO, (errmsg("auto encryption: ENC(%s) = %s", pSrc, pDst)));
	    PG_RETURN_CSTRING(pDst);
		//ereport(ERROR, (errmsg("Error: wrong length of the element")));

	}
	else
	{
		memcpy(pDst, pSrc, ENC_TIMESTAMP_LENGTH_B64);
		pDst[ENC_TIMESTAMP_LENGTH_B64 - 1] = '\0';
	}
	
	PG_RETURN_CSTRING(pDst);
}

// The output function converts an enctimestamp element to a string.
// @input: enctimestamp element
// @return: string 
PG_FUNCTION_INFO_V1(enctimestampout);
Datum
enctimestampout(PG_FUNCTION_ARGS)
{
	char *c1 = PG_GETARG_CSTRING(0);
	Timestamp timestamp;
	int resp;
    char       *result = (char*) palloc(ENC_TIMESTAMP_LENGTH_B64*sizeof(char));
    struct pg_tm tt,
                *tm = &tt;
     fsec_t      fsec;
     char        buf[MAXDATELEN + 1];

 	memcpy(result, c1, ENC_TIMESTAMP_LENGTH_B64);
 	if (debugDecryption == true) {
 		resp = decryptTimestamp(c1, &timestamp);
 		sgxErrorHandler(resp);
 		if (timestamp2tm(timestamp, NULL, tm, &fsec, NULL, NULL) == 0)
 			EncodeDateTime(tm, fsec, false, 0, NULL, 1, buf);
 		else {
 			ereport(ERROR,
                 (errcode(ERRCODE_DATETIME_VALUE_OUT_OF_RANGE),
                  errmsg("timestamp out of range")));
 		}

 		result = pstrdup(buf);
 		ereport(INFO, (errmsg("auto decryption: DEC('%s') = %s", c1, result)));
 	}

    PG_RETURN_CSTRING(result);
 }

// Gets a string as a timestamp element, encrypts it and return enctimestamp element as a string.
// Converts the input string to a int64 element, encrypts one and return base64 encrypted result.
// @input: string
// @return: a string describing enctimestamp element. 
PG_FUNCTION_INFO_V1(enctimestamp_enc);
Datum
enctimestamp_enc(PG_FUNCTION_ARGS)
{
	char       *str = PG_GETARG_CSTRING(0);
	#ifdef NOT_USED
		Oid	typelem = PG_GETARG_OID(1);
	#endif
	int32       typmod = PG_GETARG_INT32(2);
	int resp;

	double result;
	char *pDst = (char*) palloc(ENC_TIMESTAMP_LENGTH_B64*sizeof(char));

	result = timestamp_in_pg(str);
	resp = encryptTimestamp(result, pDst);
	sgxErrorHandler(resp);

//    ereport(INFO, (errmsg("resp: %d", resp)));


    PG_RETURN_CSTRING(pDst);
}

// Gets a string as a enctimestamp element, decrypts it and return timestamp element as a string.
// @input: enctimestamp element
// @return: string  
PG_FUNCTION_INFO_V1(enctimestamp_dec);
Datum
enctimestamp_dec(PG_FUNCTION_ARGS)
{
	char *c1 = PG_GETARG_CSTRING(0);
	Timestamp timestamp;
	//double timestamp;
	int resp;
    char       *result;
    struct pg_tm tt,
                *tm = &tt;
     fsec_t      fsec;
     char        buf[MAXDATELEN + 1];
	
	resp = decryptTimestamp(c1, &timestamp);
	sgxErrorHandler(resp);

    if (timestamp2tm(timestamp, NULL, tm, &fsec, NULL, NULL) == 0)
         EncodeDateTime(tm, fsec, false, 0, NULL, 1, buf);
     else {
		 ereport(ERROR,
                 (errcode(ERRCODE_DATETIME_VALUE_OUT_OF_RANGE),
                  errmsg("timestamp out of range")));
	 }

    result = pstrdup(buf);
//    ereport(INFO, (errmsg("function decrypt, output: %lld", timestamp)));
//	ereport(INFO, (errmsg("function decrypt, output: %s", buf)));


    PG_RETURN_CSTRING(result);
}

// The function checks if the first input is equal to the second one. 
// It requires a running SGX enclave and uses the function 'compareEncTimestamp' from the 'interface' library.
// It encrypts an input inside SGX, compare them as a timestamps (int64 elements) and return {true, false} as a result.
// @input: two encrypted timestamps elements
// @return: true, if the first decrypted element is equal to the second one. 
//		 false, otherwise 	   
PG_FUNCTION_INFO_V1(enctimestamp_eq);
Datum
enctimestamp_eq(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans;
	bool cmp;
	int resp = 0;

	resp = compareTimestamp(c1, c2, &ans);
	sgxErrorHandler(resp);

	if (ans == 0)
		cmp = true;
	else cmp = false;

//	ereport(INFO, (errmsg("enctimestamp, function =, output: %d", ans)));
	sgxErrorHandler(ans);

	PG_RETURN_BOOL(cmp);
      
}
	
// The function checks if the first input is not equal to the second one. 
// It requires a running SGX enclave and uses the function 'compareEncTimestamp' from the 'interface' library.
// It encrypts an input inside SGX, compare them as a timestamps (int64 elements) and return {true, false} as a result.
// @input: two encrypted timestamps elements
// @return: true, if the first decrypted element is not equal to the second one. 
//		 false, otherwise 	   
PG_FUNCTION_INFO_V1(enctimestamp_ne);
Datum
enctimestamp_ne(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans;
	bool cmp;
	int resp = 0;

	resp = compareTimestamp(c1, c2, &ans);
	sgxErrorHandler(resp);
	if (ans == 0)
		cmp = false;
	else cmp = true;

	//ereport(LOG, (errmsg("enctimestamp, function <, output: %d", ans)));
	sgxErrorHandler(ans);

	PG_RETURN_BOOL(cmp);
}

// The function checks if the first input is less than the second one. 
// It requires a running SGX enclave and uses the function 'compareEncTimestamp' from the 'interface' library.
// It encrypts an input inside SGX, compare them as a timestamps (int64 elements) and return {true, false} as a result.
// @input: two encrypted timestamps elements
// @return: true, if the first decrypted element is less the the second one. 
//		 false, otherwise 
PG_FUNCTION_INFO_V1(enctimestamp_lt);
Datum
enctimestamp_lt(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans;
	bool cmp;
	int resp = 0;

	resp = compareTimestamp(c1, c2, &ans);
	sgxErrorHandler(resp);
	if (ans == -1)
		cmp = true;
	else cmp = false;

	//ereport(LOG, (errmsg("enctimestamp, function <, output: %d", ans)));
	sgxErrorHandler(ans);

	PG_RETURN_BOOL(cmp);
}


// The function checks if the first input is less or equal than the second one. 
// It requires a running SGX enclave and uses the function 'compareEncTimestamp' from the 'interface' library.
// It encrypts an input inside SGX, compare them as a timestamps (int64 elements) and return {true, false} as a result.
// @input: two encrypted timestamps elements
// @return: true, if the first decrypted element is less or equal than the second one. 
//		 false, otherwise
PG_FUNCTION_INFO_V1(enctimestamp_le);
Datum
enctimestamp_le(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans;
	bool cmp;
	int resp = 0;

	resp = compareTimestamp(c1, c2, &ans);
	sgxErrorHandler(resp);
	if ((ans == -1)||(ans == 0))
		cmp = true;
	else cmp = false;

	//ereport(LOG, (errmsg("enctimestamp, function <=, output: %d", ans)));
	sgxErrorHandler(ans);

	PG_RETURN_BOOL(cmp);
}

// The function checks if the first input is greater than the second one. 
// It requires a running SGX enclave and uses the function 'compareEncTimestamp' from the 'interface' library.
// It encrypts an input inside SGX, compare them as a timestamps (int64 elements) and return {true, false} as a result.
// @input: two encrypted timestamps elements
// @return: true, if the first decrypted element is freater than the second one. 
//		 false, otherwise 	   
PG_FUNCTION_INFO_V1(enctimestamp_gt);
Datum
enctimestamp_gt(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans;
	bool cmp;
	int resp = 0;

	resp = compareTimestamp(c1, c2, &ans);
	sgxErrorHandler(resp);

	if (ans == 1)
		cmp = true;
	else cmp = false;

	//ereport(LOG, (errmsg("enctimestamp, function >, output: %d", ans)));
	sgxErrorHandler(ans);

	PG_RETURN_BOOL(cmp);
      
}

// The function checks if the first input is greater or equal than the second one. 
// It requires a running SGX enclave and uses the function 'compareEncTimestamp' from the 'interface' library.
// It encrypts an input inside SGX, compare them as a timestamps (int64 elements) and return {true, false} as a result.
// @input: two encrypted timestamps elements
// @return: true, if the first decrypted element is greater or equal than the second one. 
//		 false, otherwise 	   
PG_FUNCTION_INFO_V1(enctimestamp_ge);
Datum
enctimestamp_ge(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans;
	bool cmp;
	int resp = 0;

	resp = compareTimestamp(c1, c2, &ans);
	sgxErrorHandler(resp);
	if ((ans == 0)||(ans==1))
		cmp = true;
	else cmp = false;

	//ereport(LOG, (errmsg("enctimestamp, function >=, output: %d", ans)));
	sgxErrorHandler(ans);

	PG_RETURN_BOOL(cmp);
      
}

// The function compares two encrypted timestamps.
// It requires a running SGX enclave and uses the function 'compareEncTimestamp' from the 'interface' library.
// It encrypts an input inside SGX, compare them as a timestamps (int64 elements) and return {-1,0,1} as a result.
// @input: two encrypted timestamps
// @return: -1, if src1 < src2, 
//		  0, if src1 = src2, 	 
//		  1, if src1 > src2
PG_FUNCTION_INFO_V1(enctimestamp_cmp);
Datum
enctimestamp_cmp(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans;
	bool cmp;

	int resp = 0;

	resp = compareTimestamp(c1, c2, &ans);
//	ereport(INFO, (errmsg("enctimestamp, function CMP, input: %s, %s", c1, c2)));
//	ereport(INFO, (errmsg("enctimestamp, function CMP, output: %d", ans)));
	sgxErrorHandler(ans);


    PG_RETURN_INT32(ans);
      
}

