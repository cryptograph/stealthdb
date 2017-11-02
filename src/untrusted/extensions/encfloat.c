/*
 * encfloat.c : This library defines exported functions for the encrypted float(4 bytes) datatype.
 * The library contains functions for the Postgresql extension 'encdb', including:
 *
 * encrypted float type, format: BASE64(IV[12bytes]||AES-GCM(int)[4 bytes]||AUTHTAG[16 bytes])
 *			(input size: 4 bytes; output size: 44 bytes; operators: +,-,*,/,%,>=,>,<=,<,=,!=; functions: SUM, AVG)
 */
#include "stdafx.h"

#include <float.h>

#include "utils/int8.h"
#include "utils/numeric.h"

extern bool debugDecryption;

/*
 * The function converts encfloat element to a string. If flag debugDecryption is true it decrypts the string and return unencrypted result.
 * @input: encfloat element
 * @return: string
 */
PG_FUNCTION_INFO_V1(encfloatout);
Datum
encfloatout(PG_FUNCTION_ARGS)
{
	char *pSrc = PG_GETARG_CSTRING(0);
	char *str = (char *) palloc(ENC_FLOAT_LENGTH_B64 * sizeof(char));
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	float ans;

	memcpy(str, pSrc, ENC_FLOAT_LENGTH_B64);
	if (debugDecryption == true) {
		resp = decryptFloat4(pSrc, &ans);
		sgxErrorHandler(resp);
		sprintf(str, "%f", ans);
		ereport(INFO, (errmsg("auto decryption: DEC('%s') = %f", pSrc, ans)));
	}

	//pfree(str);

	PG_RETURN_CSTRING(str);
}

//TODO
// DEBUG FUNCTION
// WILL BE DELETED IN THE PRODUCT
PG_FUNCTION_INFO_V1(encfloat_enc);
Datum
encfloat_enc(PG_FUNCTION_ARGS)
{
	float src = PG_GETARG_FLOAT4(0);
	int ans;
	char *pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));
	//char *ans = encryptREncInt(c1);
	ans = encryptFloat4(src, pDst);
	sgxErrorHandler(ans);
	//ereport(LOG, (errmsg("function encrypt, output: %s", ans)));
    PG_RETURN_CSTRING(pDst);
}

//TODO
// DEBUG FUNCTION
// WILL BE DELETED IN THE PRODUCT
PG_FUNCTION_INFO_V1(encfloat_dec);
Datum
encfloat_dec(PG_FUNCTION_ARGS)
{
	float dst = 0;
	char *c1 = PG_GETARG_CSTRING(0);
	int ans = 0;
	ans = decryptFloat4(c1, &dst);
	sgxErrorHandler(ans);
	//ereport(LOG, (errmsg("function decrypt, output: %d", ans)));

	PG_RETURN_FLOAT4(dst);
}

/*
 * The function calculates the sum of elements from input array
 * It is called by sql aggregate command SUM, which is firstly appends needed encfloat elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'plusFloat4' from the 'interface' library.
 * @input: an array of encfloat values which should be summarize
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encfloat_addfinal);
Datum
encfloat_addfinal(PG_FUNCTION_ARGS)
{	
	ArrayType *v = PG_GETARG_ARRAYTYPE_P(0);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool        isnull;
	Datum value;
	char* pSrc1 = (char*) palloc((ENC_FLOAT_LENGTH_B64 + 1)*sizeof(char));
	char* pSrc2 = (char*) palloc((ENC_FLOAT_LENGTH_B64 + 1)*sizeof(char));
	char* pTemp = (char*) palloc((ENC_FLOAT_LENGTH_B64 + 1)*sizeof(char));
	ArrayMetaState * my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	ArrayIterator array_iterator = array_create_iterator(v, 0, my_extra);

	array_iterate(array_iterator, &value, &isnull);
	memcpy(pSrc1, DatumGetCString(value), ENC_FLOAT_LENGTH_B64);
	pSrc1[ENC_FLOAT_LENGTH_B64 - 1] = '\0';

	while (array_iterate(array_iterator, &value, &isnull))
	{
		memcpy(pTemp, DatumGetCString(value), ENC_FLOAT_LENGTH_B64);
		pTemp[ENC_FLOAT_LENGTH_B64 - 1] = '\0';
		resp = plusFloat4(pSrc1, pTemp, pSrc2);
		sgxErrorHandler(resp);

		memcpy(pSrc1, pSrc2, ENC_FLOAT_LENGTH_B64);
		pSrc1[ENC_FLOAT_LENGTH_B64 - 1] = '\0';
	}

	pfree(pTemp);
	pfree(pSrc2);

	PG_RETURN_CSTRING(pSrc1);
}

/*
 * The function computes the average of elements from array of encfloat elements.
 * It is called by sql aggregate command AVG, which is firstly appends needed encfloat elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'plusFloat4', 'divFloat4', 'encryptFloat4' from the 'interface' library.
 * @input: an array of encfloat elements
 * @return: an encrypted result (encrypted float4). output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encfloat_avgfinal);
Datum
encfloat_avgfinal(PG_FUNCTION_ARGS)
{	
	ArrayType *v = PG_GETARG_ARRAYTYPE_P(0);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool        isnull;
	Datum value;
	int         ndims1 = ARR_NDIM(v); //array dimension
    int        *dims1 = ARR_DIMS(v); 
    int nitems = ArrayGetNItems(ndims1, dims1); //number of items in array
    char* pSrc1 = (char*) palloc((ENC_FLOAT_LENGTH_B64 + 1)*sizeof(char));
    char* pSrc2 = (char*) palloc((ENC_FLOAT_LENGTH_B64 + 1)*sizeof(char));
    char* pTemp = (char*) palloc((ENC_FLOAT_LENGTH_B64 + 1)*sizeof(char));
	ArrayMetaState * my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	ArrayIterator array_iterator = array_create_iterator(v, 0, my_extra);

	array_iterate(array_iterator, &value, &isnull);
	memcpy(pSrc1, DatumGetCString(value), ENC_FLOAT_LENGTH_B64);
	pSrc1[ENC_FLOAT_LENGTH_B64 - 1] = '\0';

	while (array_iterate(array_iterator, &value, &isnull))
	{
		memcpy(pTemp, DatumGetCString(value), ENC_FLOAT_LENGTH_B64);
		pTemp[ENC_FLOAT_LENGTH_B64 - 1] = '\0';
		resp = plusFloat4(pSrc1, pTemp, pSrc2);
		sgxErrorHandler(resp);

		memcpy(pSrc1, pSrc2, ENC_FLOAT_LENGTH_B64);
		pSrc1[ENC_FLOAT_LENGTH_B64 - 1] = '\0';
	}

	resp = encryptFloat4(nitems, pTemp);
	sgxErrorHandler(resp);

	resp = divFloat4(pSrc1, pTemp, pSrc2);
	sgxErrorHandler(resp);

	pfree(pTemp);
	pfree(pSrc1);

	PG_RETURN_CSTRING(pSrc2);
}

/*
 * The function calculates the sum of two encfloat values. It is called by binary operator '+' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'plusFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: encrypted sum of input values
 * output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
*/

PG_FUNCTION_INFO_V1(encfloat_add);
Datum
encfloat_add(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));

	resp = plusFloat4(c1, c2, pDst);
	sgxErrorHandler(resp);

	pDst[ENC_FLOAT_LENGTH_B64-1] = '\0';
	PG_RETURN_CSTRING(pDst);	

}

/*
 * The function calculates the subtraction of two encfloat values. It is called by binary operator '-' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'minusFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encfloat_subs);
Datum
encfloat_subs(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));

	resp = minusFloat4(c1, c2, pDst);
	sgxErrorHandler(resp);
	pDst[ENC_FLOAT_LENGTH_B64 - 1] = '\0';

	PG_RETURN_CSTRING(pDst);
}

/*
 * The function calculates the product of two encfloat values. It is called by binary operator '*' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'multFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encfloat_mult);
Datum
encfloat_mult(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));

	resp = multFloat4(c1, c2, pDst);
	sgxErrorHandler(resp);
	pDst[ENC_FLOAT_LENGTH_B64 - 1] = '\0';

	PG_RETURN_CSTRING(pDst);	
}

/*
 * The function calculates the division of two encfloat values. It is called by binary operator '/' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'divFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */

PG_FUNCTION_INFO_V1(encfloat_div);
Datum
encfloat_div(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));

	resp = divFloat4(c1, c2, pDst);
	sgxErrorHandler(resp);
	pDst[ENC_FLOAT_LENGTH_B64 - 1] = '\0';

	PG_RETURN_CSTRING(pDst);	
}

/*
 * The function calculates the first input encfloat value to the power of the second input encfloat value.
 * It is called by binary operator '^' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'expFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encfloat_exp);
Datum
encfloat_exp(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));

	resp = expFloat4(c1, c2, pDst);
	sgxErrorHandler(resp);
	pDst[ENC_FLOAT_LENGTH_B64 - 1] = '\0';

	PG_RETURN_CSTRING(pDst);	
}

/*
 * The function checks if the first input encfloat is equal to the second one.
 * It is called by binary operator '=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: true, if the first decrypted float is equal to the second one.
 *		 false, otherwise
*/
PG_FUNCTION_INFO_V1(encfloat_eq);
Datum
encfloat_eq(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans=0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp = false;

	resp = compareFloat4(c1, c2, &ans);
	sgxErrorHandler(resp);
	
	if (ans == 0)
		cmp = true;
	else cmp = false;

	PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input encfloat is not equal to the second one.
 * It is called by binary operator '!=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: true, if the first decrypted float is not equal to the second one.
 *		 false, otherwise
 */
PG_FUNCTION_INFO_V1(encfloat_ne);
Datum
encfloat_ne(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans=0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp = false;

	resp = compareFloat4(c1, c2, &ans);
	sgxErrorHandler(resp);

	if (ans == 0)
		cmp = false;
	else cmp = true;

	PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input encfloat is less than the second one.
 * It is called by binary operator '<' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: true, if the first decrypted float is less the the second one.
 *		 false, otherwise
 */
PG_FUNCTION_INFO_V1(encfloat_lt);
Datum
encfloat_lt(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans=0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp;

	resp = compareFloat4(c1, c2, &ans);
	sgxErrorHandler(resp);

	if (ans == -1)
		cmp = true;
	else cmp = false;

	PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input encfloat is less or equal than the second one.
 * It is called by binary operator '<=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: true, if the first encfloat is less or equal than the second one.
 *		 false, otherwise
 */
PG_FUNCTION_INFO_V1(encfloat_le);
Datum
encfloat_le(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans=0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp;

	resp = compareFloat4(c1, c2, &ans);
	sgxErrorHandler(resp);

	if ((ans == -1)||(ans == 0))
		cmp = true;
	else cmp = false;

	PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input encfloat is greater than the second one.
 * It is called by binary operator '>' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: true, if the first decrypted float is greater than the second one.
 *		    false, otherwise
 */
PG_FUNCTION_INFO_V1(encfloat_gt);
Datum
encfloat_gt(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans=0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp;

	resp = compareFloat4(c1, c2, &ans);
	sgxErrorHandler(resp);

	if (ans == 1)
		cmp = true;
	else cmp = false;

	PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input encfloat is greater or equal than the second one.
 * It is called by binary operator '>=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: true, if the first decrypted float is greater or equal than the second one.
 *		    false, otherwise
 */
PG_FUNCTION_INFO_V1(encfloat_ge);
Datum
encfloat_ge(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans=0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp;

	resp = compareFloat4(c1, c2, &ans);
	sgxErrorHandler(resp);

	if ((ans == 0)||(ans==1))
		cmp = true;
	else cmp = false;

	PG_RETURN_BOOL(cmp);
}

/*
 * The function compares two encfloat values. It is called mostly during index building.
 * It requires a running SGX enclave and uses the function 'compareFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: -1, 0 ,1
 */
PG_FUNCTION_INFO_V1(encfloat_cmp);
Datum
encfloat_cmp(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	int ans = 0;
	
	resp = compareFloat4(c1, c2, &ans);
	sgxErrorHandler(resp);

    PG_RETURN_INT32(ans);
}

/*
 * The function calculates the first input encfloat value by module the second input encfloat value.
 * It is called by binary operator '%' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'modFloat4' from the 'interface' library.
 * @input: two encfloat values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encfloat_mod);
Datum
encfloat_mod(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char * pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));

	resp = modFloat4(c1, c2, pDst);
	sgxErrorHandler(resp);
	pDst[ENC_FLOAT_LENGTH_B64-1] = '\0';

	PG_RETURN_CSTRING(pDst);	
}

/*
 * The function converts a float to encfloat value. This function is called by sql function CAST.
 * It requires a running SGX enclave and uses the function 'encryptFloat4' from the 'interface' library.
 * @input: float4
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(float4_to_encfloat);
Datum
float4_to_encfloat(PG_FUNCTION_ARGS)
{
	float src = PG_GETARG_FLOAT4(0);
	int ans;
	char *pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));

	ans = encryptFloat4(src, pDst);
	sgxErrorHandler(ans);
	//ereport(INFO, (errmsg("auto encryption: ENC(%f) = %s", src, pDst)));

    PG_RETURN_CSTRING((const char*) pDst);
}



float4 float4_pg_in(char *num) {

	char	   *orig_num;
	double		val;
	char	   *endptr;

	/*
	 * endptr points to the first character _after_ the sequence we recognized
	 * as a valid floating point number. orig_num points to the original input
	 * string.
	 */
	orig_num = num;

	/* skip leading whitespace */
	while (*num != '\0' && isspace((unsigned char) *num))
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
		int			save_errno = errno;

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
#endif							/* HAVE_BUGGY_SOLARIS_STRTOD */

	/* skip trailing whitespace */
	while (*endptr != '\0' && isspace((unsigned char) *endptr))
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

	return ((float4) val);
}

/*
 * The function converts a numeric datatype(postgres variable datatype can be any of int2, int4, int8, float4, float8) to encfloat value.
 * This function is called by sql function CAST. It uses function float4_pg_in to convert it to float4 and return an error if it can't
 * It requires a running SGX enclave and uses the function 'encryptFloat4' from the 'interface' library.
 * @input: float4
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(numeric_to_encfloat);
Datum
numeric_to_encfloat(PG_FUNCTION_ARGS)
{
	Numeric num = PG_GETARG_NUMERIC(0);
	char *pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));
	int ans;
	float4 src;
	char *tmp = DatumGetCString(DirectFunctionCall1(numeric_out, NumericGetDatum(num)));

	src = float4_pg_in(tmp);

	ans = encryptFloat4(src, pDst);
	sgxErrorHandler(ans);

	pfree(tmp);

    PG_RETURN_CSTRING((const char*) pDst);

}

/*
 * The function converts a double precision datatype to encfloat value.
 * This function is called by sql function CAST. It uses function float4_pg_in to convert it to float4 and return an error if it can't
 * It requires a running SGX enclave and uses the function 'encryptFloat4' from the 'interface' library.
 * @input: float8
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(double_to_encfloat);
Datum
double_to_encfloat(PG_FUNCTION_ARGS)
{
	float8 num = PG_GETARG_FLOAT8(0);
	char *pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));
	int ans;
	float4 src;
	char *tmp = DatumGetCString(DirectFunctionCall1(float8out, Float8GetDatum(num)));

	src = float4_pg_in(tmp);
	//ereport(LOG, (errmsg("double_to_encfloat: %s, %f ", tmp, num)));
	ans = encryptFloat4(src, pDst);
	sgxErrorHandler(ans);

	pfree(tmp);

    PG_RETURN_CSTRING((const char*) pDst);

}

/*
 * The function converts a bigint (int8) datatype to encfloat value.
 * This function is called by sql function CAST. It uses function float4_pg_in to convert it to float4 and return an error if it can't
 * It requires a running SGX enclave and uses the function 'encryptFloat4' from the 'interface' library.
 * @input: int8
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(int8_to_encfloat);
Datum
int8_to_encfloat(PG_FUNCTION_ARGS)
{
	int8 num = PG_GETARG_INT64(0);
	char *pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));
	int ans;
	float4 src;
	char *tmp = DatumGetCString(DirectFunctionCall1(int8out, Int8GetDatum(num)));

	src = float4_pg_in(tmp);
	ans = encryptFloat4(src, pDst);
	sgxErrorHandler(ans);

	pfree(tmp);

    PG_RETURN_CSTRING((const char*) pDst);

}

/*
 * The function converts a int (int4) datatype to encfloat value.
 * This function is called by sql function CAST. It uses function float4_pg_in to convert it to float4 and return an error if it can't
 * It requires a running SGX enclave and uses the function 'encryptFloat4' from the 'interface' library.
 * @input: int4
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(int4_to_encfloat);
Datum
int4_to_encfloat(PG_FUNCTION_ARGS)
{
	int num = PG_GETARG_INT32(0);
	char *pDst = (char *) palloc((ENC_FLOAT_LENGTH_B64) * sizeof(char));
	int ans;
	float4 src;
	char *tmp = DatumGetCString(DirectFunctionCall1(int4out, Int32GetDatum(num)));

	src = float4_pg_in(tmp);
	ans = encryptFloat4(src, pDst);
	sgxErrorHandler(ans);
//	ereport(INFO, (errmsg("auto encryption: ENC(%f) = %s", src, pDst)));

	pfree(tmp);

    PG_RETURN_CSTRING((const char*) pDst);

}

/*
 * The function converts string to encfloat. It is called by dbms every time it parses a query and finds an encfloat element.
 * It uses function float4_pg_in to convert it to float4 and returns an error if it can't
 * @input: string as a postgres arg
 * @return: encfloat element as a string
 */
PG_FUNCTION_INFO_V1(encfloatin);
Datum
encfloatin(PG_FUNCTION_ARGS)
{
    char *pSrc = PG_GETARG_CSTRING(0);
	char *pDst = (char*) palloc((ENC_FLOAT_LENGTH_B64)*sizeof(char));
	float dst;
	int resp;

	/*
	 * if the length of string isnot expected
	 * check if it is an float4 and encrypt it
	 * float4_pg_in is almost postgres function that raises an error in case it exists
	 */
	if (strlen(pSrc) != ENC_FLOAT_LENGTH_B64 - 1) {
		dst = float4_pg_in(pSrc);
		resp = encryptFloat4(dst, pDst);
		sgxErrorHandler(resp);
		//ereport(INFO, (errmsg("auto encryption: ENC(%f) = %s", dst, pDst)));
		PG_RETURN_CSTRING((const char*) pDst);
	}
	else
	{
		memcpy(pDst, pSrc, ENC_FLOAT_LENGTH_B64);
		pDst[ENC_FLOAT_LENGTH_B64 - 1] = '\0';
	}

	PG_RETURN_CSTRING(pDst);

}
