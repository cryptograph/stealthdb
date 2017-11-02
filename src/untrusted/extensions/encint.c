/*
 * encint.c : This library defines exported functions for the encrypted integer(4 bytes) datatype.
 * The library contains functions for the Postgresql extension 'encdb', including:
 *
 * encrypted integer type, format: BASE64(IV[12bytes]||AES-GCM(int)[4 bytes]||AUTHTAG[16 bytes])
 *			(input size: 4 bytes; output size: 44 bytes; operators: +,-,*,/,%,>=,>,<=,<,=,!=; functions: SUM, AVG, MIN, MAX)
 */

#include "stdafx.h"
extern bool debugDecryption;

/*
 * The function converts string to encint. It is called by dbms every time it parses a query and finds an encint element.
 * @input: string as a postgres arg
 * @return: encint element as a string
 */
PG_FUNCTION_INFO_V1(encint_in);
Datum
encint_in(PG_FUNCTION_ARGS)
{
	char *pSrc = PG_GETARG_CSTRING(0);
	int32 dst_int = 0;
	int ans = ENCLAVE_IS_NOT_RUNNIG;
	char *pDst = (char*) palloc(ENC_INT_LENGTH_B64*sizeof(char));

	/*
	 * if the length of string isnot equal to ENC_INT_LENGTH_B64
	 * check if it is an integer and encrypt it
	 * pg_atoi is a postgres function that raises an error in case it exists
	 */
	if (strlen(pSrc) != ENC_INT_LENGTH_B64 - 1) {
		dst_int = pg_atoi(pSrc, INT_LENGTH, '\0');
		ans = encryptInt64(dst_int, pDst);
		sgxErrorHandler(ans);
		//ereport(INFO, (errmsg("auto encryption: ENC(%d) = %s", dst_int, pDst)));
		PG_RETURN_CSTRING((const char*) pDst);
	}
	else
	{
		memcpy(pDst, pSrc, ENC_INT_LENGTH_B64);
		pDst[ENC_INT_LENGTH_B64-1] = '\0';
	}
	
	PG_RETURN_CSTRING(pDst);
}

/*
 * The function converts encint element to a string. If flag debugDecryption is true it decrypts the string and return unencrypted result.
 * @input: encint element
 * @return: string
 */
PG_FUNCTION_INFO_V1(encint_out);
Datum
encint_out(PG_FUNCTION_ARGS)
{
	char *pSrc = PG_GETARG_CSTRING(0);
	char *pDst = (char *) palloc((INT_LENGTH) * sizeof(char));
	char *str = (char *) palloc(ENC_INT_LENGTH_B64 * sizeof(char));
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	int ans;

	memcpy(str, pSrc, ENC_INT_LENGTH_B64);
	if (debugDecryption == true) {
		resp = decryptInt64(pSrc, pDst);
		memcpy(&ans, pDst, INT_LENGTH);
		sgxErrorHandler(resp);
		sprintf(str, "%d", ans);
		ereport(INFO, (errmsg("auto decryption: DEC('%s') = %d", pSrc, ans)));
	}
	pfree(pDst);
	//pfree(str);

	PG_RETURN_CSTRING(str);
}

/*
 * The function calculates the sum of two encint values. It is called by binary operator '+' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'plusInt64' from the 'interface' library.
 * @input: two encint values
 * @return: encrypted sum of input values
 * output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
*/
PG_FUNCTION_INFO_V1(encintplus);
Datum
encintplus(PG_FUNCTION_ARGS)
{
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *pSrc1 = PG_GETARG_CSTRING(0);
	char *pSrc2 = PG_GETARG_CSTRING(1);
	char* pDst = (char *) palloc((ENC_INT_LENGTH_B64) * sizeof(char));

	resp = plusInt64(pSrc1, pSrc2, pDst);
	sgxErrorHandler(resp);

	pDst[ENC_INT_LENGTH_B64-1] = '\0';
	PG_RETURN_CSTRING(pDst);
}

/*
 * The function calculates the subtraction of two encint values. It is called by binary operator '-' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'minusInt64' from the 'interface' library.
 * @input: two encint values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encintminus);
Datum
encintminus(PG_FUNCTION_ARGS)
{
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	char *pDst = (char *) palloc((ENC_INT_LENGTH_B64) * sizeof(char));

	resp = minusInt64(c1, c2, pDst);
	sgxErrorHandler(resp);

	pDst[ENC_INT_LENGTH_B64-1] = '\0';
	PG_RETURN_CSTRING(pDst);

}

/*
 * The function calculates the product of two encint values. It is called by binary operator '*' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'multInt64' from the 'interface' library.
 * @input: two encint values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encintmult);
Datum
encintmult(PG_FUNCTION_ARGS)
{
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	char *pDst = (char *) palloc((ENC_INT_LENGTH_B64) * sizeof(char));

	resp = multInt64(c1, c2, pDst);
	sgxErrorHandler(resp);

	pDst[ENC_INT_LENGTH_B64-1] = '\0';
	PG_RETURN_CSTRING(pDst);
}

/*
 * The function calculates the division of two encint values. It is called by binary operator '/' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'divInt64' from the 'interface' library.
 * @input: two encint values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encintdiv);
Datum
encintdiv(PG_FUNCTION_ARGS)
{
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	char *pDst = (char *) palloc((ENC_INT_LENGTH_B64) * sizeof(char));

	resp = divInt64(c1, c2, pDst);
	sgxErrorHandler(resp);

	pDst[ENC_INT_LENGTH_B64-1] = '\0';
	PG_RETURN_CSTRING(pDst);

}

/*
 * The function calculates the first input encint value to the power of the second input encint value.
 * It is called by binary operator '^' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'expInt64' from the 'interface' library.
 * @input: two encint values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encintexp);
Datum
encintexp(PG_FUNCTION_ARGS)
{
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	char *pDst = (char *) palloc((ENC_INT_LENGTH_B64) * sizeof(char));

	resp = expInt64(c1, c2, pDst);
	sgxErrorHandler(resp);

	pDst[ENC_INT_LENGTH_B64-1] = '\0';
	PG_RETURN_CSTRING(pDst);

}

/*
 * The function calculates the first input encint value by module the second input encint value.
 * It is called by binary operator '%' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'modInt64' from the 'interface' library.
 * @input: two encint values
 * @return: an encrypted result of input values . output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encintmod);
Datum
encintmod(PG_FUNCTION_ARGS)
{
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	char *pDst = (char *) palloc((ENC_INT_LENGTH_B64) * sizeof(char));

	resp = modInt64(c1, c2, pDst);
	sgxErrorHandler(resp);

	pDst[ENC_INT_LENGTH_B64-1] = '\0';
	PG_RETURN_CSTRING(pDst);
}

/*
 * The function compares two encint values. It is called mostly during index building.
 * It requires a running SGX enclave and uses the function 'compareInt64' from the 'interface' library.
 * @input: two encint values
 * @return: -1, 0 ,1
 */
PG_FUNCTION_INFO_V1(encintcompare);
Datum
encintcompare(PG_FUNCTION_ARGS)
{
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	char *pDst = (char *) palloc((INT_LENGTH) * sizeof(char));
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	int ans = 0;

	resp = compareInt64(c1, c2, pDst);
	sgxErrorHandler(resp);

	memcpy(&ans, pDst, INT_LENGTH);

	pfree(pDst);
	PG_RETURN_INT32(ans);
}

/*
 * The function checks if the first input encint is equal to the second one.
 * It is called by binary operator '=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareInt64' from the 'interface' library.
 * @input: two encint values
 * @return: true, if the first decrypted integer is equal to the second one.
 *		 false, otherwise
*/
PG_FUNCTION_INFO_V1(encint_eq);
Datum
encint_eq(PG_FUNCTION_ARGS)
{	
	char *pDst = (char *) palloc((INT_LENGTH) * sizeof(char));
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans=0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp = false;

	resp = compareInt64(c1, c2, pDst);
	sgxErrorHandler(resp);

	memcpy(&ans, pDst, INT_LENGTH);
	if (ans == 0)
		cmp = true;
	else cmp = false;

	pfree(pDst);
	PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input encint is not equal to the second one.
 * It is called by binary operator '!=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareInt64' from the 'interface' library.
 * @input: two encint values
 * @return: true, if the first decrypted integer is not equal to the second one.
 *		 false, otherwise
 */
PG_FUNCTION_INFO_V1(encint_ne);
Datum
encint_ne(PG_FUNCTION_ARGS)
{	
	char *pDst = (char *) palloc((INT_LENGTH) * sizeof(char));
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans=0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp = false;

	resp = compareInt64(c1, c2, pDst);
	sgxErrorHandler(resp);
	memcpy(&ans, pDst, INT_LENGTH);

	if (ans == 0)
		cmp = false;
	else cmp = true;

	pfree(pDst);
	PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input encint is less than the second one.
 * It is called by binary operator '<' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareInt64' from the 'interface' library.
 * @input: two encint values
 * @return: true, if the first decrypted integer is less the the second one.
 *		 false, otherwise
 */
PG_FUNCTION_INFO_V1(encint_lt);
Datum
encint_lt(PG_FUNCTION_ARGS)
{	
	char *pDst = (char *) palloc((INT_LENGTH) * sizeof(char));
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans=0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp = false;

	resp = compareInt64(c1, c2, pDst);
	sgxErrorHandler(resp);
	memcpy(&ans, pDst, INT_LENGTH);

	if (ans == -1)
		cmp = true;
	else cmp = false;

	pfree(pDst);
	PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input encint is less or equal than the second one.
 * It is called by binary operator '<=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareInt64' from the 'interface' library.
 * @input: two encint values
 * @return: true, if the first decrypted integer is less or equal than the second one.
 *		 false, otherwise
 */
PG_FUNCTION_INFO_V1(encint_le);
Datum
encint_le(PG_FUNCTION_ARGS)
{	
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	char *pDst = (char *) palloc((INT_LENGTH) * sizeof(char));
	int ans=0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp;

	resp = compareInt64(c1, c2, pDst);
	sgxErrorHandler(resp);
	memcpy(&ans, pDst, INT_LENGTH);

	if ((ans == -1)||(ans == 0))
		cmp = true;
	else cmp = false;

	pfree(pDst);
	PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input encint is greater than the second one.
 * It is called by binary operator '>' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareInt64' from the 'interface' library.
 * @input: two encint values
 * @return: true, if the first decrypted integer is greater than the second one.
 *		    false, otherwise
 */
PG_FUNCTION_INFO_V1(encint_gt);
Datum
encint_gt(PG_FUNCTION_ARGS)
{	
	char *pDst = (char *) palloc((INT_LENGTH) * sizeof(char));
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans=0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp;
	
	resp = compareInt64(c1, c2, pDst);
	sgxErrorHandler(resp);
	memcpy(&ans, pDst, INT_LENGTH);

	if (ans == 1)
		cmp = true;
	else cmp = false;

	pfree(pDst);
	PG_RETURN_BOOL(cmp);
}

/*
 * The function checks if the first input encint is greater or equal than the second one.
 * It is called by binary operator '>=' defined in sql extension.
 * It requires a running SGX enclave and uses the function 'compareInt64' from the 'interface' library.
 * @input: two encint values
 * @return: true, if the first decrypted integer is greater or equal than the second one.
 *		    false, otherwise
 */
PG_FUNCTION_INFO_V1(encint_ge);
Datum
encint_ge(PG_FUNCTION_ARGS)
{	
	char *pDst = (char *) palloc((INT_LENGTH) * sizeof(char));
	char *c1 = PG_GETARG_CSTRING(0);
	char *c2 = PG_GETARG_CSTRING(1);
	int ans =0;
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	bool cmp;

	resp = compareInt64(c1, c2, pDst);
	sgxErrorHandler(resp);
	memcpy(&ans, pDst, INT_LENGTH);

	if ((ans == 0)||(ans==1))
		cmp = true;
	else cmp = false;

	pfree(pDst);
	PG_RETURN_BOOL(cmp);
}

//TODO
// DEBUG FUNCTION
// WILL BE DELETED IN THE PRODUCT
PG_FUNCTION_INFO_V1(encint_enc);
Datum
encint_enc(PG_FUNCTION_ARGS)
{
	char *pDst;
	int c1 = PG_GETARG_INT32(0);
	int ans;
	pDst = (char *) palloc((ENC_INT_LENGTH_B64) * sizeof(char));
	//pDst = encryptREncInt(c1);
	ans = encryptInt64(c1, pDst);
	sgxErrorHandler(ans);
	//ereport(LOG, (errmsg("function encrypt, output: %s", ans)));
    PG_RETURN_CSTRING((const char*) pDst);
}

//TODO
// DEBUG FUNCTION
// WILL BE DELETED IN THE PRODUCT
PG_FUNCTION_INFO_V1(encint_dec);
Datum
encint_dec(PG_FUNCTION_ARGS)
{
	int resp, ans = 0;
	char *pSrc = PG_GETARG_CSTRING(0);
	char *pDst = (char *) palloc((INT_LENGTH) * sizeof(char));

	resp = decryptInt64(pSrc, pDst);
	memcpy(&ans, pDst, INT_LENGTH);
	sgxErrorHandler(resp);
	//ereport(LOG, (errmsg("function decrypt, output: %d", ans)));

	pfree(pDst);
	PG_RETURN_INT32(ans);
}

/*
 * The function calculates the sum of elements from input array
 * It is called by sql aggregate command SUM, which is firstly appends needed encint elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'plusInt64' from the 'interface' library.
 * @input: an array of encint values which should be summarize
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encint_addfinal);
Datum
encint_addfinal(PG_FUNCTION_ARGS)
{
	ArrayType *v = PG_GETARG_ARRAYTYPE_P(0);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	ArrayIterator array_iterator;
	ArrayMetaState *my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	bool        isnull;
	Datum value;

	char* pSrc1 = (char*) palloc((ENC_INT_LENGTH_B64)*sizeof(char));
	char* pSrc2 = (char*) palloc((ENC_INT_LENGTH_B64)*sizeof(char));
	char* pTemp = (char*) palloc((ENC_INT_LENGTH_B64)*sizeof(char));

	array_iterator = array_create_iterator(v, 0, my_extra);
	array_iterate(array_iterator, &value, &isnull);

	memcpy(pSrc1, DatumGetCString(value), ENC_INT_LENGTH_B64);
	pSrc1[ENC_INT_LENGTH_B64-1] = '\0';

	while (array_iterate(array_iterator, &value, &isnull))
	{
		memcpy(pTemp, DatumGetCString(value), ENC_INT_LENGTH_B64);
		pTemp[ENC_INT_LENGTH_B64-1] = '\0';
		resp = plusInt64(pSrc1, pTemp, pSrc2);
		sgxErrorHandler(resp);

		memcpy(pSrc1, pSrc2, ENC_INT_LENGTH_B64);
		pSrc1[ENC_INT_LENGTH_B64-1] = '\0';
	}

	pfree(pTemp);
	pfree(pSrc2);

	PG_RETURN_CSTRING(pSrc1);
}


/*
 * The function computes the average of elements from array of encint elements.
 * It is called by sql aggregate command AVG, which is firstly appends needed encint elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'plusInt64', 'divInt64', 'encryptInt64' from the 'interface' library.
 * @input: an array of encint elements
 * @return: an encrypted result (encrypted integer). output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encint_avgfinal);
Datum
encint_avgfinal(PG_FUNCTION_ARGS)
{
	ArrayType *v = PG_GETARG_ARRAYTYPE_P(0);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	ArrayIterator array_iterator;
	ArrayMetaState *my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	bool isnull;
	Datum value;
	int         ndims1 = ARR_NDIM(v); //array dimension
    int        *dims1 = ARR_DIMS(v);
    int nitems = ArrayGetNItems(ndims1, dims1); //number of items in array
    char* pSrc1 = (char*) palloc((ENC_INT_LENGTH_B64)*sizeof(char));
    char* pSrc2 = (char*) palloc((ENC_INT_LENGTH_B64)*sizeof(char));
    char* pTemp = (char*) palloc((ENC_INT_LENGTH_B64)*sizeof(char));

	array_iterator = array_create_iterator(v, 0, my_extra);
	array_iterate(array_iterator, &value, &isnull);

	memcpy(pSrc1, DatumGetCString(value), ENC_INT_LENGTH_B64);
	pSrc1[ENC_INT_LENGTH_B64-1] = '\0';

	while (array_iterate(array_iterator, &value, &isnull))
	{
		memcpy(pTemp, DatumGetCString(value), ENC_INT_LENGTH_B64);
		pTemp[ENC_INT_LENGTH_B64-1] = '\0';

		resp = plusInt64(pSrc1, pTemp, pSrc2);
		sgxErrorHandler(resp);

		memcpy(pSrc1, pSrc2, ENC_INT_LENGTH_B64);
		pSrc1[ENC_INT_LENGTH_B64-1] = '\0';
	}

	resp = encryptInt64(nitems, pTemp);
	sgxErrorHandler(resp);

	resp = divInt64(pSrc1, pTemp, pSrc2);
	sgxErrorHandler(resp);

	pfree(pTemp);
	pfree(pSrc1);

	PG_RETURN_CSTRING(pSrc2);
}


/*
 * The function computes the minimal element of array of encint elements
 * It is called by sql aggregate command MIN, which is firstly appends needed encint elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'compareInt64' from the 'interface' library.
 * @input: an array of encint elements
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encint_minfinal);
Datum
encint_minfinal(PG_FUNCTION_ARGS)
{
	ArrayType *v = PG_GETARG_ARRAYTYPE_P(0);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	int ans= 0;
	ArrayIterator array_iterator;
	ArrayMetaState *my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	bool isnull;
	Datum value;

	int ndims1 = ARR_NDIM(v); //array dimension
    int *dims1 = ARR_DIMS(v);
    int nitems = ArrayGetNItems(ndims1, dims1); //number of items in array

    char* pSrc1 = (char*) palloc((ENC_INT_LENGTH_B64)*sizeof(char));
    char* pTemp = (char*) palloc((ENC_INT_LENGTH_B64)*sizeof(char));
	char *pDst = (char *) palloc((INT_LENGTH) * sizeof(char));

	array_iterator = array_create_iterator(v, 0, my_extra);
	array_iterate(array_iterator, &value, &isnull);

	memcpy(pSrc1, DatumGetCString(value), ENC_INT_LENGTH_B64);
	pSrc1[ENC_INT_LENGTH_B64-1] = '\0';

	while (array_iterate(array_iterator, &value, &isnull))
	{
		memcpy(pTemp, DatumGetCString(value), ENC_INT_LENGTH_B64);
		pTemp[ENC_INT_LENGTH_B64-1] = '\0';

		resp = compareInt64(pSrc1, pTemp, pDst);
		sgxErrorHandler(resp);
		memcpy(&ans, pDst, INT_LENGTH);

		if (ans == 1)
			memcpy(pSrc1, pTemp, ENC_INT_LENGTH_B64);
		pSrc1[ENC_INT_LENGTH_B64-1] = '\0';
	}

	pfree(pDst);
	pfree(pTemp);

	PG_RETURN_CSTRING(pSrc1);
}

/*
 * The function computes the maximal element of array of encint elements
 * It is called by sql aggregate command MAX, which is firstly appends needed encint elements into array and then calls this function.
 * It requires a running SGX enclave and uses the function 'compareInt64' from the 'interface' library.
 * @input: array of encint elements
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(encint_maxfinal);
Datum
encint_maxfinal(PG_FUNCTION_ARGS)
{
	ArrayType *v = PG_GETARG_ARRAYTYPE_P(0);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	int ans= 0;
	ArrayIterator array_iterator;
	ArrayMetaState *my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	bool        isnull;
	Datum value;

	int         ndims1 = ARR_NDIM(v); //array dimension
    int        *dims1 = ARR_DIMS(v);
    int nitems = ArrayGetNItems(ndims1, dims1); //number of items in array

    char* pSrc1 = (char*) palloc((ENC_INT_LENGTH_B64)*sizeof(char));
    char* pTemp = (char*) palloc((ENC_INT_LENGTH_B64)*sizeof(char));
	char *pDst = (char *) palloc((INT_LENGTH) * sizeof(char));

	array_iterator = array_create_iterator(v, 0, my_extra);
	array_iterate(array_iterator, &value, &isnull);

	memcpy(pSrc1, DatumGetCString(value), ENC_INT_LENGTH_B64);
	pSrc1[ENC_INT_LENGTH_B64-1] = '\0';

	while (array_iterate(array_iterator, &value, &isnull))
	{
		memcpy(pTemp, DatumGetCString(value), ENC_INT_LENGTH_B64);
		pTemp[ENC_INT_LENGTH_B64-1] = '\0';

		resp = compareInt64(pSrc1, pTemp, pDst);
		sgxErrorHandler(resp);
		memcpy(&ans, pDst, INT_LENGTH);

		if (ans == -1)
			memcpy(pSrc1, pTemp, ENC_INT_LENGTH_B64);
		pSrc1[ENC_INT_LENGTH_B64-1] = '\0';
	}

	pfree(pDst);
	pfree(pTemp);

	PG_RETURN_CSTRING(pSrc1);
}

/*
 * The function converts an integer to encint value. This function is calles by sql function CAST.
 * It requires a running SGX enclave and uses the function 'encryptInt64' from the 'interface' library.
 * @input: int4
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(int4_to_encint);
Datum
int4_to_encint(PG_FUNCTION_ARGS)
{
	int c1 = PG_GETARG_INT32(0);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *pDst = (char *) palloc((ENC_INT_LENGTH_B64) * sizeof(char));

	resp = encryptInt64(c1, pDst);
	sgxErrorHandler(resp);
	//ereport(INFO, (errmsg("auto encryption: ENC(%d) = %s", c1, pDst)));

    PG_RETURN_CSTRING((const char*) pDst);

}


/*
 * The function converts an integer(8 bytes, known as bigint) to encint value. This function is calles by sql function CAST.
 * It requires a running SGX enclave and uses the function 'encryptInt64' from the 'interface' library.
 * @input: int8
 * @return: an encrypted result. output format: BASE64(iv[12 bytes]||AES-GCM(s1+s2)[4 bytes]||AUTHTAG[16bytes])
 */
PG_FUNCTION_INFO_V1(int8_to_encint);
Datum
int8_to_encint(PG_FUNCTION_ARGS)
{
	int64 c1 = PG_GETARG_INT64(0);
	int resp = ENCLAVE_IS_NOT_RUNNIG;
	char *pDst = (char *) palloc((ENC_INT_LENGTH_B64) * sizeof(char));

	if (c1 < INT_MIN || c1 > INT_MAX)
		 ereport(ERROR, (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE), errmsg("value \"%li\" is out of range for type %s", c1, "integer")));
	resp = encryptInt64((int32) c1, pDst);
	sgxErrorHandler(resp);
	//ereport(INFO, (errmsg("auto encryption: ENC(%d) = %s", c1, pDst)));

    PG_RETURN_CSTRING((const char*) pDst);

}
