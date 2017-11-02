// encstring.c : Defines the exported functions for the encrypted string type.
// The library contains functions for the Postgresql extension 'encdb', including:
//
// encrypted float type, format: BASE64(IV[12bytes]||AES-GCM(float4)[4 bytes]||AUTHTAG[16 bytes]) 
//			(input size: 4 bytes; output size: 44 bytes; operators: +,-,*,/,%,>=,>,<=,<,=,!=; functions: SUM, AVG) 
#include "stdafx.h"

// the structure is used to describe an element of the encstring type
typedef struct enc_str {
	int length;
	char src[1024];
} enc_str;


// The input function converts a string to an encstring element.
// @input: string
// @return: pointer to a structure describing encstring element.  
PG_FUNCTION_INFO_V1(encstring_in);
Datum
encstring_in(PG_FUNCTION_ARGS)
{
	char *str = PG_GETARG_CSTRING(0);
  
	enc_str *enc_str_var = (enc_str*) palloc(sizeof(enc_str));

    if (!enc_str_var){
        PG_RETURN_NULL();
	}
	//SET_VARSIZE(enc_str_var, varsize); 
	//ereport(LOG, (errmsg("function IN, input: %s", str)));
	
	memcpy(enc_str_var->src, str, strlen(str));
	enc_str_var->src[strlen(str)] = '\0';
	enc_str_var->length = strlen(str);

	//ereport(LOG, (errmsg("function IN, typmod: %d", typmod)));
	//ereport(LOG, (errmsg("encstring, function IN, (len %d) output: %s", enc_str_var->length, enc_str_var->src)));
	
	// TODO: question: should we free memery fro char structure

    PG_RETURN_POINTER(enc_str_var);

	
}

// The output function converts an encstring element to a string.
// @input: pointer to a structure describing encstring element
// @return: string  
PG_FUNCTION_INFO_V1(encstring_out);
Datum
encstring_out(PG_FUNCTION_ARGS)
{
	enc_str *enc_str_var =  (enc_str *) PG_GETARG_POINTER(0);
	char *res;

	//ereport(LOG, (errmsg("function OUT, input: %s", enc_str_var->src)));

	res = (char *) palloc((strlen(enc_str_var->src) + 1) * sizeof(char));

	memcpy(res, enc_str_var->src, strlen(enc_str_var->src));
	res[strlen(enc_str_var->src)] = '\0';
	

	//ereport(LOG, (errmsg("function OUT, output: %s", res)));

// TODO: question: should we free memory fro enc_str structure

	PG_RETURN_CSTRING(res);

}

// The function checks the equality of two encrypted strings. 
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if decrypted strings are equal
//		 false, otherwise 
PG_FUNCTION_INFO_V1(encstring_eq);
Datum
encstring_eq(PG_FUNCTION_ARGS)
{	
	enc_str * enc_str1 = (enc_str *) PG_GETARG_POINTER(0);
	enc_str * enc_str2 = (enc_str *) PG_GETARG_POINTER(1);
	bool cmp;
	int ans=0, resp;
	char *src1, *src2;

	//ereport(LOG, (errmsg("encstring, function EQ, input1: %s", enc_str1->src)));
	//ereport(LOG, (errmsg("encstring, function EQ, input2: %s", enc_str2->src)));

	src1 = (char *) palloc((enc_str1->length+1) * sizeof(char));
	src2 = (char *) palloc((enc_str2->length+1) * sizeof(char));

	memcpy(src1, enc_str1->src, enc_str1->length);
	memcpy(src2, enc_str2->src, enc_str2->length);

	src1[enc_str1->length] = '\0';
	src2[enc_str2->length] = '\0';

	resp = compareEncString(enc_str1->src, enc_str2->src, &ans);
	sgxErrorHandler(resp);

	//ereport(LOG, (errmsg("encstring, function EQ, output: %d", ans)));



	if (ans == 0)
		cmp = true;
	else cmp = false;

	//free(src1);
	//free(src2);

	PG_RETURN_BOOL(cmp);
}

// The function checks the inequality of two encrypted strings. 
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if decrypted strings are not equal
//		 false, otherwise 	
PG_FUNCTION_INFO_V1(encstring_ne);
Datum
encstring_ne(PG_FUNCTION_ARGS)
{	
	enc_str * enc_str1 = (enc_str *) PG_GETARG_POINTER(0);
	enc_str * enc_str2 = (enc_str *) PG_GETARG_POINTER(1);
	bool cmp;
	int ans=0, resp;
	char *src1, *src2;

	//ereport(LOG, (errmsg("encstring, function !=, input1: %s", enc_str1->src)));
	//ereport(LOG, (errmsg("encstring, function !=, input2: %s", enc_str2->src)));

	src1 = (char *) palloc((enc_str1->length+1) * sizeof(char));
	src2 = (char *) palloc((enc_str2->length+1) * sizeof(char));

	memcpy(src1, enc_str1->src, enc_str1->length);
	memcpy(src2, enc_str2->src, enc_str2->length);

	src1[enc_str1->length] = '\0';
	src2[enc_str2->length] = '\0';

	resp = compareEncString(enc_str1->src, enc_str2->src, &ans);
	sgxErrorHandler(resp);
	//ereport(LOG, (errmsg("encstring, function !=, output: %d", ans)));


	if (ans != 0)
		cmp = true;
	else cmp = false;

	PG_RETURN_BOOL(cmp);
}

// The function checks if the first input encrypted string is less or equal than the second one. 
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if the first decrypted string is less or equal than the second one. 
//		 false, otherwise 	   
PG_FUNCTION_INFO_V1(encstring_le);
Datum
encstring_le(PG_FUNCTION_ARGS)
{	
		enc_str * enc_str1 = (enc_str *) PG_GETARG_POINTER(0);
	enc_str * enc_str2 = (enc_str *) PG_GETARG_POINTER(1);
	bool cmp;
	int ans=0, resp;
	char *src1, *src2;

	//ereport(LOG, (errmsg("encstring, function LE, input1: %s", enc_str1->src)));
	//ereport(LOG, (errmsg("encstring, function LE, input2: %s", enc_str2->src)));

	src1 = (char *) palloc((enc_str1->length+1) * sizeof(char));
	src2 = (char *) palloc((enc_str2->length+1) * sizeof(char));

	memcpy(src1, enc_str1->src, enc_str1->length);
	memcpy(src2, enc_str2->src, enc_str2->length);

	src1[enc_str1->length] = '\0';
	src2[enc_str2->length] = '\0';

	resp = compareEncString(enc_str1->src, enc_str2->src, &ans);
	sgxErrorHandler(resp);
	//ereport(LOG, (errmsg("encstring, function LE, output: %d", ans)));

	if (ans <= 0)
		cmp = true;
	else cmp = false;

	PG_RETURN_BOOL(cmp);
}

// The function checks if the first input encrypted string is less than the second one. 
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if the first decrypted string is less than the second one. 
//		 false, otherwise 	 
PG_FUNCTION_INFO_V1(encstring_lt);
Datum
encstring_lt(PG_FUNCTION_ARGS)
{	
		enc_str * enc_str1 = (enc_str *) PG_GETARG_POINTER(0);
	enc_str * enc_str2 = (enc_str *) PG_GETARG_POINTER(1);
	bool cmp;
	int ans=0, resp;
	char *src1, *src2;

	//ereport(LOG, (errmsg("encstring, function LT, input1: %s", enc_str1->src)));
	//ereport(LOG, (errmsg("encstring, function LT, input2: %s", enc_str2->src)));

	src1 = (char *) palloc((enc_str1->length+1) * sizeof(char));
	src2 = (char *) palloc((enc_str2->length+1) * sizeof(char));

	memcpy(src1, enc_str1->src, enc_str1->length);
	memcpy(src2, enc_str2->src, enc_str2->length);

	src1[enc_str1->length] = '\0';
	src2[enc_str2->length] = '\0';

	resp = compareEncString(enc_str1->src, enc_str2->src, &ans);
	sgxErrorHandler(resp);
	//ereport(LOG, (errmsg("encstring, function LT, output: %d", ans)));

	if (ans < 0)
		cmp = true;
	else cmp = false;

	PG_RETURN_BOOL(cmp);
}

// The function checks if the first input encrypted string is greater or equal than the second one. 
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if the first decrypted string is greater or equal than the second one. 
//		 false, otherwise
PG_FUNCTION_INFO_V1(encstring_ge);
Datum
encstring_ge(PG_FUNCTION_ARGS)
{	
	enc_str * enc_str1 = (enc_str *) PG_GETARG_POINTER(0);
	enc_str * enc_str2 = (enc_str *) PG_GETARG_POINTER(1);
	bool cmp;
	int ans=0, resp;
	char *src1, *src2;

	//ereport(LOG, (errmsg("encstring, function GE, input1: %s", enc_str1->src)));
	//ereport(LOG, (errmsg("encstring, function GE, input2: %s", enc_str2->src)));

	src1 = (char *) palloc((enc_str1->length+1) * sizeof(char));
	src2 = (char *) palloc((enc_str2->length+1) * sizeof(char));

	memcpy(src1, enc_str1->src, enc_str1->length);
	memcpy(src2, enc_str2->src, enc_str2->length);

	src1[enc_str1->length] = '\0';
	src2[enc_str2->length] = '\0';

	resp = compareEncString(enc_str1->src, enc_str2->src, &ans);
	sgxErrorHandler(resp);
	//ereport(LOG, (errmsg("encstring, function GE, output: %d", ans)));


	if (ans >= 0)
		cmp = true;
	else cmp = false;

	PG_RETURN_BOOL(cmp);
}

// The function checks if the first input encrypted string is greater than the second one. 
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: true, if the first decrypted string is greater than the second one. 
//		 false, otherwise 	
PG_FUNCTION_INFO_V1(encstring_gt);
Datum
encstring_gt(PG_FUNCTION_ARGS)
{	
		enc_str * enc_str1 = (enc_str *) PG_GETARG_POINTER(0);
	enc_str * enc_str2 = (enc_str *) PG_GETARG_POINTER(1);
	bool cmp;
	int ans=0, resp;
	char *src1, *src2;

	//ereport(LOG, (errmsg("encstring, function GT, input1: %s", enc_str1->src)));
	//ereport(LOG, (errmsg("encstring, function GT, input2: %s", enc_str2->src)));

	src1 = (char *) palloc((enc_str1->length+1) * sizeof(char));
	src2 = (char *) palloc((enc_str2->length+1) * sizeof(char));

	memcpy(src1, enc_str1->src, enc_str1->length);
	memcpy(src2, enc_str2->src, enc_str2->length);

	src1[enc_str1->length] = '\0';
	src2[enc_str2->length] = '\0';

	resp = compareEncString(enc_str1->src, enc_str2->src, &ans);
	sgxErrorHandler(resp);
	//ereport(LOG, (errmsg("encstring, function GT, output: %d", ans)));


	if (ans > 0)
		cmp = true;
	else cmp = false;

	PG_RETURN_BOOL(cmp);
}

// The function compares two encrypted strings using the lexgraphical order for decrypted strings
// It requires a running SGX enclave and uses the function 'compareREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: -1, if s1 < s2, 
//		  0, if s1 = s2, 	 
//		  1, if s1 > s2
PG_FUNCTION_INFO_V1(encstring_cmp);
Datum
encstring_cmp(PG_FUNCTION_ARGS)
{	
	enc_str* enc_str1 = (enc_str*) PG_GETARG_POINTER(0);
	enc_str* enc_str2 = (enc_str*) PG_GETARG_POINTER(1);
	int ans=0, resp;
	char *src1, *src2;

	src1 = (char *) palloc((enc_str1->length+1) * sizeof(char));
	src2 = (char *) palloc((enc_str2->length+1) * sizeof(char));

	memcpy(src1, enc_str1->src, enc_str1->length);
	memcpy(src2, enc_str2->src, enc_str2->length);

	src1[enc_str1->length] = '\0';
	src2[enc_str2->length] = '\0';

//	ereport(LOG, (errmsg("encstring, function CMP, string1 (): %s", src1)));
//	ereport(LOG, (errmsg("encstring, function CMP, string2 (): %s", src2)));
	resp = compareEncString(enc_str1->src, enc_str2->src, &ans);
	sgxErrorHandler(resp);

//	ereport(LOG, (errmsg("encstring, function CMP, output: %d", ans)));


	//free(src1);
	//free(src2);

	PG_RETURN_INT32(ans);
}

// The function encrypts the input string.
// IT'S A DEBUG FUNCTION SHOULD BE DELETED IN THE PRODUCT
// !!!!!!!!!!!!!!!!!!!!!!!!!
PG_FUNCTION_INFO_V1(encstring_enc);
Datum
encstring_enc(PG_FUNCTION_ARGS)
{
	enc_str*enc_str_var = NULL;
	int resp, b64_len, len2;
	char *pDst;
	char *src = PG_GETARG_CSTRING(0);
	int len = strlen(src);

	if (len > STRING_LENGTH - 1) {
		ereport(ERROR, (errmsg("Error: the length of the element is more than maximun")));
		PG_RETURN_CSTRING("");
	}
	len2 = len + 12 +  16;
	b64_len = ((int)(4*(double)(len2)/3)+3)&3;
	pDst = (char *) palloc((ENC_STRING_LENGTH_B64) * sizeof(char));
	//char *ans = encryptREncInt(c1);


	ereport(INFO, (errmsg("string: %s", src)));

	resp = encryptString(src, pDst);
	sgxErrorHandler(resp);
	ereport(INFO, (errmsg("encstring: %s", pDst)));
	len2 = strlen(pDst);

//	ereport(INFO, (errmsg("function ENC, output: %d", b64_len)));

	enc_str_var = (enc_str*) palloc(sizeof(enc_str));
	memcpy(enc_str_var->src, pDst, len2);
	enc_str_var->length = len2;
	
//	ereport(LOG, (errmsg("function ENC, output: %s", enc_str_var->src)));
//	ereport(LOG, (errmsg("function ENC, output: %d",  enc_str_var->length)));
	enc_str_var->src[enc_str_var->length] = '\0';

	PG_RETURN_POINTER(enc_str_var);//encint_from_str(str));

/*
	char *c1 = PG_GETARG_CSTRING(0);

	int len = strlen(c1);
	char *ans = encryptREncString(c1);
	int len2 = strlen(ans);

	char *str = (char *) palloc((len2 + 1) * sizeof(char));
   // strncpy(str, ans, len2);

	memcpy(str, ans, len2);
	str[len2] = '\0';

	ereport(LOG, (errmsg("function encrypt, output: %s", c1)));
	ereport(LOG, (errmsg("function encrypt, output: %d", len)));
	ereport(LOG, (errmsg("function encrypt, output: %s", str)));
	ereport(LOG, (errmsg("function encrypt, output: %d", len2)));

//	encstring enc_str;
//	enc_str = (encstring *) palloc(sizeof(encstring));
//	memcpy(enc_str->src, str, len);
//	enc_str->length = len;

	//str[len2] = '\0';

//	PG_RETURN_POINTER(enc_str);//encint_from_str(str));
	//PG_RETURN_TEXT_P(cstring_to_text_with_len(ans, len2));

	 //PG_RETURN_VARCHAR_P((VarChar *) cstring_to_text_with_len(ans, len2));
	PG_RETURN_CSTRING(str);
	*/
}

// The function decrypts the input encstring element.
// IT'S A DEBUG FUNCTION SHOULD BE DELETED IN THE PRODUCT
// !!!!!!!!!!!!!!!!!!!!!!!!!
PG_FUNCTION_INFO_V1(encstring_dec);
Datum
encstring_dec(PG_FUNCTION_ARGS)
{
	//har *c1 = PG_GETARG_POINTER(0);
	int ans = 0;
	enc_str* enc_str_var = (enc_str*) PG_GETARG_POINTER(0);
	char* pDst = (char *) palloc(STRING_LENGTH * sizeof(char));

	ereport(INFO, (errmsg("string: %s", enc_str_var->src)));

	ans = decryptString(enc_str_var->src, pDst);
	sgxErrorHandler(ans);

	ereport(INFO, (errmsg("dec.string: %s", pDst)));
//	char *str;

//	int len2 = strlen(ans);

//	str = (char *) palloc((len2 + 1) * sizeof(char));
 // 	memcpy(str, ans, len2);
//	str[len2] = '\0';

	/*
	enc_str* enc_str_var = (enc_str*) PG_GETARG_POINTER(0);
	char *ans;
	char *res = (char *) palloc((enc_str_var->length + 1) * sizeof(char));
	memcpy(res, enc_str_var->src, enc_str_var->length);

	ans = decryptREncString(enc_str_var->src);
	//int len2 = strlen(ans);
	*/
	//ereport(LOG, (errmsg("function DEC, length: %s", enc_str_var->length)));
	//ereport(LOG, (errmsg("function DEC, input: %s", enc_str_var->src)));
	//ereport(LOG, (errmsg("function DEC, output: %s",  ans)));

	PG_RETURN_CSTRING(pDst);

/*
	char *c1 = PG_GETARG_CSTRING(0);

	int len = strlen(c1);
	char *ans = decryptREncString(c1);
	int len2 = strlen(ans);

	char *str = (char *) palloc((len2 + 1) * sizeof(char));
   // strncpy(str, ans, len2);

	memcpy(str, ans, len2);
	str[len2] = '\0';

	ereport(LOG, (errmsg("function decrypt, output: %s", c1)));
	ereport(LOG, (errmsg("function decrypt, output: %d", len)));
	ereport(LOG, (errmsg("function decrypt, output: %s", str)));
	ereport(LOG, (errmsg("function decrypt, output: %d", len2)));

	/*
	int len = strlen(c1);
	
	char *ans = decryptREncString(c1);
	int len2 = strlen(ans);

	char *str = (char *) palloc((len2 + 1) * sizeof(char));
   // strncpy(str, ans, len2);
	ereport(LOG, (errmsg("function decrypt, output: %d", len)));
	memcpy(str, ans, len2);
	str[len2] = '\0';
	*/

}

// The function decrypts two encrypted strings, concatenates them and encrypts the result.  
// It requires a running SGX enclave and uses the function 'concatREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: an encrypted result of a concatenation. output format: BASE64(iv[12 bytes]||AES-GCM(s1||s2)||AUTHTAG[16bytes])	 
PG_FUNCTION_INFO_V1(encstring_concat);
Datum
encstring_concat(PG_FUNCTION_ARGS)
{	
	char *src1, *src2, *pDst;
	enc_str* enc_str_var;
	int resp;
	int pDst_len;
	enc_str* enc_str1 = (enc_str*) PG_GETARG_POINTER(0);
	enc_str* enc_str2 = (enc_str*) PG_GETARG_POINTER(1);

	pDst_len = enc_str1->length + enc_str2->length + 1 - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

	if (pDst_len > ENC_STRING_LENGTH_B64 - 1) {
		ereport(ERROR, (errmsg("Error: the length of the concatenated element is more than maximun")));
		PG_RETURN_CSTRING("");
	}

	src1 = (char *) palloc((enc_str1->length + 1) * sizeof(char));
	src2 = (char *) palloc((enc_str2->length + 1) * sizeof(char));
	pDst = (char *) palloc((pDst_len) * sizeof(char));

	memcpy(src1, enc_str1->src, enc_str1->length);
	memcpy(src2, enc_str2->src, enc_str2->length);

	src1[enc_str1->length] = '\0';
	src2[enc_str2->length] = '\0';

	//ereport(LOG, (errmsg("encstring, function ||, string1 (): %s", src1)));
	//ereport(LOG, (errmsg("encstring, function ||, string2 (): %s", src2)));

	resp = concatEncString(enc_str1->src, enc_str2->src, pDst);
	sgxErrorHandler(resp);
	
	enc_str_var = (enc_str*) palloc(sizeof(enc_str));
	pDst_len = strlen(pDst); // TODO: calculate the actual size of a concatenated string
	memcpy(enc_str_var->src, pDst, pDst_len); 
	
	enc_str_var->src[pDst_len] = '\0';
	enc_str_var->length = pDst_len;
	
	//ereport(LOG, (errmsg("encstring, function ||, output: %d - %s", enc_str_var->length, enc_str_var->src)));

	PG_RETURN_POINTER(enc_str_var);

}

// The function decrypts two encrypted strings, search for the second string as a substring in the first one.  
// It requires a running SGX enclave and uses the function 'substringREncString' from the 'interface' library.
// @input: two encrypted strings
// @return: an encrypted result of a concatenation. output format: BASE64(iv[12 bytes]||AES-GCM(s1||s2)||AUTHTAG[16bytes])	 
PG_FUNCTION_INFO_V1(encstring_like);
Datum
encstring_like(PG_FUNCTION_ARGS)
{	
	enc_str* enc_str1 = (enc_str*) PG_GETARG_POINTER(0);
	enc_str* enc_str2 = (enc_str*) PG_GETARG_POINTER(1);
	int ans=0, resp;
	bool cmp;
	char *src1, *src2;

	src1 = (char *) palloc((enc_str1->length+1) * sizeof(char));
	src2 = (char *) palloc((enc_str2->length+1) * sizeof(char));

	memcpy(src1, enc_str1->src, enc_str1->length);
	memcpy(src2, enc_str2->src, enc_str2->length);

	src1[enc_str1->length] = '\0';
	src2[enc_str2->length] = '\0';

	//ereport(LOG, (errmsg("encstring, function LIKE, string1 (): %s", src1)));
	//ereport(LOG, (errmsg("encstring, function LIKE, string2 (): %s", src2)));
	
	resp = substringEncString(enc_str1->src, enc_str2->src, &ans);
	sgxErrorHandler(resp);

	if (ans == 0)
		cmp = true;
	else cmp = false;

	//ereport(LOG, (errmsg("The result of the substraction function: %d", ans)));

	PG_RETURN_BOOL(cmp);
}


// The input function converts a string to an encstring element.
// @input: string
// @return: pointer to a structure describing encstring element.
PG_FUNCTION_INFO_V1(varchar_to_encstring);
Datum
varchar_to_encstring(PG_FUNCTION_ARGS)
{
	enc_str*enc_str_var = NULL;
	int resp, b64_len, len2;
	char *pDst;
	char *src = PG_GETARG_CSTRING(0);
	int len = strlen(src);

	if (len > STRING_LENGTH - 1) {
		ereport(ERROR, (errmsg("Error: the length of the element is more than maximun")));
		PG_RETURN_CSTRING("");
	}
	len2 = len + 12 +  16;
	b64_len = ((int)(4*(double)(len2)/3)+3)&3;
	pDst = (char *) palloc((ENC_STRING_LENGTH_B64) * sizeof(char));

	resp = encryptString(src, pDst);
	sgxErrorHandler(resp);

	len2 = strlen(pDst);

	enc_str_var = (enc_str*) palloc(sizeof(enc_str));
	memcpy(enc_str_var->src, pDst, len2);
	enc_str_var->length = len2;
	enc_str_var->src[enc_str_var->length] = '\0';

	PG_RETURN_POINTER(enc_str_var);//encint_from_str(str));
}
