#include "untrusted/extensions/stdafx.h"

PG_MODULE_MAGIC;
bool debugMode = false;

void sgxErrorHandler(int code)
{
    size_t i;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    if ((code > 1) || (code < -6))
    {
        for (i = 0; i < ttl; i++)
        {
            if (sgx_errlist[i].err == code)
                ereport(ERROR, (-1, errmsg("SGX_ERROR_CODE %d: %s \n", code, sgx_errlist[i].msg)));
        }
        //ereport(ERROR, (-1, errmsg("SGX_ERROR_CODE: %d \n", code)));
    }

    if (code == -2)
        ereport(ERROR, (-1, errmsg("SGX_ERROR_CODE %d: ENCLAVE IS NOT RUNNING", code)));
    if (code == -3)
        ereport(ERROR, (-1, errmsg("SGX_ERROR_CODE %d: MEMORY_COPY_ERROR", code)));
    if (code == -4)
        ereport(ERROR, (-1, errmsg("SGX_ERROR_CODE %d: ARITHMETIC_ERROR", code)));
    if (code == -5)
        ereport(ERROR, (-1, errmsg("SGX_ERROR_CODE %d: MEMORY_ALLOCATION_ERROR", code)));
    if (code == -6)
        ereport(ERROR, (-1, errmsg("SGX_ERROR_CODE %d: OUT_OF_THE_RANGE_ERROR", code)));
    if (code == -7)
        ereport(ERROR, (-1, errmsg("INTERFACE_ERROR_CODE %d: BASE64DECODER_ERROR", code)));
    if (code == -8)
        ereport(ERROR, (-1, errmsg("INTERFACE_ERROR_CODE %d: \n The extension was not initialized. Run 'select launch();'", code)));
    if (code == -9)
        ereport(ERROR, (-1, errmsg("INTERFACE_ERROR_CODE %d: \n Cannot open key storage file.'", code)));
    if (code == -10)
        ereport(ERROR, (-1, errmsg("INTERFACE_ERROR_CODE %d: \n The default master key was not set up. Run 'select generate_key();'.", code)));
    if (code == TOO_MANY_ELEMENTS_IN_BULK)
        ereport(ERROR, (-1, errmsg("INTERFACE_ERROR_CODE %d: Too many elements in a bulk for an aggregation function.", code)));
}

PG_FUNCTION_INFO_V1(launch);
Datum
    launch(PG_FUNCTION_ARGS)
{
    int resp = initMultithreading();
    sgxErrorHandler(resp);
    resp = loadKey(0);
    sgxErrorHandler(resp);
    ereport(INFO, (errmsg("StealthDB is initialized: the default key has been loaded.")));

    PG_RETURN_INT32(resp);
}

PG_FUNCTION_INFO_V1(generate_key);
Datum
    generate_key(PG_FUNCTION_ARGS)
{
    int resp = generateKey();
    sgxErrorHandler(resp);

    PG_RETURN_INT32(resp);
}

PG_FUNCTION_INFO_V1(load_key);
Datum
    load_key(PG_FUNCTION_ARGS)
{
    int item = PG_GETARG_INT64(0);

    int resp = loadKey(item);
    sgxErrorHandler(resp);

    PG_RETURN_INT32(resp);
}

PG_FUNCTION_INFO_V1(enable_debug_mode);
Datum
    enable_debug_mode(PG_FUNCTION_ARGS)
{
    int item = PG_GETARG_INT64(0);
    debugMode = item;

    PG_RETURN_INT32(0);
}
