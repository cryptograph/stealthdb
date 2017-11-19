// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once
#include <iostream>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"

#include <stdio.h>
#include <stdint.h>
#include <thread>
#include <mutex>
#include <unistd.h>
#include <algorithm>

#include "enclave/Queue.h"
#include "utils/SyncUtils.h"
#include "utils/Base64Coder.h"
#include "defs.h"


