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

#include "enclave/Queue.hpp"
#include "tools/sync_utils.hpp"
#include "tools/base64.hpp"
#include "defs.h"
