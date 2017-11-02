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

#include "../common/Queue.h"
#include "../common/SyncUtils.h"
#include "../common/Common.h"
#include "../common/Base64Coder.h"
#include "../common/def.h"


