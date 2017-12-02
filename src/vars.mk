SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
USE_OPT_LIBS ?= 1
export USE_OPT_LIBS

UNTRUSTED_DIR=untrusted
INTERFACE_DIR=untrusted/interface
EXTENSION_DIR=untrusted/extensions
RUNTIME_DIR= runtime
PKGLIBDIR = $(shell pg_config --pkglibdir)
SHAREDIR = $(shell pg_config --sharedir)/extension

STEALTHDIR = /usr/local/lib/stealthdb
ENCLAVE_DIR		:= enclave
ENCLAVE_NAME		:= enclave
TARGET			:= $(ENCLAVE_DIR)/$(ENCLAVE_NAME).so

SIGNDATA		:= $(ENCLAVE_DIR)/$(ENCLAVE_NAME).signdata
MRENCLAVE		:= $(ENCLAVE_DIR)/$(ENCLAVE_NAME).mrenclave
SIGNED_TARGET		:= $(ENCLAVE_DIR)/$(ENCLAVE_NAME).signed.so
ENCLAVE_CONFIG		:= $(ENCLAVE_DIR)/$(ENCLAVE_NAME).config.xml

DEBUG_ENCLAVE_NAME	:= $(ENCLAVE_NAME).debug
DEBUG_SIGNDATA		:= $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).signdata
DEBUG_SIGNED_TARGET	:= $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).signed.so
DEBUG_ENCLAVE_CONFIG	:= $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).config.xml

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Urts_Library_Name := sgx_urts
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
