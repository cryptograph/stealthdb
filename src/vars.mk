SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

UNTRUSTED_DIR=untrusted
INTERFACE_DIR=untrusted/interface
EXTENSION_DIR=untrusted/extensions
BUILD_DIR= $(CURDIR)/../build
PSQL_PKG_LIBDIR = $(shell pg_config --pkglibdir)
PSQL_SHAREDIR = $(shell pg_config --sharedir)/extension

STEALTHDIR = /usr/local/lib/stealthdb
ENCLAVE_DIR := enclave
ENCLAVE_NAME:= enclave
TARGET:= $(ENCLAVE_DIR)/$(ENCLAVE_NAME).so

SIGNDATA:= $(ENCLAVE_DIR)/$(ENCLAVE_NAME).signdata
MRENCLAVE:= $(ENCLAVE_DIR)/$(ENCLAVE_NAME).mrenclave
SIGNED_TARGET:= $(ENCLAVE_DIR)/$(ENCLAVE_NAME).signed.so
ENCLAVE_CONFIG:= $(ENCLAVE_DIR)/$(ENCLAVE_NAME).config.xml

DEBUG_ENCLAVE_NAME	:= $(ENCLAVE_NAME).debug
DEBUG_SIGNDATA		:= $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).signdata
DEBUG_SIGNED_TARGET	:= $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).signed.so
DEBUG_ENCLAVE_CONFIG	:= $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).config.xml

SGX_COMMON_CFLAGS := -m64
SGX_INCLUDE_PATH:= /usr/include/sgx
SGX_ENCLAVE_SIGNER := /usr/bin/sgx_sign
SGX_EDGER8R := /usr/bin/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

SGX_URTS := sgx_urts
SGX_TRTS := sgx_trts
SGX_SERVICELIB := sgx_tservice
