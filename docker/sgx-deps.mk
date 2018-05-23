#Builds Intel SGX libraries and binaries required by StealthDB.
#Does not include those corresponding to the AESMD service and SGX driver.

SGX_MODE ?= HW
export SGX_MODE

USE_OPT_LIBS = 1
export USE_OPT_LIBS

SDK_REV := sgx_2.0
SDK_SRC := $(SDK_REV)
SDK_BUILD_DIR := $(SDK_SRC)/build/linux
SDK_INSTALL_PATH := /opt/intel/sgxsdk

SGX_BUILD_LIBS := libsgx_trts.a libsgx_tservice.a libsgx_tstdc.a libsgx_tcrypto.a libsgx_tstdcxx.a libsgx_tcxx.a
SGX_RUNTIME_LIBS := libsgx_urts.so libsgx_uae_service.so
SGX_LIBS_INSTALL_DIR := $(SDK_INSTALL_PATH)/lib64

SGX_BINS := sgx_sign sgx_edger8r
SGX_BINS_INSTALL_DIR := $(SDK_INSTALL_PATH)/bin/x64

SGX_HEADERS_INSTALL_DIR := $(SDK_INSTALL_PATH)/include

.PHONY: all
all: $(addprefix $(SGX_LIBS_INSTALL_DIR)/, $(SGX_BUILD_LIBS) $(SGX_RUNTIME_LIBS)) $(addprefix $(SGX_BINS_INSTALL_DIR)/, $(SGX_BINS)) sgx_headers

$(SGX_LIBS_INSTALL_DIR)/libsgx_%: $(SDK_BUILD_DIR)/libsgx_% | $(SGX_LIBS_INSTALL_DIR)
	cp $(SDK_BUILD_DIR)/libsgx_$* $@

$(SDK_BUILD_DIR)/libsgx_%.a: | $(SDK_SRC)
	$(MAKE) -C $(SDK_SRC)/sdk $*

$(SDK_BUILD_DIR)/libsgx_%.so: | $(SDK_SRC)
	$(MAKE) -C $(SDK_SRC)/psw CXXFLAGS="-Wno-unused-parameter -fPIC" $*

$(SGX_BINS_INSTALL_DIR)/sgx_%: $(SDK_BUILD_DIR)/sgx_% | $(SGX_BINS_INSTALL_DIR)
	cp $(SDK_BUILD_DIR)/sgx_$* $@

$(SDK_BUILD_DIR)/sgx_sign: | $(SDK_SRC)
	$(MAKE) -C $(SDK_SRC)/sdk signtool

$(SDK_BUILD_DIR)/sgx_edger8r: | $(SDK_SRC)
	$(MAKE) -C $(SDK_SRC)/sdk edger8r

.PHONY: sgx_headers
sgx_headers: | $(SGX_HEADERS_INSTALL_DIR)
	cp -R $(SDK_SRC)/common/inc/* $|

$(SGX_HEADERS_INSTALL_DIR) $(SGX_BINS_INSTALL_DIR) $(SGX_LIBS_INSTALL_DIR):
	mkdir -p $@

$(SDK_SRC): $(SDK_REV).git
	git --git-dir=$< fetch origin master
	git --git-dir=$< archive --prefix=$@/ HEAD | tar -x
ifeq ($(USE_OPT_LIBS),1)
	cd $@ && ./download_prebuilt.sh
endif

$(SDK_REV).git:
	git clone --depth 1 --branch $(SDK_REV) --bare https://github.com/01org/linux-sgx.git $@

.PHONY: uninstall
uninstall:
	$(RM) $(addprefix $(SGX_LIBS_INSTALL_DIR), $(SGX_LIBS))\
		  $(addprefix $(SGX_BINS_INSTALL_DIR), $(SGX_BINS))\
		  -r $(SGX_HEADERS_INSTALL_DIR)

.PHONY: clean
clean:
	$(RM) -r $(SDK_SRC) $(SDK_REV)
