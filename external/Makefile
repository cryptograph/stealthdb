SGX_MODE ?= HW
export SGX_MODE

USE_OPT_LIBS ?= 1
export USE_OPT_LIBS

SDK_SOURCE_GIT_TAG := sgx_1.9.git
SDK_SOURCE_GIT_REV := sgx_1.9-6-gaa8e9755aaec
SDK_SOURCE := $(SDK_SOURCE_GIT_REV)
SDK_SOURCE_BUILD_DIR := $(SDK_SOURCE)/build/linux

SDK_LIBS := libsgx_trts.a libsgx_tservice.a libsgx_tstdc.a libsgx_tcrypto.a libsgx_tstdcxx.a libsgx_tcxx.a libsgx_urts.so
SDK_BINS := sgx_sign sgx_edger8r
HEADERS := /usr/include/sgx

PSW_LIBS := libsgx_uae_service.so
AESM := /var/run/aesmd/aesm.socket
AESM_FILES:= le_prod_css.bin libsgx_le.signed.so libsgx_pce.signed.so libsgx_pse_op.signed.so libsgx_pse_pr.signed.so libsgx_pve.signed.so libsgx_qe.signed.so PSDA.dalp aesm_service
AESM_INSTALL_RULES = \
		-e 's:(+SDK_SOURCE_BUILD_DIR):$(SDK_SOURCE_BUILD_DIR):g' \
		-e 's:(+AESMD_FILES):$(addprefix $(SDK_SOURCE_BUILD_DIR)/,$(AESM_FILES)):g'

BUILD_TARGETS := $(addprefix $(SDK_SOURCE_BUILD_DIR)/,$(SDK_LIBS)) $(addprefix $(SDK_SOURCE_BUILD_DIR)/,$(SDK_BINS)) $(addprefix $(SDK_SOURCE_BUILD_DIR)/,$(PSW_LIBS))

INSTALL_TARGETS := $(SDK_LIBS:%=/usr/lib/%) $(SDK_BINS:%=/usr/bin/%) $(PSW_LIBS:%=/usr/lib/%)

DRIVER_SOURCE := linux-sgx-driver
DRIVER := /dev/isgx

.PHONY: all install uninstall clean

all: $(BUILD_TARGETS)
install: $(INSTALL_TARGETS) $(HEADERS) $(AESM) $(DRIVER)

$(DRIVER): | $(DRIVER_SOURCE)
	make -C $|
	cd $| \
	&& mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx" \
	&& cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx" \
	&& sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules" \
	&& depmod \
	&& modprobe isgx

$(AESM):
	$(MAKE) -C $(SDK_SOURCE)/psw/ae AESM
	$(MAKE) -C $(SDK_SOURCE)/psw/ae COPY_AES
	sed $(AESM_INSTALL_RULES) aesmd_install.template > aesmd_install.sh
	chmod +x aesmd_install.sh
	./aesmd_install.sh

$(HEADERS):
	mkdir -p $@
	cp -R $(SDK_SOURCE)/common/inc/* $@

/usr/lib/libsgx_%: $(SDK_SOURCE_BUILD_DIR)/libsgx_%
	mv $(SDK_SOURCE_BUILD_DIR)/libsgx_$* $@

/usr/bin/sgx_%: $(SDK_SOURCE_BUILD_DIR)/sgx_%
	mv $(SDK_SOURCE_BUILD_DIR)/sgx_$* $@

$(SDK_SOURCE_BUILD_DIR)/libsgx_%.a: | $(SDK_SOURCE)
	$(MAKE) -C $(SDK_SOURCE)/sdk $*

$(SDK_SOURCE_BUILD_DIR)/libsgx_%.so: | $(SDK_SOURCE)
	# CXXFLAGS workaround for protobuf-3 incompatibility
	$(MAKE) -C $(SDK_SOURCE)/psw CXXFLAGS="-fPIC -Wno-unused-parameter -std=c++11" $*

$(SDK_SOURCE_BUILD_DIR)/sgx_sign: | $(SDK_SOURCE)
	$(MAKE) -C $(SDK_SOURCE)/sdk signtool

$(SDK_SOURCE_BUILD_DIR)/sgx_edger8r: | $(SDK_SOURCE)
	$(MAKE) -C $(SDK_SOURCE)/sdk edger8r

$(SDK_SOURCE): $(SDK_SOURCE_GIT_TAG)
	git --git-dir=$< fetch origin master
	git --git-dir=$< archive --prefix=$@/ $(SDK_SOURCE_GIT_REV) | tar -x
ifeq ($(USE_OPT_LIBS),1)
	cd $@ && ./download_prebuilt.sh
endif

$(DRIVER_SOURCE):
	git clone https://github.com/01org/$@

%.git:
	git clone --depth 1 --branch $* --bare https://github.com/01org/linux-sgx.git $@

uninstall:
	rm -rf $(TARGETS)
	./aesmd_uninstall.sh
	#Driver
	/sbin/modprobe -r isgx
	rm -rf "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
	/sbin/depmod
	/bin/sed -i '/^isgx\$$/d' /etc/modules

clean:
	rm -rf $(SDK_SOURCE) aesmd_install.sh $(DRIVER_SOURCE) $(SDK_SOURCE_GIT_TAG)
