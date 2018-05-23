include vars.mk
-include status.mk

SIGNDATA := $(ENCLAVE_DIR)/$(ENCLAVE_NAME).signdata
MRENCLAVE := $(ENCLAVE_DIR)/$(ENCLAVE_NAME).mrenclave
SIGNED_TARGET := $(ENCLAVE_DIR)/$(ENCLAVE_NAME).signed.so
ENCLAVE_CONFIG := $(ENCLAVE_DIR)/$(ENCLAVE_NAME).config.xml
SGX_ENCLAVE_SIGNER := $(SDK_INSTALL_PATH)/bin/x64/sgx_sign

DEBUG_ENCLAVE_NAME := $(ENCLAVE_NAME).debug
DEBUG_SIGNDATA := $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).signdata
DEBUG_SIGNED_TARGET := $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).signed.so
DEBUG_ENCLAVE_CONFIG := $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).config.xml

CXX_SRCS := $(wildcard tools/*.cpp) $(filter-out $(wildcard $(ENCLAVE_DIR)/*int32*.cpp),$(wildcard $(ENCLAVE_DIR)/*.cpp))
ifeq ($(OBLVS), 1)
  BUILD_TARGET = oblvs
  CXX_SRCS += $(ENCLAVE_DIR)/enc_oblvs_int32_ops.cpp
else
  BUILD_TARGET = non_oblvs
  CXX_SRCS += $(ENCLAVE_DIR)/enc_int32_ops.cpp
endif
CXX_OBJS := $(CXX_SRCS:.cpp=.o)

TARGET := $(ENCLAVE_DIR)/$(ENCLAVE_NAME).so

ifndef BUILT_TARGET
  BUILT_TARGET = $(BUILD_TARGET)
endif

ASM_SRCS := $(wildcard tools/*.S)
ASM_OBJS := $(ASM_SRCS:.S=.o)

C_SRCS := $(wildcard tools/*.c)
C_OBJS := $(C_SRCS:.c=.o)

CPPFLAGS := $(addprefix -I, include $(SGX_INCLUDE_PATH) $(SGX_INCLUDE_PATH)/tlibc)

FLAGS:= -m64 -O0 -g -fvisibility=hidden -fpie -fstack-protector -fno-builtin-printf -Wall -Wextra -Wpedantic
CFLAGS := $(FLAGS) $(CPPFLAGS) -nostdinc -std=c11
CXXFLAGS :=  $(FLAGS) $(CPPFLAGS) -nostdinc++ -std=c++11

LDFLAGS := \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SDK_INSTALL_PATH)/lib64\
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(ENCLAVE_DIR)/enclave.lds

.PHONY: check_target
check_target:
ifneq ($(BUILT_TARGET),$(BUILD_TARGET))
	$(error "A different target was built earlier. Run 'make clean' first.")
endif
	@echo "BUILT_TARGET=$(BUILD_TARGET)" > status.mk

.PHONY: all
all: check_target $(DEBUG_SIGNED_TARGET) $(TARGET)

$(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).key:
	@openssl genrsa -out $@ -3 3072

$(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).pub: %.pub: %.key
	@openssl rsa -out $@ -in $< -pubout

$(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).sig: %.sig: %.signdata %.key
	@openssl dgst -sha256 -out $@ -sign $*.key $*.signdata

$(ENCLAVE_DIR)/enclave_t.c: $(SGX_EDGER8R) $(ENCLAVE_DIR)/enclave.edl
	@cd $(ENCLAVE_DIR) && $(SGX_EDGER8R) --trusted enclave.edl
	@mv $(ENCLAVE_DIR)/enclave_t.h include/enclave
	@echo "GEN  =>  $@"

$(ENCLAVE_DIR)/enclave_t.o: $(ENCLAVE_DIR)/enclave_t.c
	@$(CC) -Iinclude/enclave $(CFLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(C_OBJS): %.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(CXX_OBJS): %.o: %.cpp
	@$(CXX) $(CXXFLAGS) -c $< -o $@
	@echo "CXX  <=  $<"

$(ASM_OBJS): %.o: %.S
	@nasm -f elf64 $< -o $@
	@echo "NASM  <=  $<"

$(TARGET): $(ENCLAVE_DIR)/enclave_t.o $(CXX_OBJS) $(ASM_OBJS) $(C_OBJS)
	@$(CXX) $^ -o $@ $(LDFLAGS)
	@echo "LINK =>  $@"

$(DEBUG_ENCLAVE_CONFIG): $(ENCLAVE_CONFIG)
	@sed -e 's@<DisableDebug>1</DisableDebug>@<DisableDebug>0</DisableDebug>@' $< > $@

$(SIGNDATA) $(DEBUG_SIGNDATA): %.signdata: $(TARGET) %.config.xml | $(SGX_SIGN)
	$(SGX_ENCLAVE_SIGNER) gendata -out $@ -enclave $(TARGET) -config $*.config.xml
	@echo "GENDATA =>  $@"

$(DEBUG_SIGNED_TARGET): %.signed.so: $(TARGET) %.pub %.sig %.signdata
	@$(SGX_ENCLAVE_SIGNER) catsig -enclave $(TARGET) -unsigned $*.signdata -out $@ -config $*.config.xml -key $*.pub -sig $*.sig
	cp $(DEBUG_SIGNED_TARGET) $(BUILD_DIR)
	@echo "SIGN =>  $@"

.PHONY: install
install:
	@if [ -e $(SIGNED_TARGET) ]; then cp $(SIGNED_TARGET) $(STEALTHDIR)/$(ENCLAVE_NAME).signed.so; fi
	@if [ -e $(DEBUG_SIGNED_TARGET) ]; then cp $(DEBUG_SIGNED_TARGET) $(STEALTHDIR)/$(ENCLAVE_NAME).signed.so; fi
	@echo cp $(BUILD_DIR)/$(DEBUG_ENCLAVE_NAME).signed.so $(STEALTHDIR)/$(ENCLAVE_NAME).signed.so;
	
.PHONY: clean
clean:
	@$(RM) status.mk *.so \
           $(ASM_OBJS) $(CXX_OBJS) $(TARGET) \
           $(SIGNDATA) $(MRENCLAVE) $(SIGNED_TARGET) \
           $(ENCLAVE_DIR)/enclave_t.* \
           $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).key \
           $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).pub \
           $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).sig \
           $(DEBUG_SIGNDATA) $(DEBUG_SIGNED_TARGET)
