include vars.mk
-include status.mk

CXX_SRCS := $(wildcard utils/*.cpp) $(filter-out $(wildcard $(ENCLAVE_DIR)/*int32*.cpp),$(wildcard $(ENCLAVE_DIR)/*.cpp))

ifeq ($(OBLVS), 1)
  BUILD_TARGET = oblvs
  CXX_SRCS += $(ENCLAVE_DIR)/enc_oblvs_int32_ops.cpp
else
  BUILD_TARGET = non_oblvs
  CXX_SRCS += $(ENCLAVE_DIR)/enc_int32_ops.cpp
endif

CXX_OBJS := $(CXX_SRCS:.cpp=.o)
ifndef BUILT_TARGET
  BUILT_TARGET = $(BUILD_TARGET)
endif

ASM_SRCS := $(wildcard utils/*.S)
ASM_OBJS := $(ASM_SRCS:.S=.o)

INC:= include $(SGX_INCLUDE_PATH) $(SGX_INCLUDE_PATH)/tlibc $(SGX_INCLUDE_PATH)/stlport .

INCFLAGS:=$(INC:%=-I%)

COMMON_FLAGS:= $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(INCFLAGS) -fno-builtin-printf
CFLAGS := $(COMMON_FLAGS) -Wno-implicit-function-declaration -std=c11
CXXFLAGS :=  $(COMMON_FLAGS) -std=c++11 -nostdinc++

LDFLAGS := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-Wl,--whole-archive -l$(SGX_TRTS) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -l$(SGX_SERVICELIB) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(ENCLAVE_DIR)/enclave.lds

.PHONY: check_target all

check_target:
ifneq ($(BUILT_TARGET),$(BUILD_TARGET))
	$(error "A different target was built earlier. Run 'make clean' first.")
endif
	@echo "BUILT_TARGET=$(BUILD_TARGET)" > status.mk
 
all: check_target $(DEBUG_SIGNED_TARGET) $(TARGET)

######## enclave Objects ########

$(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).key:
	@openssl genrsa -out $@ -3 3072

$(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).pub: %.pub: %.key
	@openssl rsa -out $@ -in $< -pubout

$(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).sig: %.sig: %.signdata %.key
	@openssl dgst -sha256 -out $@ -sign $*.key $*.signdata

$(ENCLAVE_DIR)/enclave_t.c: $(SGX_EDGER8R) ./$(ENCLAVE_DIR)/enclave.edl
	@cd ./$(ENCLAVE_DIR) && $(SGX_EDGER8R) --trusted ../$(ENCLAVE_DIR)/enclave.edl --search-path ../$(ENCLAVE_DIR) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(ENCLAVE_DIR)/enclave_t.o: ./$(ENCLAVE_DIR)/enclave_t.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.cpp
	@$(CXX) $(CXXFLAGS) -c $< -o $@
	@echo "CXX  <=  $<"

$(ASM_OBJS): %.o: %.S
	@nasm -f elf64 $< -o $@
	@echo "NASM  <=  $<"
  
$(TARGET): $(ENCLAVE_DIR)/enclave_t.o $(CXX_OBJS) $(ASM_OBJS)
	@$(CXX) $(CXX_OBJS) $(ASM_OBJS) $(ENCLAVE_DIR)/enclave_t.o -o $@ $(LDFLAGS)
	@echo "LINK =>  $@"

$(DEBUG_ENCLAVE_CONFIG): $(ENCLAVE_CONFIG)
	@sed -e 's@<DisableDebug>1</DisableDebug>@<DisableDebug>0</DisableDebug>@' $< > $@

$(SIGNDATA) $(DEBUG_SIGNDATA): %.signdata: $(TARGET) %.config.xml | $(SGX_SIGN)
	$(SGX_ENCLAVE_SIGNER) gendata -out $@ -enclave $(TARGET) -config $*.config.xml
	@echo "GENDATA =>  $@"

$(DEBUG_SIGNED_TARGET): %.signed.so: $(TARGET) %.pub %.sig %.signdata
	@$(SGX_ENCLAVE_SIGNER) catsig -enclave $(TARGET) -unsigned $*.signdata -out $@ -config $*.config.xml -key $*.pub -sig $*.sig
	cp $(DEBUG_SIGNED_TARGET) ../$(RUNTIME_DIR)
	@echo "SIGN =>  $@"

install:
	@if [ -e $(SIGNED_TARGET) ]; then cp $(SIGNED_TARGET) $(STEALTHDIR)/$(ENCLAVE_NAME).signed.so; fi
	@if [ -e $(DEBUG_SIGNED_TARGET) ]; then cp $(DEBUG_SIGNED_TARGET) $(STEALTHDIR)/$(ENCLAVE_NAME).signed.so; fi
	@echo cp $(RUNTIME_DIR)/$(DEBUG_ENCLAVE_NAME).signed.so $(STEALTHDIR)/$(ENCLAVE_NAME).signed.so;
	
clean:
	@rm -f status.mk *.so $(ASM_OBJS) $(ENCLAVE_DIR)/enclave_t.* $(ENCLAVE_DIR)/*.o $(TARGET) \
	$(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).key $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).pub $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).sig \
	$(DEBUG_SIGNDATA) $(DEBUG_SIGNED_TARGET) \
	$(SIGNDATA) $(MRENCLAVE) $(SIGNED_TARGET) -r $(RUNTIME_DIR)
