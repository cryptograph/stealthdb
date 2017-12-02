include vars.mk
-include status.mk

######## SGX SDK Settings ########

ifeq ($(SGX_DEBUG), 1)
  ifeq ($(SGX_PRERELEASE), 1)
    $(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
  endif
endif

Crypto_Library_Name := sgx_tcrypto

Cpp_Files := $(wildcard utils/*.cpp) $(filter-out $(wildcard $(ENCLAVE_DIR)/*int32*.cpp),$(wildcard $(ENCLAVE_DIR)/*.cpp))

ifeq ($(OBLVS), 1)
  BUILD_TARGET = oblvs
  Cpp_Files += $(ENCLAVE_DIR)/enc_oblvs_int32_ops.cpp
else
  BUILD_TARGET = non_oblvs
  Cpp_Files += $(ENCLAVE_DIR)/enc_int32_ops.cpp
endif

Cpp_Objects := $(Cpp_Files:.cpp=.o)
ifndef BUILT_TARGET
  BUILT_TARGET = $(BUILD_TARGET)
endif

Asm_Files := $(wildcard utils/*.S)
Asm_Objects := $(Asm_Files:.S=.o)

INC:= include $(SGX_SDK)/include $(SGX_SDK)/include/tlibc $(SGX_SDK)/include/stlport .
INCFLAGS:=$(INC:%=-I%)

COMMON_FLAGS:= $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(INCFLAGS) -fno-builtin-printf
CFLAGS := $(COMMON_FLAGS) -Wno-implicit-function-declaration -std=c11 $(Common_C_Cpp_Flags)
CXXFLAGS :=  $(COMMON_FLAGS) -std=c++11 -nostdinc++

LDFLAGS := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(ENCLAVE_DIR)/enclave.lds


ifeq ($(SGX_MODE), HW)
  ifneq ($(SGX_DEBUG), 1)
    ifneq ($(SGX_PRERELEASE), 1)
      Build_Mode = HW_RELEASE
    endif
  endif
endif

.PHONY: check_target all run

check_target:
ifneq ($(BUILT_TARGET),$(BUILD_TARGET))
	$(error "A different target was built earlier. Run 'make clean' first.")
endif
	@echo "BUILT_TARGET=$(BUILD_TARGET)" > status.mk
 
ifeq ($(Build_Mode), HW_RELEASE)
all: check_target $(TARGET) $(SIGNED_TARGET)
	@echo "Build enclave $(TARGET) [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the enclave.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo 

else
all: check_target debug_sign $(TARGET) 
endif

debug_sign: $(DEBUG_SIGNED_TARGET)

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/app
	@echo "RUN  =>  app [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

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

$(Asm_Objects): %.o: %.S
	@nasm -f elf64 $< -o $@
	@echo "NASM  <=  $<"
  
$(TARGET): $(ENCLAVE_DIR)/enclave_t.o $(Cpp_Objects) $(Asm_Objects) $(Enclave_C_Objects)
	@$(CXX) $(Cpp_Objects) $(Asm_Objects) $(ENCLAVE_DIR)/enclave_t.o -o $@ $(LDFLAGS)
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

remove:
	@rm -f status.mk *.so $(Asm_Objects) $(ENCLAVE_DIR)/enclave_t.* $(ENCLAVE_DIR)/*.o $(TARGET) \
	$(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).key $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).pub $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).sig \
	$(DEBUG_SIGNDATA) $(DEBUG_SIGNED_TARGET) \
	$(SIGNDATA) $(MRENCLAVE) $(SIGNED_TARGET) -r ../$(RUNTIME_DIR)
	
clean:
	@rm -f status.mk *.so $(Asm_Objects) $(ENCLAVE_DIR)/enclave_t.* $(ENCLAVE_DIR)/*.o $(TARGET) \
	$(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).pub $(ENCLAVE_DIR)/$(DEBUG_ENCLAVE_NAME).sig \
	$(DEBUG_SIGNDATA) $(DEBUG_SIGNED_TARGET) \
	$(SIGNDATA) $(MRENCLAVE) $(SIGNED_TARGET) -r ../$(RUNTIME_DIR)
