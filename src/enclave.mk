include vars.mk 
-include status.mk

######## SGX SDK Settings ########

ifeq ($(SGX_DEBUG), 1)
  ifeq ($(SGX_PRERELEASE), 1)
    $(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
  endif
endif

Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := $(wildcard utils/*.cpp) $(filter-out $(wildcard enclave/*int32*.cpp),$(wildcard enclave/*.cpp))

ifeq ($(OBLVS), 1)
  BUILD_TARGET = oblvs
  Enclave_Cpp_Files += enclave/enc_oblvs_int32_ops.cpp
else
  BUILD_TARGET = non_oblvs
  Enclave_Cpp_Files += enclave/enc_int32_ops.cpp
endif


ifndef BUILT_TARGET
  BUILT_TARGET = $(BUILD_TARGET)
endif

Enclave_Asm_Files := $(wildcard utils/*.S)

Enclave_Include_Paths := -Iinclude -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths) -fno-builtin-printf -I.
Enclave_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags)
Enclave_Cpp_Flags :=  $(Common_C_Cpp_Flags) -std=c++11 -nostdinc++ -fno-builtin-printf -I.

Enclave_Cpp_Flags := $(Enclave_Cpp_Flags)  -fno-builtin-printf

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=enclave/enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o) 

Enclave_C_Objects := $(Enclave_C_Files:.c=.o)
Enclave_Asm_Objects := $(Enclave_Asm_Files:.S=.o)

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
all: check_target enclave.so
	@echo "Build enclave enclave.so  [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the enclave.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo 

else
all: check_target enclave.signed.so
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/app
	@echo "RUN  =>  app [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## enclave Objects ########

enclave/enclave_t.c: $(SGX_EDGER8R) ./enclave/enclave.edl
	@cd ./enclave && $(SGX_EDGER8R) --trusted ../enclave/enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave/enclave_t.o: ./enclave/enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/%.o: enclave/%.cpp
	@echo "$(Enclave_Cpp_Flags) -c $< -o $@"
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Asm_Objects): %.o: %.S
	nasm -f elf64 $< -o $@
  
enclave.so: enclave/enclave_t.o $(Enclave_Cpp_Objects) $(Enclave_Asm_Objects) $(Enclave_C_Objects)
	@echo "$(Enclave_Cpp_Objects) $(Enclave_Asm_Objects) enclave/enclave_t.o -o $@ $(Enclave_Link_Flags)"
	@$(CXX) $(Enclave_Cpp_Objects) $(Enclave_Asm_Objects) enclave/enclave_t.o -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"
	
enclave.signed.so: enclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/enclave_private.pem -enclave enclave.so -out $@ -config enclave/enclave.config.xml
	@echo "SIGN =>  $@"

install:
	cp enclave.signed.so $(STEALTHDIR)	
	
clean:
	@rm -f status.mk *.so enclave/enclave_t.* enclave/*.o
