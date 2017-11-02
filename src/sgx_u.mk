######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

UNTRUSTED_DIR=untrusted
INTERFACE_DIR=untrusted/interface
EXTENSION_DIR=untrusted/extensions
PKGLIBDIR = $(shell pg_config --pkglibdir)
SHAREDIR = $(shell pg_config --sharedir)/extension
STEALTHDIR = /usr/local/lib/stealthdb


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
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

# App_Cpp_Files := App/App.cpp $(wildcard App/Edger8rSyntax/*.cpp) $(wildcard App/TrustedLibrary/*.cpp)
App_Cpp_Files := $(wildcard common/*.cpp) $(INTERFACE_DIR)/interface.cpp $(INTERFACE_DIR)/encintInterface.cpp $(INTERFACE_DIR)/encfloatInterface.cpp $(INTERFACE_DIR)/encstringInterface.cpp $(INTERFACE_DIR)/enctimestampInterface.cpp # $(wildcard App/TrustedLibrary/*.cpp)
App_C_Files := $(EXTENSION_DIR)/encint.o $(EXTENSION_DIR)/enctimestamp.o $(EXTENSION_DIR)/encfloat.o $(EXTENSION_DIR)/encstring.o $(EXTENSION_DIR)/encdb.o

App_Include_Paths := -IInclude -I$(UNTRUSTED_DIR) -I$(SGX_SDK)/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread 

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_C_Objects := $(App_C_Files:.cpp=.o)


ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: sample
	@echo "Build interface [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the enclave.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo


else
all: $(UNTRUSTED_DIR)/encdb.so
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/sample
	@echo "RUN  =>  sample [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

common/%.o: common/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@ $(App_Link_Flags)
	@echo "CXX  <=  $<"

$(UNTRUSTED_DIR)/enclave_u.c: $(SGX_EDGER8R) trusted/enclave.edl
	@cd $(UNTRUSTED_DIR) && $(SGX_EDGER8R) --untrusted ../trusted/enclave.edl --search-path ../trusted --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(UNTRUSTED_DIR)/enclave_u.o: $(UNTRUSTED_DIR)/enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(INTERFACE_DIR)/%.o: $(INTERFACE_DIR)/%.cpp 
	@$(CXX) $(App_Cpp_Flags) -fPIC -o $@ -c $^
	@echo "CXX interface <=  $<"
	
PSQL_INCLUDEDIRS := -I.
PSQL_INCLUDEDIRS += -I$(shell pg_config --includedir-server)
PSQL_INCLUDEDIRS += -I$(shell pg_config --includedir)
PSQL_LIBDIR = -L$(shell pg_config --libdir)

EXTENSION = $(EXTENSION_DIR)/encdb        # the extensions name
DATA = $(EXTENSION_DIR)/encdb--0.0.1.sql  # script files to install

$(EXTENSION_DIR)/%.o: $(EXTENSION_DIR)/%.c 
	@$(CC) $(App_C_Flags) $(PSQL_INCLUDEDIRS) -o $@ -c $^
	@echo "CC extension <=  $<"
	
$(UNTRUSTED_DIR)/encdb.so: $(UNTRUSTED_DIR)/enclave_u.o $(App_Cpp_Objects) $(App_C_Objects) 
	@$(CC)  $(PSQL_LIBDIR) $^ -shared -o $@ $(App_Link_Flags) -lstdc++ 
	@echo "CC extension <=  $<"
	@echo $(App_Link_Flags)

	
	
.PHONY: clean install

install:	
	cp $(UNTRUSTED_DIR)/encdb.so $(PKGLIBDIR)
	cp $(EXTENSION_DIR)/*.control $(SHAREDIR)
	cp $(EXTENSION_DIR)/*.sql $(SHAREDIR)
	mkdir -p $(STEALTHDIR)
	test -e $(STEALTHDIR)/stealthDB.data || touch $(STEALTHDIR)/stealthDB.data
	chown postgres:postgres $(STEALTHDIR)/stealthDB.data

clean:
	rm -f $(App_Cpp_Objects) $(App_C_Objects) $(UNTRUSTED_DIR)/enclave_u.* 
