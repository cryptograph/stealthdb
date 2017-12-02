include vars.mk

######## App Settings ########

C_Files := $(wildcard $(EXTENSION_DIR)/*.c)
C_Objects := $(C_Files:.c=.o)

Cpp_Files := $(wildcard utils/*.cpp) $(wildcard $(INTERFACE_DIR)/*.cpp)
Cpp_Objects := $(Cpp_Files:.cpp=.o)

INC:= include $(UNTRUSTED_DIR) $(SGX_SDK)/include

INCFLAGS:=$(INC:%=-I%)
CFLAGS := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(INCFLAGS)
CXXFLAGS := $(CFLAGS) -std=c++11
LDFLAGS := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread

.PHONY: all

all: $(UNTRUSTED_DIR)/encdb.so

######## App Objects ########

utils/%.o: utils/%.cpp
	@$(CXX) $(CXXFLAGS) -c $< -o $@ $(LDFLAGS)
	@echo "CXX  <=  $<"

$(UNTRUSTED_DIR)/enclave_u.c: $(SGX_EDGER8R) $(ENCLAVE_DIR)/enclave.edl
	@cd $(UNTRUSTED_DIR) && $(SGX_EDGER8R) --untrusted ../$(ENCLAVE_DIR)/enclave.edl --search-path ../$(ENCLAVE_DIR) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(UNTRUSTED_DIR)/enclave_u.o: $(UNTRUSTED_DIR)/enclave_u.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

$(INTERFACE_DIR)/%.o: $(INTERFACE_DIR)/%.cpp
	@$(CXX) $(CXXFLAGS) -fPIC -o $@ -c $^
	@echo "CXX interface <=  $<"
	
PSQL_INCLUDEDIRS := -I.
PSQL_INCLUDEDIRS += -I$(shell pg_config --includedir-server)
PSQL_INCLUDEDIRS += -I$(shell pg_config --includedir)
PSQL_LIBDIR = -L$(shell pg_config --libdir)

EXTENSION = $(EXTENSION_DIR)/encdb        # the extension's name
DATA = $(EXTENSION_DIR)/encdb--0.0.1.sql  # scripts to install

$(EXTENSION_DIR)/%.o: $(EXTENSION_DIR)/%.c
	@$(CC) $(CFLAGS) $(PSQL_INCLUDEDIRS) -o $@ -c $^
	@echo "CC extension <=  $<"
	
$(UNTRUSTED_DIR)/encdb.so: $(UNTRUSTED_DIR)/enclave_u.o $(Cpp_Objects) $(C_Objects)
	@$(CC)  $(PSQL_LIBDIR) $^ -shared -o $@ $(LDFLAGS) -lstdc++
	@echo "CC extension <=  $<"
	@mkdir -p ../$(RUNTIME_DIR)
	@mv $(UNTRUSTED_DIR)/encdb.so ../$(RUNTIME_DIR)
	@cp $(EXTENSION_DIR)/*.control ../$(RUNTIME_DIR)
	@cp $(EXTENSION_DIR)/*.sql ../$(RUNTIME_DIR)
	
.PHONY: clean install

install:	
	cp ../$(RUNTIME_DIR)/encdb.so $(PKGLIBDIR)
	cp ../$(RUNTIME_DIR)/*.control $(SHAREDIR)
	cp ../$(RUNTIME_DIR)/*.sql $(SHAREDIR)
	@mkdir -p $(STEALTHDIR)
	@test -e $(STEALTHDIR)/stealthDB.data || touch $(STEALTHDIR)/stealthDB.data
	@chown postgres:postgres $(STEALTHDIR)/stealthDB.data

remove: 
	rm -r $(STEALTHDIR)
	rm $(PKGLIBDIR)/encdb.so
	rm $(SHAREDIR)/encdb.control
	rm $(SHAREDIR)/encdb--0.0.1.sql 
	@rm -f $(Cpp_Objects) $(C_Objects) $(UNTRUSTED_DIR)/enclave_u.*
	
clean:
	@rm -f $(Cpp_Objects) $(C_Objects) $(UNTRUSTED_DIR)/enclave_u.*
