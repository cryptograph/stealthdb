include vars.mk

C_SRCS := $(wildcard $(EXTENSION_DIR)/*.c)
C_OBJS := $(C_SRCS:.c=.o)

CXX_SRCS := $(wildcard utils/*.cpp) $(wildcard $(INTERFACE_DIR)/*.cpp)
CXX_OBJS := $(CXX_SRCS:.cpp=.o)

INC:= include $(SGX_INCLUDE_PATH) $(UNTRUSTED_DIR)

INCFLAGS:=$(INC:%=-I%)
CPPFLAGS := -DTOKEN_FILENAME=\"$(STEALTHDIR)/$(ENCLAVE_NAME).token\" \
			-DENCLAVE_FILENAME=\"$(STEALTHDIR)/$(ENCLAVE_NAME).signed.so\" \
			-DDATA_FILENAME=\"$(STEALTHDIR)/stealthDB.data\"
CFLAGS := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(INCFLAGS)
CXXFLAGS := $(CFLAGS) $(CPPFLAGS) -std=c++11
LDFLAGS := $(SGX_COMMON_CFLAGS) -l$(SGX_URTS) -lpthread

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
	
$(UNTRUSTED_DIR)/encdb.so: $(UNTRUSTED_DIR)/enclave_u.o $(CXX_OBJS) $(C_OBJS)
	@$(CC)  $(PSQL_LIBDIR) $^ -shared -o $@ $(LDFLAGS) -lstdc++
	@echo "CC extension <=  $<"
	@mkdir -p $(BUILD_DIR)
	@mv $(UNTRUSTED_DIR)/encdb.so $(BUILD_DIR)
	@cp $(EXTENSION_DIR)/*.control $(BUILD_DIR)
	@cp $(EXTENSION_DIR)/*.sql $(BUILD_DIR)
	
.PHONY: clean install uninstall

install:
	cp $(BUILD_DIR)/encdb.so $(PSQL_PKG_LIBDIR)
	cp $(BUILD_DIR)/*.control $(PSQL_SHAREDIR)
	cp $(BUILD_DIR)/*.sql $(PSQL_SHAREDIR)
	@mkdir -p $(STEALTHDIR)
	@test -e $(STEALTHDIR)/stealthDB.data || touch $(STEALTHDIR)/stealthDB.data
	@chown postgres:postgres $(STEALTHDIR)/stealthDB.data

uninstall:
	$(RM) $(PSQL_PKG_LIBDIR).encdb.so $(PSQL_SHAREDIR)/*.control $(PSQL_SHAREDIR)/*.sql
	$(RM) -r $(STEALTHDIR)

clean:
	@$(RM) $(CXX_OBJS) $(C_OBJS) $(UNTRUSTED_DIR)/enclave_u.*
