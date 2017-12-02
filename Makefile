UNTRUSTED_MK:= src/untrusted.mk
ENCLAVE_MK:= src/enclave.mk

.PHONY: all clean install remove

all clean install remove:
	$(MAKE) -C $(shell dirname $(UNTRUSTED_MK)) -f $(shell basename $(UNTRUSTED_MK)) $@
	$(MAKE) -C $(shell dirname $(ENCLAVE_MK)) -f $(shell basename $(ENCLAVE_MK)) $@
