ALL_UNTRUSTED_MK=$(shell find . -name '*untrusted.mk')
ALL_TRUSTED_MK=$(shell find . -name '*enclave.mk')

.PHONY: all clean run install

all clean install:
	$(foreach U_MK, $(ALL_UNTRUSTED_MK), $(MAKE) -C $(shell dirname $(U_MK)) -f $(shell basename $(U_MK)) $@;)
	$(foreach T_MK, $(ALL_TRUSTED_MK), $(MAKE) -C $(shell dirname $(T_MK))  -f $(shell basename $(T_MK)) $@;)

run:
	$(foreach U_MK, $(ALL_UNTRUSTED_MK), $(MAKE) -C $(shell dirname $(U_MK))   -f $(shell basename $(U_MK)) $@;)

