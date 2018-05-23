UNTRUSTED_MK:= src/untrusted.mk
ENCLAVE_MK:= src/enclave.mk

.PHONY: all
all:
	$(MAKE) -C $(shell dirname $(UNTRUSTED_MK)) -f $(shell basename $(UNTRUSTED_MK)) $@
	$(MAKE) -C $(shell dirname $(ENCLAVE_MK)) -f $(shell basename $(ENCLAVE_MK)) $@

.PHONY: docker
docker:
	docker build -f docker/Dockerfile -t stealthdb:1.0 docker/
	docker run -it -d --rm --device=/dev/isgx --volume=/var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket -p 5432:5432 --name sdb stealthdb:1.0

.PHONY: install
install:
	$(MAKE) -C $(shell dirname $(UNTRUSTED_MK)) -f $(shell basename $(UNTRUSTED_MK)) $@
	$(MAKE) -C $(shell dirname $(ENCLAVE_MK)) -f $(shell basename $(ENCLAVE_MK)) $@

.PHONY: clean
clean:
	$(MAKE) -C $(shell dirname $(UNTRUSTED_MK)) -f $(shell basename $(UNTRUSTED_MK)) $@
	$(MAKE) -C $(shell dirname $(ENCLAVE_MK)) -f $(shell basename $(ENCLAVE_MK)) $@
	$(RM) -r build
