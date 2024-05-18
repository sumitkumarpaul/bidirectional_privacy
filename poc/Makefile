ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
CFLAGS += -O0 -ggdb3 -D ENC_DEF_LOG_LVL=ENCLAVE_LOG_LVL_ALL -D DU_DEF_LOG_LVL=DU_LOG_LVL_ALL -D DO_DEF_LOG_LVL=DO_LOG_LVL_ALL -D CP_DEF_LOG_LVL=CP_LOG_LVL_ALL
else ifeq ($(DEBUG),0)
GRAMINE_LOG_LEVEL = error
CFLAGS += -O2 -D ENC_DEF_LOG_LVL=ENCLAVE_LOG_LVL_PERF_RSLT -D DU_DEF_LOG_LVL=DU_LOG_LVL_PERF_RSLT -D DO_DEF_LOG_LVL=DO_LOG_LVL_PERF_RSLT -D CP_DEF_LOG_LVL=CP_LOG_LVL_PERF_RSLT
else
GRAMINE_LOG_LEVEL = error
CFLAGS += -O0 -ggdb3 -D ENC_DEF_LOG_LVL=ENCLAVE_LOG_LVL_MIN -D DU_DEF_LOG_LVL=DU_LOG_LVL_MIN -D DO_DEF_LOG_LVL=DO_LOG_LVL_MIN -D CP_DEF_LOG_LVL=CP_LOG_LVL_MIN
endif

CFLAGS += -fPIE
LDFLAGS += -pie

RA_TYPE ?= dcap
RA_CLIENT_SPID ?=
RA_CLIENT_LINKABLE ?= 0

.PHONY: all
all: do eclv du cp

.PHONY: do
do: data_owner

.PHONY: eclv_only
eclv_only: enclave

.PHONY: eclv
eclv: ssl/enclave.crt enclave.manifest.sgx enclave.sig

.PHONY: du
du: data_user

.PHONY: cp
cp: code_provider

.PHONY: app
app: ssl/enclave.crt enclave.manifest.sgx enclave.sig client

.PHONY: epid
epid: client_epid.manifest.sgx client_epid.sig

.PHONY: dcap
dcap: client_dcap.manifest.sgx client_dcap.sig

############################# SSL DATA DEPENDENCY #############################

# SSL data: key and x.509 self-signed certificate
ssl/enclave.crt: ssl/ca_config.conf
	openssl genrsa -out ssl/ca.key 2048
	openssl req -x509 -new -nodes -key ssl/ca.key -sha256 -days 1024 -out ssl/ca.crt -config ssl/ca_config.conf
	openssl genrsa -out ssl/enclave.key 2048
	openssl req -new -key ssl/enclave.key -out ssl/enclave.csr -config ssl/ca_config.conf
	openssl x509 -req -days 360 -in ssl/enclave.csr -CA ssl/ca.crt -CAkey ssl/ca.key -CAcreateserial -out ssl/enclave.crt

######################### CLIENT/SERVER EXECUTABLES ###########################

CFLAGS += $(shell pkg-config --cflags mbedtls_gramine) \
          $(shell pkg-config --cflags ra_tls_gramine)

#### Sumit added
CFLAGS += -I/usr/include/libxml2/ -I./src/include/
CFLAGS += -lxml2

# no need for `pkg-config --libs ra_tls_gramine` because programs use dlopen
LDFLAGS += -ldl -Wl,--enable-new-dtags $(shell pkg-config --libs mbedtls_gramine)

enclave: src/enclave/enclave.c src/include/enclave_details.h
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

data_user: src/data_user/data_user.c src/include/enclave_details.h
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

data_owner: src/data_owner/data_owner.c src/include/enclave_details.h
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

code_provider: src/code_provider/code_provider.c src/include/enclave_details.h
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

############################### SERVER MANIFEST ###############################

enclave.manifest: enclave.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
enclave.manifest.sgx enclave.sig: sgx_sign_enclave
	@:

.INTERMEDIATE: sgx_sign_enclave
sgx_sign_enclave: enclave.manifest enclave
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

############################### SGX CHECKS FOR CI #############################

.PHONY: check_epid
check_epid: app epid
	gramine-sgx enclave & SERVER_ID=$$!; \
	sleep 30; \
	./client epid > OUTPUT; \
	./client epid 0 0 0 0 >> OUTPUT; \
	kill -9 $$SERVER_ID
	@grep -q "using default SGX-measurement verification callback" OUTPUT && echo "[ Success 1/4 ]"
	@grep -q "using our own SGX-measurement verification callback" OUTPUT && echo "[ Success 2/4 ]"
	@grep -q "Verifying peer X.509 certificate... ok" OUTPUT && echo "[ Success 3/4 ]"
	@(exit `grep -c "failed" "OUTPUT"`) && echo "[ Success 4/4 ]"
	@rm OUTPUT

.PHONY: check_epid_fail
check_epid_fail: app epid
	gramine-sgx enclave --test-malicious-quote >/dev/null & SERVER_ID=$$!; \
	sleep 30; \
	./client epid && exit 1 || echo "[ Success 1/1 ]"; \
	kill -9 $$SERVER_ID

.PHONY: check_dcap
check_dcap: app dcap
	gramine-sgx enclave >/dev/null & SERVER_ID=$$!; \
	sleep 30; \
	./client dcap > OUTPUT; \
	./client dcap 0 0 0 0 >> OUTPUT; \
	kill -9 $$SERVER_ID
	@grep -q "using default SGX-measurement verification callback" OUTPUT && echo "[ Success 1/4 ]"
	@grep -q "using our own SGX-measurement verification callback" OUTPUT && echo "[ Success 2/4 ]"
	@grep -q "Verifying peer X.509 certificate... ok" OUTPUT && echo "[ Success 3/4 ]"
	@(exit `grep -c "failed" "OUTPUT"`) && echo "[ Success 4/4 ]"
	@rm OUTPUT

.PHONY: check_dcap_fail
check_dcap_fail: app dcap
	gramine-sgx enclave --test-malicious-quote >/dev/null & SERVER_ID=$$!; \
	sleep 30; \
	./client dcap && exit 1 || echo "[ Success 1/1 ]"; \
	kill -9 $$SERVER_ID

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) -r \
		*.token *.sig *.manifest.sgx *.manifest enclave data_user data_owner code_provider client *.so.* enc/received_code/*.so enc/*.xml OUTPUT
		#*.token *.sig *.manifest.sgx *.manifest enclave client *.so *.so.* OUTPUT

.PHONY: distclean
distclean: clean
	$(RM) -r ssl/ca.* ssl/enclave.*
