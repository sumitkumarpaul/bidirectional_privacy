#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
#
# TODO: What will be the copyright? This file is modified from original one
# Ideally, this compilation should not depend on Intel SGX SDK. However, for
# the time being, for demonstration proof of concept level, this dependency
# is not removed.

SGX_SDK ?= /opt/intel/sgxsdk
SGX_COMMON_CFLAGS := -m64
SGX_DEBUG ?= 1
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
Urts_Library_Name := sgx_urts
Include_Path := -I. -I$(SGX_SDK)/include -I/usr/include/openssl 
Cpp_Flags := -DCLIENT_USE_QVL $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Include_Path)
TARGET ?= u_data_owner
SRC_DIRS ?= ./src/
CERT_DIR ?= ./materials
U_DU_IP ?= 127.0.0.1
U_DU_PORT ?= 1235
LIBENC_IP ?= 127.0.0.1 
LIBENC_PORT ?= 1234
SRV_REQ_ID ?= 1
DO_CERT ?= ./materials/sample_do_cert.pem
DO_PRI_KEY ?= ./materials/sample_do_pri_key.pem
DO_PRI_DATA_FILE ?= ../test_data_creater/data_cert/sample_do_data_1000_attr.pem
EXP_TIME ?= 2308185037

SRCS := $(shell find $(SRC_DIRS) -name *.cpp -or -name *.c -or -name *.s)
OBJS := $(addsuffix .o,$(basename $(SRCS)))
DEPS := $(OBJS:.o=.d)

INC_DIRS := $(shell find $(SRC_DIRS) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))
ifeq ($(SGX_DEBUG), 1)
	Cpp_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	Cpp_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Cpp_Flags += -std=c++11
# Change this value according to your desired log-level
Cpp_Flags += -DLOG_LEVEL=DEBUG_LEVEL_ERROR

Link_Flags := $(SGX_COMMON_CFLAGS) -L. -lssl \
	-L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lsgx_utls \
	-lsgx_dcap_ql -lsgx_dcap_quoteverify -lcrypto

.PHONY: all build clean test

all: build

build:
	$(CXX) -c $(Cpp_Flags) $(SRCS)
	mv *.o $(SRC_DIRS)
	$(CXX) -o $(TARGET) $(OBJS) $(Link_Flags)

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)
	$(RM) ./materials/enc.*


.PHONY: cert_create
cert_create:
	@echo "It will a new certificate, private and public key in the "$(CERT_DIR)" directory, if it is not already present"
	# generate a private key with the correct length
	openssl genrsa -out $(CERT_DIR)/sample_do_pri_key.pem -3 3072
	sudo chmod +r $(CERT_DIR)/sample_do_pri_key.pem
	
	# generate corresponding public key
	openssl rsa -in $(CERT_DIR)/sample_do_pri_key.pem -pubout -out $(CERT_DIR)/sample_do_pub_key.pem
	
	# Create a self-signed certificate
	openssl req -new -x509 -key $(CERT_DIR)/sample_do_pri_key.pem -out $(CERT_DIR)/sample_do_cert.pem -days 3600 -subj "/C=XY/ST=Some state/L=Some location/O=Some organization/CN=Data-Owner 1"


.PHONY: cert_del
cert_del:
	@echo "It will delete the certificates from "$(CERT_DIR)" directory"
	$(RM) $(CERT_DIR)/sample_do*

.PHONY: data_req_create
data_req_create:
	openssl req -new -key $(CERT_DIR)/sample_do_pri_key.pem -out $(CERT_DIR)/private_data/sample_do_pri_data.csr -config  $(CERT_DIR)/private_data/sample_do_pri_data.conf
	@echo "Content of the data-details file: ("$(CERT_DIR)"/private_data/sample_do_pri_data.conf) is:"
	@cat "$(CERT_DIR)"/private_data/sample_do_pri_data.conf
	@echo "Generated new data request according to the above mentioned data-details file\nSubmit this newly generated "$(CERT_DIR)"/private_data/sample_do_pri_data.csr file to the data-issure to get a new certified data file"

.PHONY: test
test:
	@echo Running the program as:./u_data_owner "$(U_DU_IP)" "$(U_DU_PORT)" "$(DO_PRI_DATA_FILE)" "$(EXP_TIME)"
	./u_data_owner "$(U_DU_IP)" "$(U_DU_PORT)" "$(DO_PRI_DATA_FILE)" "$(EXP_TIME)"

