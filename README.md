# Bidirectional Privacy
This repository contains the prototype implementation of the $BPPM$-framework, which provides *Bidirectional Privacy-Preservation with Multi-Layer Data Sharing*.

It is mainly implemented in ***C***-programming language. Intel-SGX is used as the underlying Trusted Execution Environment technology (TEE). Specifically, we use a Microsoft Azure cloud, SGX-enabled, [DC4SV3](https://learn.microsoft.com/en-us/azure/virtual-machines/dcv3-series) instance with an **Ubuntu-20.04** Operating System for performing all our development and experimentation. This implementation is dependent on [Gramine](https://github.com/gramineproject/gramine) shim-library for Intel-SGX related operation and on [MBed-TLS](https://github.com/Mbed-TLS/mbedtls/) library for the cryptographic primitives and network operations.

The involved parties in $BPPM$ are, a data-owner ($DO$), a code-provider ($CP$) and a few data-users distributed among multiple layers. $DU_{i,j}$ denotes the $j^{th}$-data-user of $i^{th}$-layer. $\forall i,j:DU_{i,j}$ requires TEE-enabled platform and others do not require TEE.

## How to prepare the system?
For simplicity, this document assumes all the involved parties (i.e., $DO$, $CP$ and $\forall i,j:DU_{i,j}$) will run on the same physical machine and communicate among themselves using local loopback interface. However, internet reachability of is required for the environment, otherwise attestation procedure may fail.

Following steps are verified in Microsoft Azure cloud, SGX-enabled, DC4SV3 instance with an Ubuntu-20.04 Operating System.


Run the script `./setup.sh` in the terminal to make the system ready.


### Install *Gramine* in your system

At first install *Gramine* in your system. For that, in an terminal, issue the following commands in the specified order:
```
sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
```
```
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
| sudo tee /etc/apt/sources.list.d/gramine.list
```
```
sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
```
```
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" \
| sudo tee /etc/apt/sources.list.d/intel-sgx.list
```
```
sudo apt-get update
```
```
sudo apt-get install gramine
```

If any problem occurs during this stage, then that may be resolved by following [this detailed guide](https://gramine.readthedocs.io/en/latest/installation.html).

### Generate private key for signing the *enclave*

Issue the following command in the terminal to generate *enclave* singing private key.

```
gramine-sgx-gen-private-key
```

### Install *MBedTLS*

To install the proper MBedTLS in your system, first run the following command:

```
sudo apt install libmbedtls-dev
```

### Install required software for compilation

```
sudo apt-get install gcc make
sudo apt install pkg-config
```

TODO...more..

<span style="color: red;">Is it really required? Everthing got compiled, even without this. Then, copy all the content from [this particular folder](https://github.com/Mbed-TLS/mbedtls/tree/08b04b11ff55a96f4021e5622b49e28a09417672/include) and overwrite into ***/user/include/*** directory of your machine.</span> 

### Setup the system for remote attestation
<span style="color: red;">TODO</span>

### Verify installation and setup

Run the Gramin's inbuilt remote attestation examples. Detailed steps regarding how to run those, can be found [here](https://github.com/gramineproject/gramine/tree/master/CI-Examples/ra-tls-mbedtls). If you have successfully set your system, then all the ***DCAP***-related examples should run successfully in SGX-mode.

### Install *libxml2*

Install libxml2, by issuing the following command:

```
sudo apt install libxml2 libxml2-dev
```

## How to run *BPPM*?
To run BPPM, first clone this repository into your machine and compile the source code.

### Compile BPPM
To compile the BPPM source code, goto the poc directory and compile the source using the following commands:

```
cd poc
make
```
In case of successful compilation, something like the following should be shown in the terminal:
```
:
:
measured
    0000000000010000-000000003edfe000 [REG:RWX] (free)
Measurement:
    9861d25aea36d2112c7db40befbc572a6f1a377b706e78862fcfb4019eb08031
cc src/data_user/data_user.c -O0 -ggdb3 -D ENC_DEF_LOG_LVL=ENCLAVE_LOG_LVL_MIN -D DU_DEF_LOG_LVL=DU_LOG_LVL_MIN -D DO_DEF_LOG_LVL=DO_LOG_LVL_MIN -D CP_DEF_LOG_LVL=CP_LOG_LVL_MIN -fPIE -I/usr/include/gramine -I/usr/include/gramine -I/usr/include/libxml2/ -I./src/include/ -lxml2 -pie -ldl -Wl,--enable-new-dtags -Wl,-rpath,/usr/lib/x86_64-linux-gnu -Wl,--start-group -lmbedcrypto_gramine -lmbedtls_gramine -lmbedx509_gramine -Wl,--end-group -o data_user
cc src/code_provider/code_provider.c -O0 -ggdb3 -D ENC_DEF_LOG_LVL=ENCLAVE_LOG_LVL_MIN -D DU_DEF_LOG_LVL=DU_LOG_LVL_MIN -D DO_DEF_LOG_LVL=DO_LOG_LVL_MIN -D CP_DEF_LOG_LVL=CP_LOG_LVL_MIN -fPIE -I/usr/include/gramine -I/usr/include/gramine -I/usr/include/libxml2/ -I./src/include/ -lxml2 -pie -ldl -Wl,--enable-new-dtags -Wl,-rpath,/usr/lib/x86_64-linux-gnu -Wl,--start-group -lmbedcrypto_gramine -lmbedtls_gramine -lmbedx509_gramine -Wl,--end-group -o code_provider
```
Now note down the details of the newly generated enclave in the current directory, by issuing the following command:

```
gramine-sgx-sigstruct-view enclave.sig
```
It will show something like the following.

```
Attributes:
    mr_signer: 38ec81599b6bcd18ee8cce9cbe3e724aeeb8c0def65c410bd569470584365ea1
    mr_enclave: 9861d25aea36d2112c7db40befbc572a6f1a377b706e78862fcfb4019eb08031
    isv_prod_id: 0
    isv_svn: 0
    debug_enclave: False
```
Note down the observed *mr_signer* and *mr_enclave* values and update *MRENCLAVE_STR* and *MRSIGNER_STR* macros in the *src/include/enclave_details.h* file with those exact same values.

```
#define MRENCLAVE_STR "38ec81599b6bcd18ee8cce9cbe3e724aeeb8c0def65c410bd569470584365ea1"
#define MRSIGNER_STR "9861d25aea36d2112c7db40befbc572a6f1a377b706e78862fcfb4019eb08031"
```
Then again, we have to re-compile everything again with the following command.
```
make clean
make
```

### Walkthough of BPPM
TODO: Walkthorough related log level.\
TODO: Walkthorough picture.

To walkthrough the execution of BPPM, in same terminal first export a couple of environmental variables using the following commands:

```
export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1
export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1
export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1
export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1
export AZDCAP_DEBUG_LOG_LEVEL=ERROR
export AZDCAP_COLLATERAL_VERSION=v3
```
Then run the script: `sample_protocol_walkthrough.sh` to execute a walkthrough of BPPM. The terminal should show something like this:

```
:
TODO
```
Alternatively, the same thing can be achieved by performing the steps manually.
i.e.,

