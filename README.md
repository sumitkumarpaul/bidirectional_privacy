# Bidirectional Privacy
This repository contains the prototype implementation of the $BPPM$-framework, which provides *Bidirectional Privacy-Preservation with Multi-Layer Data Sharing*.

The involved parties in $BPPM$ are, a data-owner ($DO$), a code-provider ($CP$) and a few data-users distributed among multiple layers. $DU_{i,j}$ denotes the $j^{th}$-data-user of $i^{th}$-layer. $\forall i,j:DU_{i,j}$ requires an environment having support of the, Trusted Execution Environment (TEE) and others do not require TEE.

$BPPM$ is mainly implemented in ***C***-programming language. This implementation is dependent on [Gramine](https://github.com/gramineproject/gramine) shim-library for TEE related operations and on [MBed-TLS](https://github.com/Mbed-TLS/mbedtls/) library for the cryptographic primitives and network operations. **Intel-SGX** is used as the underlying TEE. Specifically, for performing all our development, experimentation and performance measurement purpose, we use an SGX-enabled instance, [DC4SV3](https://learn.microsoft.com/en-us/azure/virtual-machines/dcv3-series) in Microsoft Azure cloud. We use **Ubuntu-20.04** Operating System, in that environment.

## 1. How to create the system?
Intel-SGX enabled VM can be created in Microsoft-Azure, by following [this guide line](https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-portal). After creating the system, enable the remote attestation by following [this link](https://learn.microsoft.com/en-us/azure/attestation/quickstart-powershell). This [text](https://learn.microsoft.com/en-us/azure/security/fundamentals/trusted-hardware-identity-management) might also be useful.

If you already have a SGX-enabled system, then this step is not required.

## 2. How to prepare the system?
A simple working environment can be created by running all the involved parties (i.e., $DO$, $CP$ and $\forall i,j:DU_{i,j}$) on the same enviroment and enable communication among themselves using local loopback interface. However, internet reachability of is required for the environment, otherwise the remote-attestation procedure may fail.

All the steps required to prepare a Microsoft Azure cloud, SGX-enabled, DC4SV3 instance with an Ubuntu-20.04 Operating System, is encoded into a bash script. So, to prepare the system, first open a new terminal and run the following script:

```
./setup.sh
```

It should complete its execution, without any error.

In other environment, please perform the follwing steps in the proper order.
### 2.1 Install *Gramine* in your system

How to install *Gramine* in your system can be found in [this detailed guide](https://gramine.readthedocs.io/en/latest/installation.html).

### 2.2 Generate private key for signing the *enclave*

Issue the following command in the terminal to generate *enclave* singing private key.

```
gramine-sgx-gen-private-key
```

### 2.3 Install *MBedTLS*

To install the proper MBedTLS in your system, run the following command:

```
sudo apt install libmbedtls-dev
```

### 2.4 Install required software for compilation

Some additional software and libraries are required for compilation of the source code, install them run the following command:

```
sudo apt-get install gcc make
sudo apt install pkg-config
sudo apt install libxml2 libxml2-dev
```
<!--
TODO...more..

<span style="color: red;">Is it really required? Everthing got compiled, even without this. Then, copy all the content from [this particular folder](https://github.com/Mbed-TLS/mbedtls/tree/08b04b11ff55a96f4021e5622b49e28a09417672/include) and overwrite into ***/user/include/*** directory of your machine.</span> 
-->

### 3. Verify installation and setup

Before proceeding further, it is now important to verify that everything setup till now are fine. Specifically, it is important to ensure that an *enclave* can run in the system in real-SGX mode. Moreover, it must be ensured that, that the remote attestation works properly with that *enclave*.

To verify thes, run the *Gramine*'s inbuilt remote attestation examples in the newly set environment. Detailed steps regarding how to run those, can be found [here](https://github.com/gramineproject/gramine/tree/master/CI-Examples/ra-tls-mbedtls). If you have successfully set your system, then all the ***DCAP***-related examples should run successfully in ***SGX***-mode.

## 4. How to run *BPPM*?
To run $BPPM$, first compile the source code and then run its different components according to some desired workflow.

### 4.1 Compile *BPPM*
To compile the $BPPM$ source code, goto the ***poc*** directory and compile the source using the following commands:

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
Now note down the details of the newly generated *enclave* in the current directory, by issuing the following command:

```
gramine-sgx-sigstruct-view enclave.sig
```
It should show something like the following. However, the hexadecimal strings must be different, in your system.

```
Attributes:
    mr_signer: 38ec81599b6bcd18ee8cce9cbe3e724aeeb8c0def65c410bd569470584365ea1
    mr_enclave: 9861d25aea36d2112c7db40befbc572a6f1a377b706e78862fcfb4019eb08031
    isv_prod_id: 0
    isv_svn: 0
    debug_enclave: False
```
Note down the observed *mr_signer* and *mr_enclave* values and update *MRENCLAVE_STR* and *MRSIGNER_STR* macros in the *src/include/enclave_details.h* file with those values.

```
:
#define MRENCLAVE_STR "38ec81599b6bcd18ee8cce9cbe3e724aeeb8c0def65c410bd569470584365ea1"
#define MRSIGNER_STR "9861d25aea36d2112c7db40befbc572a6f1a377b706e78862fcfb4019eb08031"
:
```
Then again, the entire source code is required to be re-compiled with the following command.
```
make clean
make
```

### 4.2 Run a sample walkthough of $BPPM$
$BPPM$ can be used with different workflows and with different layouts of the data usage tree. The following diagram shows a sample walkthorugh. Supposes, there are only two data users $DU_{1,1}$ and $DU_{2,1}$, residing in two different layers. $DO$ provides some personal data to $DU_{1,1}$. $DU_{1,1}$ can perform some computation on that locally or can forward that to the next layer-data user,$DU_{2,1}$. \
![Alt text](diagrams/Walkthrough.png?raw=true "Sample walkthorugh of BPPM")
At first, $DU_{1,1}$ and $DU_{2,1}$ setup their *enclave*. During this time, the $CP$ sends the required code components to those *enclave*s in piracy-protected way. Then $DO$, sends her personal data to $DU_{1,1}$. $DU_{1,1}$ performs some data processing and then forwards the data to $DU_{2,1}$ with reduced consent. Finally, $DU_{2,1}$ performs some data processing in its location.\
\
To facilitate the above mentioned walkthrough, a script is already prepared (`sample_protocol_walkthrough.sh`), which executes different parties in the proper order. Before running the script, couple of environmental variables must be exported in the terminal, by issuing the following commands:

```
export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1
export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1
export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1
export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1
export AZDCAP_DEBUG_LOG_LEVEL=ERROR
export AZDCAP_COLLATERAL_VERSION=v3
```
Then run the script: `sample_protocol_walkthrough.sh` to execute the walkthrough.

```
./sample_protocol_walkthrough.sh
```

The involved parites must print the transcript in the terminal. On success, the terminal should show something like this:

```
:
[ENC: 0002810]  [23-05-2024 19:27:13.709301] Waiting for receiving the data and consent
[ENC: 0002763]  [23-05-2024 19:27:14.711234] Forwarding data (did: 0) after removing: 20 data processing statements
[ENC: 0002810]  [23-05-2024 19:27:14.902936] Processed data (did: 0) according to processing statement ID: 1, the result is: 793406281
```
### 4.3 Measure different performance matrices of $BPPM$
To measure its performance first compile it in release mode. Steps required for compilation are [already mentioned](#41-compile-bppm). But to compile $BPPM$ in release mode, instead of using `make`, use `make DEBUG=0`.

Then export the required environment variables, by issuing the following commands.

```
export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1
export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1
export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1
export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1
export AZDCAP_DEBUG_LOG_LEVEL=ERROR
export AZDCAP_COLLATERAL_VERSION=v3
```
Then run the following script in the terminal, and follow the on-terminal instructions.

```
./perf_measurement.sh 100 n
```

It will take a long time. Maybe 6-8 hours. On success it should show something like the following.

```
============================================================================================================
Started performance measurement of BPPM
Please wait, it will take considerable amount of time...

Performance measurement completed..!! Open the folder Perf_log_23_05_2024_20-08-03/ for detailed reports.
============================================================================================================
```
