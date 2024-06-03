# Install Curl first
sudo apt-get install -y curl

# Install Gramine

sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/gramine.list
sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
sleep 2
sudo apt-get update
sleep 2
sudo apt-get install -y gramine

# Generate enclave signing-key
gramine-sgx-gen-private-key

# Prepare the system for remote attestation
sudo apt install -y sgx-aesm-service 
sudo apt install -y libsgx-aesm-launch-plugin 
sudo apt install -y libsgx-aesm-quote-ex-plugin 
sudo apt install -y libsgx-aesm-ecdsa-plugin 
sudo apt install -y libsgx-dcap-quote-verify
sudo apt remove -y libsgx-dcap-default-qpl
# Install DCAP client
wget https://packages.microsoft.com/ubuntu/20.04/prod/pool/main/a/az-dcap-client/az-dcap-client_1.12.0_amd64.deb
mkdir ~/.az-dcap-client
sudo dpkg -i az-dcap-client_1.12.0_amd64.deb
rm az-dcap-client_1.12.0_amd64.deb

# Install other required softwares for compilation
sudo apt-get install -y gcc make
sudo apt install -y pkg-config
sudo apt install -y libxml2 libxml2-dev
#sudo apt -y libmbedtls-dev