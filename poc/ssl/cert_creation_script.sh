openssl req -new -x509 -key ca.key -out ca.crt -days 36500 -config ca_config.conf
openssl req -new -key enclave.key -out enclave.csr -config ca_config.conf
openssl x509 -req -in enclave.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out enclave.crt -days 36500 -extfile ca_config.conf
