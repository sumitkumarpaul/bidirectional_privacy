# Create the private key of Data-issuer
#openssl genrsa -out sample_di_pri_key.pem 3072

# Create the self-signed certificate of the data-issuer
#openssl req -x509 -sha256 -new -nodes -key sample_di_pri_key.pem -days 3650 -out sample_di_cert.pem -subj "/C=XY/ST=Some-state/L=Some-locality/O=Trusted organization/CN=Trusted-data-issuer"

# Show the details of the data-issuer certificate
#openssl x509 -in sample_di_cert.pem -text

# Create a new certificate signing-request for the data owner's data-certificate
openssl req -new -key sample_do_pri_key.pem -out sample_do_pri_data.csr -config  sample_do_pri_data.conf

# Create a new private data-certificate for the data-owner, signed by the data-issuer
openssl x509 -req -in sample_do_pri_data.csr -CA sample_di_cert.pem -CAkey sample_di_pri_key.pem -CAcreateserial -out sample_do_pri_data_cert.pem -extensions v3_req -extfile sample_do_pri_data.conf -set_serial 01
# Show the details of the data-owner's private data-certificate
openssl x509 -inform pem -noout -text -in 'sample_do_pri_data_cert.pem'

# Verify the newly generated data-owner's private data certificate with the data-issuer certificate
openssl verify -verbose -CAfile sample_di_cert.pem  sample_do_pri_data_cert.pem
