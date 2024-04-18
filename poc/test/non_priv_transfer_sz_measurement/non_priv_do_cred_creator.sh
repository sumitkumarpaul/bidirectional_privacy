# Generate 512 bit Private key
#openssl genrsa -out non_priv_do_secret_key.pem 2048 # Separate the public part from the Private key file.

#openssl rsa -in non_priv_do_secret_key.pem -pubout > non_priv_do_public_key.pem

# Generate credentials for DO
openssl genpkey -algorithm RSA -out non_priv_do_secret_key.pem
openssl req -new -key non_priv_do_secret_key.pem -out non_priv_do.csr
openssl x509 -req -days 3650 -in non_priv_do.csr -signkey non_priv_do_secret_key.pem -out non_priv_do_cert.pem


# Generate credentials for DU
openssl genpkey -algorithm RSA -out non_priv_du_secret_key.pem
openssl req -new -key non_priv_du_secret_key.pem -out non_priv_du.csr
openssl x509 -req -days 3650 -in non_priv_du.csr -signkey non_priv_du_secret_key.pem -out non_priv_du_cert.pem


