# Generate 512 bit Private key
openssl genrsa -out ad_secret_key.pem 2048 # Separate the public part from the Private key file.

openssl rsa -in ad_secret_key.pem -pubout > ad_public_key.pem
