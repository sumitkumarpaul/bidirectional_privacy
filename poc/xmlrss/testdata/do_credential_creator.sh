# Generate 512 bit Private key
openssl genrsa -out do_secret_key.pem 2048 # Separate the public part from the Private key file.

openssl rsa -in do_secret_key.pem -pubout > do_public_key.pem

openssl dgst -sha256 -sign do_secret_key.pem -out redkey.sign redkey.obj

openssl dgst -verify do_public_key.pem -sha256 -signature redkey.sign redkey.obj