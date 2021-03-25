# rsa-wrap

# Generate RSA Private Key
- openssl genrsa -out private-key.pem 2048

# Generate AES Key
- openssl rand 32 > aes-key.key

# Convert RSA Private Key to PKCS#8 format
- openssl pkcs8 -topk8 -inform PEM -outform DER -in private-key.pem -out private-key.der -nocrypt

# Use rsa-wrap utility to wrap key material using "RsaOaepAesSha256" algorithm mechanism.
- java -jar rsa-wrap.jar <wrapping-public-key.pem> <RSA-private-key-pkcs8 OR AES-key> <wrapped-output-key-file>
- java -jar rsa-wrap.jar wrapping-key.pem private-key.der wrapped-key.bin
