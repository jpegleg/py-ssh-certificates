# Python OpenSSH Certificates
A small and simple implementation of OpenSSH Certificates in Python. Generates RSA, ECDSA, ED25519 and DSA(DSS) certificates

# Installation
1. Clone the repository and make sure python3 and python3-pip are installed
2. Run pip3 install -r requirements.txt

# Usage
python3 main.py

# What it does
- Generates two keypairs for each keytype
- Generates a SSH Certificate for each keytype
- Decodes the SSH Certificate and verifies the values

# What it (currently) doesn't
- Validate the certificate signature against a CA pubkey (in-cert or provided)
- Cross-signing of certificates (e.g. ECDSA User and ED25519 CA) (although this is a simple matter of copy and paste to replace the signature part on each certificate. The cert type is based on the user key type)
- Create/verify signed Host keys (although this is a simple matter of changing the certificate type to 2)
- Create/verify FIDO2 (sk-) ED25519/ECSDA keys