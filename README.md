# Python OpenSSH Certificates
A small and simple implementation of OpenSSH Certificates in Python. Generates RSA, ECDSA, ED25519 and DSA certificates

# Installation
1. Clone the repository and make sure python3 and python3-pip are installed
2. Run pip3 install -r requirements.txt

# Usage
python3 main.py

# What it does
- Generates two keypairs for each keytype
- Generates a SSH Certificate for each keytype
- Decodes the SSH Certificate and verifies the values
- (Validates the signature) Upcoming