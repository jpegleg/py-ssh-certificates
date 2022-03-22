import os
from time import time as timestamp
from base64 import b64encode, b64decode
import sshcert_utils as utils

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric import padding

def make_rsa_certificate(
        user_pubkey_path: str, 
        ca_pubkey_path: str, 
        ca_privkey_path: str, 
        ca_privkey_pass: str = "password",
        attributes: dict = {}
    ):
    
    
    # Load the user public key
    with open(user_pubkey_path, 'rb') as f:
        user_pubkey = serialization.load_ssh_public_key(f.read(), default_backend())
        user_pub_numbers = user_pubkey.public_numbers()
    
    # Load the key data for the CA Public Key
    # For this, we just need the entire key data in byte format
    with open(ca_pubkey_path, 'r') as f:
        ca_pubkey = b64decode(f.read().split(' ')[1])
        
    # Load the data for the CA Private key as bytes
    with open(ca_privkey_path, 'rb') as f:
        ca_privkey = f.read()
          
    
    # Create an empty Bytes object
    certificate = b''
    
    # Add the certificate type
    # This is based on the users certificate type
    # For RSA, this is usually ssh-rsa-cert-v01@openssh.com
    certificate += utils.encode_string(b'ssh-rsa-cert-v01@openssh.com')
    
    # Add the nonce
    # This is the random part of the certificate which is used
    # to prevent hash collision attacks against the CA private key
    # Even though not as important as with ECDSA, it is still bad practice to re-use nonces
    # since it increases the likelihood of hash collision attacks
    nonce = utils.generate_secure_nonce(32)
    certificate += utils.encode_string(nonce)

    # Add E and N from the users public key       
    certificate += utils.encode_mpint(user_pub_numbers.e)
    certificate += utils.encode_mpint(user_pub_numbers.n)
    
    #Add the serial number (numeric)
    certificate += utils.encode_int64(attributes.get('serial', 123456))    
    
    # Add the certificate type
    # 1: OpenSSH User Certificate
    # 2: OpenSSH Host Certificate
    certificate += utils.encode_int(attributes.get('type', 1))
    
    # Add the key ID (string)
    certificate += utils.encode_string(attributes.get('key_id', 'abcdefgh'))
    
    # Add the list of valid principals
    certificate += utils.encode_list(attributes.get('valid_principals', ['root', 'user']))
    
    # Add the "Valid after"-timestamp to specify when the validity starts
    certificate += utils.encode_int64(attributes.get('valid_after', int(timestamp())))
    
    # Add the "Valid before"-timestamp to specify when the validity ends
    certificate += utils.encode_int64(attributes.get('valid_before', int(timestamp()) + (60 * 60 * 12)))
    
    # Add any critical options to the certificate
    certificate += utils.encode_list(attributes.get('critical_options', []))

    # This is encoded a bit differently than the principals list, with null bytes inserted between each extensions
    certificate += utils.encode_list(attributes.get('extensions', ['permit-agent-forwarding']), True)

    # Add the reserved part (empty, reserved for future functionality)
    certificate += utils.encode_string(attributes.get('reserved', ''))

    # Add the signing CA Public Key
    certificate += utils.encode_string(ca_pubkey)
       
    # Create the signature
    # Load the CA Private key from the OpenSSH format
    ca_privkey = serialization.load_ssh_private_key(
        data=ca_privkey,
        password=ca_privkey_pass.encode('utf-8'),
        backend=default_backend()
    )
 
    signature = ca_privkey.sign(
        certificate,
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    
    # # Append the signature to the certificate
    certificate += utils.encode_rsa_signature(signature, b'ssh-rsa')

    # Write the certificate to file
    filename = f'{user_pubkey_path.split("/")[-1].split(".")[0]}-cert.pub'
    with open(filename, 'wb') as f:
        f.write( b'%b-cert-v01@openssh.com %b %b' % (
                    b'ssh-rsa',
                    b64encode(certificate),
                    b'User@Host'
                    )
                )
        
        
    # Verify the certificate with SSH-Keygen
    os.system(f'ssh-keygen -Lf {filename}')


def decode_rsa_certificate(certificate_path: str):
    with open(certificate_path, 'r') as f:
        certificate = b64decode(f.read().split(' ')[1])

    cert_decoded = {}
  
    # Get the certificate type
    cert_decoded['ktype'], certificate = utils.decode_string(certificate)

    # Get the nonce
    cert_decoded['nonce'], certificate = utils.decode_string(certificate)
    
    # Get the user pubkey exponents E and N
    e, certificate = utils.decode_mpint(certificate)
    n, certificate = utils.decode_mpint(certificate)
    
    cert_decoded['pubkey'] = {
        "e": e,
        "n": n,
        "pubkey": b64encode(RSAPublicNumbers(e, n).public_key(default_backend()).public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode('utf-8')
    }
    
    # Get the serial number
    cert_decoded['serial'], certificate = utils.decode_int64(certificate)

    # Get the certificate type
    cert_decoded['ctype'], certificate = utils.decode_int(certificate)
    
    # Get the certificate key ID
    cert_decoded['key_id'], certificate = utils.decode_string(certificate)
    
    # Get the certificate principals
    cert_decoded['valid_principals'], certificate = utils.decode_list(certificate)
    
    # Get the certificate valid after
    cert_decoded['valid_after'], certificate = utils.decode_int64(certificate)
    
    # Get the certificate valid before
    cert_decoded['valid_before'], certificate = utils.decode_int64(certificate)
    
    # Get the certificate critical options
    cert_decoded['critical_options'], certificate = utils.decode_list(certificate)
    
    # Get the certificate extensions
    cert_decoded['extensions'], certificate = utils.decode_list(certificate, True)
    
    # Get the reserved part
    cert_decoded['reserved'], certificate = utils.decode_string(certificate)
    
    # Get the CA public key
    cert_decoded['ca_pubkey'], certificate = utils.decode_string(certificate)
    
    # Get the signature
    cert_decoded['signature'], _ = utils.decode_rsa_signature(certificate)
    
    cert_decoded['ca_pubkey'] = b64encode(cert_decoded['ca_pubkey']).decode('utf-8')
    cert_decoded['signature']['type'] = cert_decoded['signature']['type'].decode('utf-8')
    cert_decoded['signature']['data'] = b64encode(cert_decoded['signature']['data']).decode('utf-8')
    
    for item in cert_decoded.keys():
        if isinstance(cert_decoded[item], bytes):
            cert_decoded[item] = cert_decoded[item].decode('utf-8')
        if isinstance(cert_decoded[item], list):
            newlst = []
            for litem in cert_decoded[item]:
                if isinstance(litem, bytes):
                    newlst.append(litem.decode('utf-8'))
            cert_decoded[item] = newlst

    return cert_decoded