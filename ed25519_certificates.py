import os
from time import time as timestamp
from base64 import b64encode, b64decode
import sshcert_utils as utils

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def make_ed25519_certificate(
        user_pubkey_path: str, 
        ca_pubkey_path: str, 
        ca_privkey_path: str, 
        ca_privkey_pass: str = "password",
        attributes: dict = {},
        auto_verify: bool = True
    ):
    
    
    # Load the user public key
    with open(user_pubkey_path, 'r') as f:
        file_content = f.read().split(' ')

        # Get the two major parts from the file
        # The certificate data
        data = b64decode(file_content[1])
        
        # And the comment at the end of the file (e.g. User@Host)
        user_comment = file_content[2]

        # Convert the user public key to its parts
        # The Key type (e.g. ecdsa-sha2-nistp256)
        user_keytype, data = utils.decode_string(data)
        
        # The public key in bytes
        user_pubkey, data = utils.decode_string(data)  
    
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
    # For ED25519, this is usually ssh-ed25519-cert-v01@openssh.com
    certificate += utils.encode_string('ssh-ed25519-cert-v01@openssh.com')

    # Add the nonce
    # This is the random part of the certificate which is used
    # to prevent hash collision attacks against the CA private key
    # This is really important, seeing as if an attacker has access to two signed messages with the same nonce
    # they can deduct the private key from this.
    # Read more here: https://billatnapier.medium.com/ecdsa-weakness-where-nonces-are-reused-2be63856a01a
    nonce = utils.generate_secure_nonce(32)
    certificate += utils.encode_string(nonce)
  
    # Add the users public key
    certificate += utils.encode_string(user_pubkey)
    
    # Add the serial number (numeric)
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
    certificate += utils.encode_list(attributes.get('critical_options', []), True)

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
    

    # Create the signature    
    signature = utils.encode_string('ssh-ed25519')
    signature += utils.encode_string(ca_privkey.sign(certificate))

    # Append the signature to the certificate
    certificate += utils.encode_string(signature)
    
    
    # Write the certificate to file
    filename = f'{user_pubkey_path.split("/")[-1].split(".")[0]}-cert.pub'
    with open(filename, 'wb') as f:
        f.write( b'%b-cert-v01@openssh.com %b %b' % (
                    user_keytype,
                    b64encode(certificate),
                    user_comment.encode()
                    )
                )

        
        
    # Verify the certificate with SSH-Keygen
    if auto_verify:
        os.system(f'ssh-keygen -Lf {filename}')
    
def decode_ed25519_certificate(certificate_path: str):
    with open(certificate_path, 'r') as f:
        certificate = b64decode(f.read().split(' ')[1])

    cert_decoded = {}
    
    # Get the certificate type
    cert_decoded['ktype'], certificate = utils.decode_string(certificate)

    # Get the nonce
    cert_decoded['nonce'], certificate = utils.decode_string(certificate)
    
    # Get the user public key
    cert_decoded['pubkey'], certificate = utils.decode_string(certificate)

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
    cert_decoded['critical_options'], certificate = utils.decode_list(certificate, True)
    
    # Get the certificate extensions
    cert_decoded['extensions'], certificate = utils.decode_list(certificate, True)
    
    # Get the reserved part
    cert_decoded['reserved'], certificate = utils.decode_string(certificate)
    
    # Get the CA public key
    cert_decoded['ca_pubkey'], certificate = utils.decode_string(certificate)
    
    # Get the signature
    signature_encoded = utils.decode_string(certificate)[0]
    
    cert_decoded['signature'] = {}
    cert_decoded['signature']['type'], signature_encoded = utils.decode_string(signature_encoded)
    cert_decoded['signature']['bytes'] = utils.decode_string(signature_encoded)[0]
    
    
    # Decode bytes and/or b64encode to allow for JSON serialization  
    cert_decoded['pubkey'] = b64encode(cert_decoded['pubkey']).decode('utf-8')
    cert_decoded['ca_pubkey'] = b64encode(cert_decoded['ca_pubkey']).decode('utf-8')

    cert_decoded['signature']['type'] = cert_decoded['signature']['type'].decode('utf-8')
    
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