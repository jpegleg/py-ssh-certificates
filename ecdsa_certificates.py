import os
from time import time as timestamp
from base64 import b64encode, b64decode
import sshcert_utils as utils

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

CURVES = {
    'secp256r1': hashes.SHA256,
    'secp384r1': hashes.SHA384,
    'secp521r1': hashes.SHA512
}

def make_ecdsa_certificate(
        user_pubkey_path: str, 
        ca_pubkey_path: str, 
        ca_privkey_path: str, 
        ca_privkey_pass: str = "password",
        attributes: dict = {}
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
        
        # The curve (e.g. nistp256)
        user_keycurve, data = utils.decode_string(data)
        
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
    # For ECDSA, this is usually ecdsa-sha2-nistpXXX-cert-v01@openssh.com
    # where XXX is the length of the curve in bits
    certificate += utils.encode_string(b'%s-cert-v01@openssh.com' % user_keytype)

    # Add the nonce
    # This is the random part of the certificate which is used
    # to prevent hash collision attacks against the CA private key
    # This is really important, seeing as if an attacker has access to two signed messages with the same nonce
    # they can deduct the private key from this.
    # Read more here: https://billatnapier.medium.com/ecdsa-weakness-where-nonces-are-reused-2be63856a01a
    nonce = utils.generate_secure_nonce(32)
    certificate += utils.encode_string(nonce)
  
    # Add the curve used to create the user key
    # certificate += utils.encode_string(user_keycurve)
    certificate += utils.encode_string(user_keycurve)

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
        password=b"password",
        backend=default_backend()
    )
    
    # Get the curve used in the private key
    curve = ec.ECDSA(CURVES[ca_privkey.curve.name]())

    # Create the signature
    signature = ca_privkey.sign(
        certificate,
        curve
    )
    
    # Get the signature parts, r and s
    r, s = decode_dss_signature(signature)
       
    # Add the signature to the certificate
    certificate += utils.encode_dsa_signature(r, s, 'ecdsa-sha2-nistp%d' % ca_privkey.curve.key_size)

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
    os.system(f'ssh-keygen -Lf {filename}')
    
def decode_ecdsa_certificate(certificate_path: str):
    with open(certificate_path, 'r') as f:
        certificate = b64decode(f.read().split(' ')[1])

    cert_decoded = {}
    
    # Get the certificate type
    cert_decoded['type'], certificate = utils.decode_string(certificate)

    # Get the nonce
    cert_decoded['nonce'], certificate = utils.decode_string(certificate)
    
    # Get the user key curve
    cert_decoded['curve'], certificate = utils.decode_string(certificate)

    # Get the user public key
    cert_decoded['pubkey'], certificate = utils.decode_string(certificate)

    # Get the serial number
    cert_decoded['serial'], certificate = utils.decode_int64(certificate)

    # Get the certificate type
    cert_decoded['type'], certificate = utils.decode_int(certificate)
    
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
    cert_decoded['signature'], _ = utils.decode_dsa_signature(certificate)
    
    cert_decoded['pubkey'] = b64encode(cert_decoded['pubkey']).decode('utf-8')
    cert_decoded['ca_pubkey'] = b64encode(cert_decoded['ca_pubkey']).decode('utf-8')
    cert_decoded['signature']['curve'] = cert_decoded['signature']['curve'].decode('utf-8')
    
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