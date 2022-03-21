import os
import random
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
        ca_privkey_pass: str = "password"
    ):
    
    # # Load the OpenSSH public key to be signed
    # # Here, we need some different parts of the key for the certificate
    # with open(user_pubkey_path, 'r') as f:
    #     file_content = f.read().split(' ')
    
    #     # Get the two major parts from the file
    #     # The certificate data
    #     data = b64decode(file_content[1])
        
    #     # And the comment at the end of the file (e.g. User@Host)
    #     user_comment = file_content[2]
    
    #     # Convert the user public key to its parts
    #     # The Key type (e.g. ecdsa-sha2-nistp256)
    #     user_keytype, data = utils.decode_string(data)
        
    #     # The curve (e.g. nistp256)
    #     user_keycurve, data = utils.decode_string(data)
        
    #     # The public key in bytes
    #     user_pubkey, data = utils.decode_string(data)
    
    
    # # Load the key data for the CA Public Key
    # # For this, we just need the entire key data in byte format
    # with open(ca_pubkey_path, 'r') as f:
    #     ca_pubkey = b64decode(f.read().split(' ')[1])
        
    # # Load the data for the CA Private key as bytes
    # with open(ca_privkey_path, 'rb') as f:
    #     ca_privkey = f.read()
    
    # Create an empty Bytes object
    certificate = b''
    
    # Add the certificate type
    # This is based on the users certificate type
    # For ECDSA, this is usually ecdsa-sha2-nistpXXX-cert-v01@openssh.com
    # where XXX is the length of the curve in bits
    # certificate += utils.encode_string(b'%s-cert-v01@openssh.com' % user_keytype)
    certificate += utils.encode_string('ecdsa-sha2-nistp256-cert-v01@openssh.com')

    # Add the nonce
    # This is the random part of the certificate which is used
    # to prevent hash collision attacks against the CA private key
    # This is really important, seeing as if an attacker has access to two signed messages with the same nonce
    # they can deduct the private key from this.
    # Read more here: https://billatnapier.medium.com/ecdsa-weakness-where-nonces-are-reused-2be63856a01a
    
    # nonce = utils.generate_secure_nonce(32)
    # certificate += utils.encode_string(nonce)
    nonce = str(random.randint(2**10, 2**32))
    certificate += utils.encode_string(nonce)
    
    
    # Add the curve used to create the user key
    # certificate += utils.encode_string(user_keycurve)
    certificate += utils.encode_string('nistp256')


    with open('test_ecdsa_user.pub') as f:
        from paramiko.message import Message
        user_pubkey = f.read().split(' ')[1]
        user_pubkey = Message(b64decode(user_pubkey))
        _ = user_pubkey.get_string()
        _ = user_pubkey.get_string()
        user_pubkey = user_pubkey.get_string()

    # Add the users public key
    certificate += utils.encode_string(user_pubkey)
    
    # Add the serial number (numeric)
    certificate += utils.encode_int64(123456)    
    # Add the certificate type
    # 1: OpenSSH User Certificate
    # 2: OpenSSH Host Certificate
    certificate += utils.encode_int(1)
    
    # Add the key ID (string)
    certificate += utils.encode_string('MyFirstCert')
    
    # Add the list of valid principals
    principals = ['root', 'user1', 'user2']
    certificate += utils.encode_list(principals)
    
    # Add the "Valid after"-timestamp to specify when the validity starts
    certificate += utils.encode_int64(int(timestamp()))
    
    # Add the "Valid before"-timestamp to specify when the validity ends
    # 60 * 60 * 12 = 12 Hours
    validity_seconds = 60 * 60 * 12
    certificate += utils.encode_int64(int(timestamp()) + validity_seconds)
    
    # Add any critical options to the certificate
    # In this case, we'll add none
    certificate += utils.encode_list([])
    
    # Add optional extensions to the certificate
    extensions = [
        'permit-X11-forwarding',
        'permit-agent-forwarding',
        'permit-port-forwarding',
        'permit-pty'
    ]
    
    # This is encoded a bit differently than the principals list, with null bytes inserted between each extensions
    certificate += utils.encode_list(extensions, True)


    with open('test_ecdsa_ca.pub', 'r') as f:
        ca_pubkey = f.read().split(' ')[1]
        ca_pubkey = b64decode(ca_pubkey)

    # Add the signing CA Public Key
    certificate += utils.encode_string(ca_pubkey)
    
    
    with open('test_ecdsa_ca', 'rb') as f:
        ca_privkey = f.read()
    
    # Create the signature
    # Load the CA Private key from the OpenSSH format
    ca_privkey = serialization.load_ssh_private_key(
        data=ca_privkey,
        password=b"password",
        backend=default_backend()
    )
    
    # Get the curve used in the private key
    curve = ec.ECDSA(hashes.SHA256())

    # Create the signature
    signature = ca_privkey.sign(
        certificate,
        curve
    )
    
    # Get the signature parts, r and s
    r, s = decode_dss_signature(signature)
    
    # Add the signature to the certificate
    certificate += utils.encode_dsa_signature(r, s, 'ecdsa-sha2-nistp256')

    # Write the certificate to file
    # filename = f'{user_pubkey_path.split("/")[-1].split(".")[0]}-cert.pub'
    # with open(filename, 'wb') as f:
    #     f.write(
    #             b'ecdsa-sha2-nistp256-cert-v01@openssh.com ' +
    #             b64encode(certificate) +
    #             b' User@Host'
    #     )
        
    filename = "test_ecdsa_cert.pub"
    with open(filename, 'w') as f:
        f.write(
            'ecdsa-sha2-nistp256-cert-v01@openssh.com ' +
            b64encode(certificate).decode('iso-8859-1') +
            ' User@Host'
        )
        
        
    # Verify the certificate with SSH-Keygen
    os.system(f'ssh-keygen -Lf {filename}')