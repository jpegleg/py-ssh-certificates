# This file generates test SSH Keys for the Certificate tests
import os
import random

def gen_test_sshkeys(
        password: str = 'password', 
        remove_user_privkey: bool = True,
        rsa: bool = True, 
        dss: bool = True, 
        ecdsa: bool = True, 
        ed25519: bool = True 
):
    if rsa is True:
        gen_ssh_rsa_keys(password)
        # We can remove the private key for the user to simulate that we only get the public key for signing
        os.remove('test_rsa_user')
    if dss is True:
        gen_ssh_dss_keys(password)
        os.remove('test_dss_user')
    if ecdsa is True:
        gen_ssh_ecdsa_keys(password)
        os.remove('test_ecdsa_user')
    if ed25519 is True:
        gen_ssh_ed25519_keys(password)
        os.remove('test_ed25519_user')
        
def gen_ssh_rsa_keys(password):
    lengths = [ '1024', '2048', '3072', '4096' ]
    ca_length = random.choice(lengths)
    user_length = random.choice(lengths)
    os.system(f'ssh-keygen -t rsa -b {ca_length} -C CA -f test_rsa_ca -N {password} -q')
    os.system(f'ssh-keygen -t rsa -b {user_length} -C User@Host -f test_rsa_user -N {password} -q')
        
def gen_ssh_dss_keys(password):
    # DSA/DSS keys are always 1024 bits
    ca_length = '1024'
    user_length = '1024'
    os.system(f'ssh-keygen -t dsa -b {ca_length} -C CA -f test_dss_ca -N {password} -q')
    os.system(f'ssh-keygen -t dsa -b {user_length} -C User@Host -f test_dss_user -N {password} -q')
    
def gen_ssh_ecdsa_keys(password):
    lengths = [ '256', '384', '521' ]
    ca_length = random.choice(lengths)
    user_length = random.choice(lengths)
    os.system(f'ssh-keygen -t ecdsa -b {ca_length} -C CA -f test_ecdsa_ca -N {password} -q')
    os.system(f'ssh-keygen -t ecdsa -b {user_length} -C User@Host -f test_ecdsa_user -N {password} -q')
    
def gen_ssh_ed25519_keys(password):
    # All ED25519 keys are always 256 bits
    ca_length = '256'
    user_length = '256'
    os.system(f'ssh-keygen -t ed25519 -b {ca_length} -C CA -f test_ed25519_ca -N {password} -q')
    os.system(f'ssh-keygen -t ed25519 -b {user_length} -C User@Host -f test_ed25519_user -N {password} -q')
    
    
def remove_test_sshkeys(certificates: bool = False):
    files = [
        'test_rsa_ca',
        'test_rsa_ca.pub',
        'test_rsa_user',
        'test_rsa_user.pub',
        'test_ecdsa_ca',
        'test_ecdsa_ca.pub',
        'test_ecdsa_user',
        'test_ecdsa_user.pub',
        'test_ed25519_ca',
        'test_ed25519_ca.pub',
        'test_ed25519_user',
        'test_ed25519_user.pub',
        'test_dss_ca',
        'test_dss_ca.pub',
        'test_dss_user',
        'test_dss_user.pub'
        ]
    
    if certificates is True:
        files += [
            'test_rsa_user-cert.pub',
            'test_ecdsa_user-cert.pub',
            'test_ed25519_user-cert.pub',
            'test_dss_user-cert.pub'
        ]
    
    for file in files:
        if os.path.isfile(file):
            os.remove(file)