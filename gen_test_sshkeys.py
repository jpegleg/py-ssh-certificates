# This file generates test SSH Keys for the Certificate tests
import os
def gen_test_sshkeys(password: str = 'password', rsa: bool = True, dsa: bool = True, ecdsa: bool = True, ed25519: bool = True):
    if rsa:
        gen_ssh_rsa_keys(password)
    if dsa:
        gen_ssh_dsa_keys(password)
    if ecdsa:
        gen_ssh_ecdsa_keys(password)
    if rsa:
        gen_ssh_ed25519_keys(password)
        
def gen_ssh_rsa_keys(password):
    os.system(f'ssh-keygen -t rsa -C CA -f test_rsa_ca -N {password}')
    os.system(f'ssh-keygen -t rsa -C User@Host -f test_rsa_user -N {password}')
        
def gen_ssh_dsa_keys(password):
    os.system(f'ssh-keygen -t dsa -C CA -f test_dsa_ca -N {password}')
    os.system(f'ssh-keygen -t dsa -C User@Host -f test_dsa_user -N {password}')
    
def gen_ssh_ecdsa_keys(password):
    os.system(f'ssh-keygen -t ecdsa -C CA -f test_ecdsa_ca -N {password}')
    os.system(f'ssh-keygen -t ecdsa -C User@Host -f test_ecdsa_user -N {password}')
    
def gen_ssh_ed25519_keys(password):
    os.system(f'ssh-keygen -t ed25519 -C CA -f test_ed25519_ca -N {password}')
    os.system(f'ssh-keygen -t ed25519 -C User@Host -f test_ed25519_user -N {password}')