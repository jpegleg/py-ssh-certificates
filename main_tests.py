import time
import datetime
from test_sshkeys import gen_test_sshkeys, remove_test_sshkeys
gen_test_sshkeys('password')


print("---------------| starting ssh certificate tests")
print("")
print("----->>> UTC start time ref in ISO format:", datetime.datetime.utcfromtimestamp(int(time.time())).isoformat())
print("")
# Common attributes
# (not certificate-type specific)
# See https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
# 
# Serial: Numeric ID, arbitrary
# Type: Certificate type, 1 = user, 2 = host
# Key ID: Certificate identifier, arbitrary string
# Valid Principals: List of principals for which the certificate is valid, list of strings
# Valid after: Timestamp, seconds since epoch
# Valid before: Timestamp, seconds since epoch
# Critical Options: List of critical options, list of strings
# Extensions: List of extensions, list of strings
# Reserved: Empty string, unused

certificate_attr = {
    "serial": 123456,
    "type": 1,
    "key_id": "qwerty",
    "valid_principals": [
        "root", 
        "userone", 
        "usergroup"
    ],
    "valid_after": int(time.time()),
    "valid_before": int(time.time() + 60 * 60 * 12),
    "critical_options": [],
    "extensions": [
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding"    
    ],
    "reserved": ""
}

print("-----<<< ISO expiration ref:", datetime.datetime.utcfromtimestamp(int(time.time() + 60 * 60 * 12)).isoformat())

# Now we can test the certificates

# Certificate-specific options:
# Type (Overall): ssh-ecdsa-sha2-nistpXYZ-cert-v01@openssh.com where XYZ is the key size
# Nonce: Random string to prevent hash collision attacks
# Curve: The curve used to create the user key
# Public Key: The public key of the user
# Generate an ECDSA SSH Certificate:
from ecdsa_certificates import make_ecdsa_certificate, decode_ecdsa_certificate

make_ecdsa_certificate(
    user_pubkey_path='test_ecdsa_user.pub',
    ca_pubkey_path='test_ecdsa_ca.pub',
    ca_privkey_path='test_ecdsa_ca',
    ca_privkey_pass='password',
    attributes=certificate_attr
    )

# Decode the certificate and verify the contents
decoded_ecdsa = decode_ecdsa_certificate('test_ecdsa_user-cert.pub')

assert decoded_ecdsa['serial'] == certificate_attr['serial']
assert decoded_ecdsa['ctype'] == certificate_attr['type']
assert decoded_ecdsa['key_id'] == certificate_attr['key_id']
assert decoded_ecdsa['valid_principals'] == certificate_attr['valid_principals']
assert decoded_ecdsa['valid_after'] == certificate_attr['valid_after']
assert decoded_ecdsa['valid_before'] == certificate_attr['valid_before']
assert decoded_ecdsa['critical_options'] == certificate_attr['critical_options']
assert decoded_ecdsa['extensions'] == certificate_attr['extensions']
assert decoded_ecdsa['reserved'] == certificate_attr['reserved']

# Certificate-specific options:
# Type (Overall): ssh-rsa-cert-v01@openssh.com
# Nonce: Random string to prevent hash collision attacks
# e: The E-value from the user's public key numbers
# n: The N-value from the user's public key numbers
# Generate a RSA SSH Certificate:
from rsa_certificates import make_rsa_certificate, decode_rsa_certificate
make_rsa_certificate(
    user_pubkey_path='test_rsa_user.pub',
    ca_pubkey_path='test_rsa_ca.pub',
    ca_privkey_path='test_rsa_ca',
    ca_privkey_pass='password',
    attributes=certificate_attr
    )


# Certificate-specific options:
# Type (Overall): ssh-rsa-cert-v01@openssh.com
# Nonce: Random string to prevent hash collision attacks
# p: The P-value from the user's public key parameters
# q: The Q-value from the user's public key parameters
# g: The G-value from the user's public key parameters
# y: The Y-value from the user's public key numbers
# Decode the certificate and verify the contents
decoded_rsa = decode_rsa_certificate('test_rsa_user-cert.pub')

assert decoded_rsa['serial'] == certificate_attr['serial']
assert decoded_rsa['ctype'] == certificate_attr['type']
assert decoded_rsa['key_id'] == certificate_attr['key_id']
assert decoded_rsa['valid_principals'] == certificate_attr['valid_principals']
assert decoded_rsa['valid_after'] == certificate_attr['valid_after']
assert decoded_rsa['valid_before'] == certificate_attr['valid_before']
assert decoded_rsa['critical_options'] == certificate_attr['critical_options']
assert decoded_rsa['extensions'] == certificate_attr['extensions']
assert decoded_rsa['reserved'] == certificate_attr['reserved']

# Generate a DSA SSH Certificate
from dss_certificates import make_dss_certificate, decode_dss_certificate
make_dss_certificate(
    user_pubkey_path='test_dss_user.pub',
    ca_pubkey_path='test_dss_ca.pub',
    ca_privkey_path='test_dss_ca',
    ca_privkey_pass='password',
    attributes=certificate_attr
    )

# # Decode the certificate and verify the contents
decoded_dss = decode_dss_certificate('test_dss_user-cert.pub')

assert decoded_dss['serial'] == certificate_attr['serial']
assert decoded_dss['ctype'] == certificate_attr['type']
assert decoded_dss['key_id'] == certificate_attr['key_id']
assert decoded_dss['valid_principals'] == certificate_attr['valid_principals']
assert decoded_dss['valid_after'] == certificate_attr['valid_after']
assert decoded_dss['valid_before'] == certificate_attr['valid_before']
assert decoded_dss['critical_options'] == certificate_attr['critical_options']
assert decoded_dss['extensions'] == certificate_attr['extensions']
assert decoded_dss['reserved'] == certificate_attr['reserved']

# Certificate-specific options:
# Type (Overall): ssh-rsa-cert-v01@openssh.com
# Nonce: Random string to prevent hash collision attacks
# pk: Encoded ED25519 public key as per RFC8032

# Generate an ED25519 SSH Certificate
from ed25519_certificates import make_ed25519_certificate, decode_ed25519_certificate

make_ed25519_certificate(
    user_pubkey_path='test_ed25519_user.pub',
    ca_pubkey_path='test_ed25519_ca.pub',
    ca_privkey_path='test_ed25519_ca',
    attributes=certificate_attr
)

# # # Decode the certificate and verify the contents
decoded_ed25519 = decode_ed25519_certificate('test_ed25519_user-cert.pub')

assert decoded_ed25519['serial'] == certificate_attr['serial']
assert decoded_ed25519['ctype'] == certificate_attr['type']
assert decoded_ed25519['key_id'] == certificate_attr['key_id']
assert decoded_ed25519['valid_principals'] == certificate_attr['valid_principals']
assert decoded_ed25519['valid_after'] == certificate_attr['valid_after']
assert decoded_ed25519['valid_before'] == certificate_attr['valid_before']
assert decoded_ed25519['critical_options'] == certificate_attr['critical_options']
assert decoded_ed25519['extensions'] == certificate_attr['extensions']
assert decoded_ed25519['reserved'] == certificate_attr['reserved']

print("")
print("-| UTC end time ref in ISO format:", datetime.datetime.utcfromtimestamp(int(time.time())).isoformat())
print("---------------| ssh certificate tests end")
