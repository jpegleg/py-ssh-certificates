import time
# Start by generating the test certificates
from gen_test_sshkeys import gen_test_sshkeys
gen_test_sshkeys(dsa=False, ed25519=False)

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

# Now we can test the certificates
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
assert decoded_ecdsa['type'] == certificate_attr['type']
assert decoded_ecdsa['key_id'] == certificate_attr['key_id']
assert decoded_ecdsa['valid_principals'] == certificate_attr['valid_principals']
assert decoded_ecdsa['valid_after'] == certificate_attr['valid_after']
assert decoded_ecdsa['valid_before'] == certificate_attr['valid_before']
assert decoded_ecdsa['critical_options'] == certificate_attr['critical_options']
assert decoded_ecdsa['extensions'] == certificate_attr['extensions']
assert decoded_ecdsa['reserved'] == certificate_attr['reserved']

# Generate an RSA SSH Certificate:
from rsa_certificates import make_rsa_certificate, decode_rsa_certificate
make_rsa_certificate(
    user_pubkey_path='test_rsa_user.pub',
    ca_pubkey_path='test_rsa_ca.pub',
    ca_privkey_path='test_rsa_ca',
    ca_privkey_pass='password',
    attributes=certificate_attr
    )

# Decode the certificate and verify the contents
decoded_rsa = decode_rsa_certificate('test_rsa_user-cert.pub')

assert decoded_ecdsa['serial'] == certificate_attr['serial']
assert decoded_ecdsa['type'] == certificate_attr['type']
assert decoded_ecdsa['key_id'] == certificate_attr['key_id']
assert decoded_ecdsa['valid_principals'] == certificate_attr['valid_principals']
assert decoded_ecdsa['valid_after'] == certificate_attr['valid_after']
assert decoded_ecdsa['valid_before'] == certificate_attr['valid_before']
assert decoded_ecdsa['critical_options'] == certificate_attr['critical_options']
assert decoded_ecdsa['extensions'] == certificate_attr['extensions']
assert decoded_ecdsa['reserved'] == certificate_attr['reserved']