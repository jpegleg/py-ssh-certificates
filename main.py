# Start by generating the test certificates
from gen_test_sshkeys import gen_test_sshkeys
# gen_test_sshkeys()

# Now we can test the certificates
# Generate an ECDSA SSH Certificate:
from make_ecdsa_certificate import make_ecdsa_certificate
make_ecdsa_certificate('test_ecdsa_user.pub', 'test_ecdsa_ca.pub', 'test_ecdsa_ca')
