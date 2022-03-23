import os
import string
import random
import unittest

from time import time, sleep

from test_sshkeys import gen_test_sshkeys, remove_test_sshkeys

from rsa_certificates import make_rsa_certificate, decode_rsa_certificate
from dss_certificates import make_dss_certificate, decode_dss_certificate
from ecdsa_certificates import make_ecdsa_certificate, decode_ecdsa_certificate
from ed25519_certificates import make_ed25519_certificate, decode_ed25519_certificate

RAND_LETTERS = string.ascii_letters + string.digits
RAND_CRITICAL_OPTIONS = [
    'verify-required'
]
RAND_EXTENSIONS = [
    'no-touch-required',
    'permit-X11-forwarding',
    'permit-agent-forwarding',
    'permit-port-forwarding',
    'permit-pty',
    'permit-user-rc'
]

class TestCertificate(unittest.TestCase):
    def setUp(self):
        self.config = {
            'ca': '',
            'user': '',
            'pass': ''.join(random.choice(RAND_LETTERS) for _ in range(10)),
            'attributes': {
                "serial":  random.randint(0, 2**64),
                "type": 1,
                "key_id": ''.join(random.choice(RAND_LETTERS) for _ in range(random.randint(10, 100))),
                "valid_principals": [
                    "root", 
                    "user_one", 
                    "user two",
                    ''.join(random.choice(RAND_LETTERS) for _ in range(10))
                ],
                "valid_after": int(time()),
                "valid_before": int(time() + random.randint(1, 3600*48)),
                "critical_options": [ random.choice(RAND_CRITICAL_OPTIONS) for _ in range(random.randint(0, len(RAND_CRITICAL_OPTIONS))) ],
                "extensions": [ random.choice(RAND_EXTENSIONS) for _ in range(random.randint(0, len(RAND_EXTENSIONS))) ],
                "reserved": ""
            }
        }
        
    def test_certificates(self):
        self.gen_certificate(
            user_pubkey_path=f"{self.config['user']}.pub",
            ca_pubkey_path=f"{self.config['ca']}.pub",
            ca_privkey_path=f"{self.config['ca']}",
            ca_privkey_pass=self.config['pass'],
            attributes=self.config['attributes'],
            auto_verify=False
        )
        
        self.assertEqual(0, os.system(f"ssh-keygen -Lf {self.config['user']}-cert.pub > /dev/null 2>&1"))
        
        decoded = self.decode_certificate(f"{self.config['user']}-cert.pub")
        
        self.assertEqual(self.config['attributes']['serial'], decoded['serial'])
        self.assertEqual(self.config['attributes']['type'], decoded['ctype'])
        self.assertEqual(self.config['attributes']['key_id'], decoded['key_id'])
        self.assertEqual(self.config['attributes']['valid_principals'], decoded['valid_principals'])
        self.assertEqual(self.config['attributes']['valid_after'], decoded['valid_after'])
        self.assertEqual(self.config['attributes']['valid_before'], decoded['valid_before'])
        self.assertEqual(self.config['attributes']['critical_options'], decoded['critical_options'])
        self.assertEqual(self.config['attributes']['extensions'], decoded['extensions'])
        self.assertEqual(self.config['attributes']['reserved'], decoded['reserved'])

    def tearDown(self):
        remove_test_sshkeys()


class RSATest(TestCertificate):
    def setUp(self):
        super().setUp()
        self.gen_certificate = make_rsa_certificate
        self.decode_certificate = decode_rsa_certificate
        self.config['ca'] = 'test_rsa_ca'
        self.config['user'] = 'test_rsa_user'
        
        gen_test_sshkeys(
            password=self.config['pass'],
            dss=False,
            ecdsa=False,
            ed25519=False,            
        )
        
class DSSTest(TestCertificate):
    def setUp(self):
        super().setUp()
        self.gen_certificate = make_dss_certificate
        self.decode_certificate = decode_dss_certificate
        self.config['ca'] = 'test_dss_ca'
        self.config['user'] = 'test_dss_user'
        
        gen_test_sshkeys(
            password=self.config['pass'],
            rsa=False,
            ecdsa=False,
            ed25519=False
        )
        
class ECDSATest(TestCertificate):
    def setUp(self):
        super().setUp()
        self.gen_certificate = make_ecdsa_certificate
        self.decode_certificate = decode_ecdsa_certificate
        self.config['ca'] = 'test_ecdsa_ca'
        self.config['user'] = 'test_ecdsa_user'
        
        gen_test_sshkeys(
            password=self.config['pass'],
            rsa=False,
            dss=False,
            ed25519=False
        )
        
class ED25519Test(TestCertificate):
    def setUp(self):
        super().setUp()
        self.gen_certificate = make_ed25519_certificate
        self.decode_certificate = decode_ed25519_certificate
        self.config['ca'] = 'test_ed25519_ca'
        self.config['user'] = 'test_ed25519_user'
        
        gen_test_sshkeys(
            password=self.config['pass'],
            rsa=False,
            dss=False,
            ecdsa=False
        )
    
if __name__ == '__main__':
    for _ in range(10):
        test_suite = unittest.TestSuite()
        test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(RSATest))
        test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(DSSTest))
        test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(ECDSATest))
        test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(ED25519Test))
        test_runner = unittest.TextTestRunner()
        test_runner.run(test_suite)
