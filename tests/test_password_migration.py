import hashlib
import unittest
from core.security import hash_password, password_needs_upgrade, verify_password

class PasswordMigrationTests(unittest.TestCase):
    def test_new_hash_is_versioned(self):
        stored = hash_password('correct horse battery staple')
        self.assertTrue(stored.startswith('pbkdf2_sha256$310000$'))
        self.assertTrue(verify_password('correct horse battery staple', stored))
        self.assertFalse(password_needs_upgrade(stored))

    def test_legacy_hash_still_verifies(self):
        salt = b'0123456789abcdef'
        digest = hashlib.pbkdf2_hmac('sha256', b'legacy', salt, 120_000)
        stored = f'{salt.hex()}:{digest.hex()}'
        self.assertTrue(verify_password('legacy', stored))
        self.assertTrue(password_needs_upgrade(stored))

    def test_malformed_hash_fails_closed(self):
        self.assertFalse(verify_password('x', 'not-a-hash'))

if __name__ == '__main__':
    unittest.main()
