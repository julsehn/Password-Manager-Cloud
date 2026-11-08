import hashlib
import unittest

from fastapi import HTTPException

from app.main import (
    AUTH_RATE_LIMIT,
    _auth_attempts,
    enforce_auth_rate_limit,
    hash_password,
    verify_password,
)


class CloudAuthSecurityTests(unittest.TestCase):
    def test_password_hashes_use_argon2id(self):
        stored = hash_password("sample-cloud-password")

        self.assertTrue(stored.startswith("$argon2id$"))
        self.assertTrue(verify_password("sample-cloud-password", stored))
        self.assertFalse(verify_password("incorrect", stored))

    def test_unsalted_sha256_hash_is_rejected(self):
        stored = hashlib.sha256(b"sample-cloud-password").hexdigest()

        self.assertFalse(verify_password("sample-cloud-password", stored))

    def test_auth_rate_limit_is_enforced(self):
        _auth_attempts.clear()
        for _ in range(AUTH_RATE_LIMIT):
            enforce_auth_rate_limit("test-auth-client")

        with self.assertRaises(HTTPException) as error:
            enforce_auth_rate_limit("test-auth-client")

        self.assertEqual(error.exception.status_code, 429)
        _auth_attempts.clear()


if __name__ == "__main__":
    unittest.main()