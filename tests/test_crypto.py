"""
Unit tests for CryptoManager module.

Tests encryption, decryption, key derivation, and password hashing functionality.
"""

import unittest
import os
from cryptography.fernet import InvalidToken

# Add parent directory to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from taala_password_manager.core.crypto import CryptoManager


class TestCryptoManager(unittest.TestCase):
    """Test cases for CryptoManager."""

    def setUp(self):
        """Set up test fixtures."""
        self.crypto = CryptoManager()
        self.test_password = "test_master_password_123!"
        self.test_data = "sensitive password data"

    def test_salt_generation(self):
        """Test salt generation."""
        salt1 = self.crypto.generate_salt()
        salt2 = self.crypto.generate_salt()

        # Check salt properties
        self.assertEqual(len(salt1), 16)
        self.assertEqual(len(salt2), 16)
        self.assertNotEqual(salt1, salt2)  # Should be unique

    def test_key_derivation(self):
        """Test PBKDF2 key derivation."""
        salt = self.crypto.generate_salt()
        key1 = self.crypto.derive_key(self.test_password, salt)
        key2 = self.crypto.derive_key(self.test_password, salt)

        # Same password and salt should produce same key
        self.assertEqual(key1, key2)

        # Different salt should produce different key
        different_salt = self.crypto.generate_salt()
        key3 = self.crypto.derive_key(self.test_password, different_salt)
        self.assertNotEqual(key1, key3)

    def test_encryption_decryption(self):
        """Test data encryption and decryption."""
        # Encrypt data
        encrypted_data, salt = self.crypto.encrypt_data(self.test_data, self.test_password)

        # Decrypt data
        decrypted_data = self.crypto.decrypt_data(encrypted_data, salt, self.test_password)

        # Verify round-trip
        self.assertEqual(decrypted_data, self.test_data)

    def test_encryption_with_wrong_password(self):
        """Test decryption with wrong password fails."""
        encrypted_data, salt = self.crypto.encrypt_data(self.test_data, self.test_password)

        # Try to decrypt with wrong password
        with self.assertRaises(InvalidToken):
            self.crypto.decrypt_data(encrypted_data, salt, "wrong_password")

    def test_master_password_hashing(self):
        """Test master password hashing and verification."""
        salt = self.crypto.generate_salt()

        # Hash password
        password_hash = self.crypto.hash_master_password(self.test_password, salt)

        # Verify correct password
        self.assertTrue(
            self.crypto.verify_master_password(self.test_password, password_hash, salt)
        )

        # Verify wrong password
        self.assertFalse(
            self.crypto.verify_master_password("wrong_password", password_hash, salt)
        )

    def test_secure_comparison(self):
        """Test secure byte comparison."""
        data1 = b"test_data"
        data2 = b"test_data"
        data3 = b"different"

        # Same data should compare equal
        self.assertTrue(self.crypto._secure_compare(data1, data2))

        # Different data should not compare equal
        self.assertFalse(self.crypto._secure_compare(data1, data3))

        # Different lengths should not compare equal
        self.assertFalse(self.crypto._secure_compare(data1, b"short"))


if __name__ == '__main__':
    unittest.main()
