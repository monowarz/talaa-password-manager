"""
Cryptographic operations for Taala Password Manager

Implements secure encryption/decryption using Fernet (AES-256) and 
PBKDF2 key derivation following OWASP security guidelines.

Security Features:
- AES-256 encryption via Fernet
- PBKDF2 key derivation with 100,000 iterations
- Cryptographically secure random salt generation
- SHA-256 hashing for master password verification
"""

import os
import base64
import hashlib
from typing import Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class CryptoManager:
    """
    Handles all cryptographic operations for the password manager.

    Uses industry-standard encryption practices:
    - Fernet for symmetric encryption (AES-256 in CBC mode with HMAC)
    - PBKDF2 for key derivation with high iteration count
    - Secure random salt generation for each operation
    """

    # Security constants following OWASP recommendations
    PBKDF2_ITERATIONS = 100000  # High iteration count for key derivation
    SALT_LENGTH = 16           # 128-bit salt for PBKDF2
    KEY_LENGTH = 32            # 256-bit key for AES

    def __init__(self):
        """Initialize the CryptoManager."""
        self._current_key = None

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from password using PBKDF2.

        Args:
            password: Master password string
            salt: Random salt bytes for key derivation

        Returns:
            32-byte derived key suitable for Fernet encryption

        Security Notes:
            - Uses PBKDF2-HMAC-SHA256 with 100,000 iterations
            - Salt must be unique for each derivation
            - Iteration count provides resistance to brute-force attacks
        """
        # Convert password to bytes
        password_bytes = password.encode('utf-8')

        # Create PBKDF2 key derivation function
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS
        )

        # Derive and encode key for Fernet
        derived_key = kdf.derive(password_bytes)
        return base64.urlsafe_b64encode(derived_key)

    def generate_salt(self) -> bytes:
        """
        Generate a cryptographically secure random salt.

        Returns:
            16 random bytes suitable for use as PBKDF2 salt

        Security Notes:
            - Uses os.urandom() for cryptographically secure randomness
            - Each salt should be unique and stored with encrypted data
        """
        return os.urandom(self.SALT_LENGTH)

    def encrypt_data(self, data: str, password: str) -> Tuple[bytes, bytes]:
        """
        Encrypt data using password-derived key.

        Args:
            data: Plain text data to encrypt
            password: Master password for key derivation

        Returns:
            Tuple of (encrypted_data, salt) where:
            - encrypted_data: Fernet-encrypted bytes
            - salt: Salt used for key derivation (needed for decryption)

        Security Notes:
            - Generates new salt for each encryption operation
            - Uses Fernet which provides authenticated encryption
            - Salt must be stored alongside encrypted data
        """
        # Generate unique salt for this encryption
        salt = self.generate_salt()

        # Derive encryption key
        key = self.derive_key(password, salt)

        # Create Fernet instance and encrypt data
        fernet = Fernet(key)
        data_bytes = data.encode('utf-8')
        encrypted_data = fernet.encrypt(data_bytes)

        return encrypted_data, salt

    def decrypt_data(self, encrypted_data: bytes, salt: bytes, password: str) -> str:
        """
        Decrypt data using password-derived key.

        Args:
            encrypted_data: Fernet-encrypted bytes
            salt: Salt used during original encryption
            password: Master password for key derivation

        Returns:
            Decrypted plain text string

        Raises:
            InvalidToken: If password is wrong or data is corrupted

        Security Notes:
            - Uses same salt as original encryption
            - Fernet provides authentication - tampering will be detected
            - Wrong password will raise InvalidToken exception
        """
        # Derive the same key using stored salt
        key = self.derive_key(password, salt)

        # Create Fernet instance and decrypt
        fernet = Fernet(key)
        decrypted_bytes = fernet.decrypt(encrypted_data)

        return decrypted_bytes.decode('utf-8')

    def hash_master_password(self, password: str, salt: bytes) -> bytes:
        """
        Create secure hash of master password for verification.

        Args:
            password: Master password string
            salt: Unique salt for this password hash

        Returns:
            SHA-256 hash bytes

        Security Notes:
            - Uses SHA-256 with salt to prevent rainbow table attacks
            - This hash is for verification only, not encryption
            - Salt should be unique and stored with hash
        """
        password_bytes = password.encode('utf-8')
        return hashlib.sha256(salt + password_bytes).digest()

    def verify_master_password(self, password: str, stored_hash: bytes, salt: bytes) -> bool:
        """
        Verify master password against stored hash.

        Args:
            password: Password to verify
            stored_hash: Previously computed password hash
            salt: Salt used with stored hash

        Returns:
            True if password matches, False otherwise

        Security Notes:
            - Uses constant-time comparison to prevent timing attacks
            - Hash verification is separate from encryption key derivation
        """
        computed_hash = self.hash_master_password(password, salt)

        # Use constant-time comparison to prevent timing attacks
        return self._secure_compare(computed_hash, stored_hash)

    def _secure_compare(self, a: bytes, b: bytes) -> bool:
        """
        Perform constant-time comparison of two byte strings.

        Args:
            a, b: Byte strings to compare

        Returns:
            True if equal, False otherwise

        Security Notes:
            - Prevents timing attacks by ensuring comparison always takes same time
            - Essential for secure password verification
        """
        if len(a) != len(b):
            return False

        result = 0
        for x, y in zip(a, b):
            result |= x ^ y

        return result == 0


# Example usage and testing functions (for development/debugging)
if __name__ == "__main__":
    # This section runs only when the module is executed directly
    # Useful for testing during development

    crypto = CryptoManager()

    # Test encryption/decryption
    test_password = "my_secure_master_password"
    test_data = "This is sensitive password data"

    print("Testing Taala CryptoManager...")
    print(f"Original data: {test_data}")

    # Encrypt
    encrypted, salt = crypto.encrypt_data(test_data, test_password)
    print(f"Encrypted successfully (length: {len(encrypted)} bytes)")

    # Decrypt
    decrypted = crypto.decrypt_data(encrypted, salt, test_password)
    print(f"Decrypted data: {decrypted}")
    print(f"Encryption/Decryption successful: {test_data == decrypted}")

    # Test master password hashing
    password_salt = crypto.generate_salt()
    password_hash = crypto.hash_master_password(test_password, password_salt)

    # Test verification
    is_valid = crypto.verify_master_password(test_password, password_hash, password_salt)
    print(f"Password verification successful: {is_valid}")

    # Test with wrong password
    wrong_password_valid = crypto.verify_master_password("wrong_password", password_hash, password_salt)
    print(f"Wrong password correctly rejected: {not wrong_password_valid}")
