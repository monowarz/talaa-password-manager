"""
Input validation utilities for Taala Password Manager

Provides comprehensive input validation and sanitization functions
to ensure data integrity and security throughout the application.

Features:
- URL/domain validation
- Username/email validation  
- Password policy enforcement
- Safe string handling
- Input sanitization
"""

import re
import urllib.parse
from typing import Optional, List, Tuple, Union


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


class InputValidator:
    """
    Comprehensive input validation for password manager operations.

    Provides validation for all user inputs including sites, usernames,
    passwords, and other sensitive data. Ensures data integrity and
    helps prevent injection attacks.
    """

    # Regex patterns for validation
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )

    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )

    # Safe characters for different input types
    SAFE_SITE_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:/')
    SAFE_USERNAME_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_@+')

    def __init__(self):
        """Initialize the input validator."""
        # Maximum lengths to prevent DoS attacks
        self.max_lengths = {
            'site': 255,
            'username': 100,
            'password': 128,
            'notes': 1000,
            'master_password': 128
        }

    def validate_site(self, site: str) -> Tuple[bool, str, str]:
        """
        Validate and normalize a site/domain input.

        Args:
            site: Site URL or domain to validate

        Returns:
            Tuple of (is_valid, normalized_site, error_message)

        Examples:
            "google.com" -> (True, "google.com", "")
            "https://www.example.com/login" -> (True, "example.com", "")
            "invalid..domain" -> (False, "", "Invalid domain format")
        """
        if not site or not isinstance(site, str):
            return False, "", "Site cannot be empty"

        site = site.strip()

        # Check length
        if len(site) > self.max_lengths['site']:
            return False, "", f"Site too long (max {self.max_lengths['site']} chars)"

        # Normalize site input - extract domain from URL if needed
        normalized_site = self._normalize_site(site)

        if not normalized_site:
            return False, "", "Could not extract valid domain from input"

        # Validate domain format
        if not self._is_valid_domain(normalized_site):
            return False, "", "Invalid domain format"

        # Check for suspicious characters
        if not all(c in self.SAFE_SITE_CHARS for c in normalized_site):
            return False, "", "Site contains invalid characters"

        return True, normalized_site, ""

    def validate_username(self, username: str) -> Tuple[bool, str, str]:
        """
        Validate username/email input.

        Args:
            username: Username or email to validate

        Returns:
            Tuple of (is_valid, cleaned_username, error_message)
        """
        if not username or not isinstance(username, str):
            return False, "", "Username cannot be empty"

        username = username.strip()

        # Check length
        if len(username) > self.max_lengths['username']:
            return False, "", f"Username too long (max {self.max_lengths['username']} chars)"

        # Check for dangerous characters
        if not all(c in self.SAFE_USERNAME_CHARS for c in username):
            dangerous_chars = set(username) - self.SAFE_USERNAME_CHARS
            return False, "", f"Username contains invalid characters: {''.join(dangerous_chars)}"

        # Basic format validation
        if '@' in username:
            # Validate as email
            if not self.EMAIL_PATTERN.match(username):
                return False, "", "Invalid email format"
        else:
            # Validate as regular username
            if len(username) < 1:
                return False, "", "Username too short"
            if username.startswith('.') or username.endswith('.'):
                return False, "", "Username cannot start or end with period"

        return True, username, ""

    def validate_password(
        self,
        password: str,
        min_length: int = 1,
        enforce_complexity: bool = False
    ) -> Tuple[bool, str]:
        """
        Validate password input.

        Args:
            password: Password to validate
            min_length: Minimum password length
            enforce_complexity: Whether to enforce complexity requirements

        Returns:
            Tuple of (is_valid, error_message)

        Note:
            This validates the password data itself, not its strength.
            For strength analysis, use PasswordStrengthChecker.
        """
        if not isinstance(password, str):
            return False, "Password must be a string"

        # Check length constraints
        if len(password) < min_length:
            return False, f"Password too short (minimum {min_length} characters)"

        if len(password) > self.max_lengths['password']:
            return False, f"Password too long (maximum {self.max_lengths['password']} characters)"

        # Check for null bytes (security risk)
        if '\x00' in password:
            return False, "Password cannot contain null bytes"

        # Optional complexity enforcement
        if enforce_complexity:
            complexity_error = self._check_password_complexity(password)
            if complexity_error:
                return False, complexity_error

        return True, ""

    def validate_notes(self, notes: str) -> Tuple[bool, str, str]:
        """
        Validate and sanitize notes field.

        Args:
            notes: Notes text to validate

        Returns:
            Tuple of (is_valid, cleaned_notes, error_message)
        """
        if not isinstance(notes, str):
            return False, "", "Notes must be a string"

        notes = notes.strip()

        # Check length
        if len(notes) > self.max_lengths['notes']:
            return False, "", f"Notes too long (max {self.max_lengths['notes']} chars)"

        # Remove potentially dangerous characters
        cleaned_notes = self._sanitize_text(notes)

        return True, cleaned_notes, ""

    def validate_master_password(self, password: str) -> Tuple[bool, str]:
        """
        Validate master password with stricter requirements.

        Args:
            password: Master password to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(password, str):
            return False, "Master password must be a string"

        # Stricter length requirements for master password
        if len(password) < 8:
            return False, "Master password must be at least 8 characters"

        if len(password) > self.max_lengths['master_password']:
            return False, f"Master password too long (max {self.max_lengths['master_password']} chars)"

        # Check for null bytes
        if '\x00' in password:
            return False, "Master password cannot contain null bytes"

        # Ensure minimum complexity for master password
        complexity_error = self._check_password_complexity(password)
        if complexity_error:
            return False, f"Master password {complexity_error.lower()}"

        return True, ""

    def _normalize_site(self, site: str) -> str:
        """
        Normalize site input by extracting domain from URL.

        Args:
            site: Raw site input

        Returns:
            Normalized domain string or empty string if invalid
        """
        site = site.lower().strip()

        # Remove common prefixes
        for prefix in ['https://', 'http://', 'www.']:
            if site.startswith(prefix):
                site = site[len(prefix):]

        # Extract domain part (remove path, query, fragment)
        try:
            parsed = urllib.parse.urlparse(f'http://{site}')
            domain = parsed.netloc or parsed.path.split('/')[0]

            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]

            return domain.lower()

        except Exception:
            return ""

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Check if string is a valid domain name.

        Args:
            domain: Domain string to validate

        Returns:
            True if valid domain format
        """
        if not domain or len(domain) > 255:
            return False

        # Check basic format
        if domain.startswith('.') or domain.endswith('.'):
            return False

        # Check for consecutive dots
        if '..' in domain:
            return False

        # Must contain at least one dot
        if '.' not in domain:
            return False

        # Use regex for detailed validation
        return bool(self.DOMAIN_PATTERN.match(domain))

    def _check_password_complexity(self, password: str) -> Optional[str]:
        """
        Check if password meets basic complexity requirements.

        Args:
            password: Password to check

        Returns:
            Error message if complexity not met, None if okay
        """
        if len(password) < 8:
            return "must be at least 8 characters long"

        # Check for at least 3 of 4 character types
        char_types = 0

        if any(c.islower() for c in password):
            char_types += 1
        if any(c.isupper() for c in password):
            char_types += 1
        if any(c.isdigit() for c in password):
            char_types += 1
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            char_types += 1

        if char_types < 3:
            return "must contain at least 3 types of characters (uppercase, lowercase, numbers, symbols)"

        return None

    def _sanitize_text(self, text: str) -> str:
        """
        Sanitize text by removing potentially dangerous characters.

        Args:
            text: Text to sanitize

        Returns:
            Sanitized text
        """
        # Remove null bytes and other control characters
        sanitized = ''.join(c for c in text if ord(c) >= 32 or c in '\t\n\r')

        # Remove excessive whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()

        return sanitized

    def validate_all_entry_data(
        self,
        site: str,
        username: str,
        password: str,
        notes: str = ""
    ) -> Tuple[bool, dict, List[str]]:
        """
        Validate all data for a password entry.

        Args:
            site: Site/domain
            username: Username/email
            password: Password
            notes: Optional notes

        Returns:
            Tuple of (all_valid, validated_data_dict, error_list)
        """
        errors = []
        validated_data = {}

        # Validate site
        site_valid, validated_site, site_error = self.validate_site(site)
        if site_valid:
            validated_data['site'] = validated_site
        else:
            errors.append(f"Site: {site_error}")

        # Validate username
        username_valid, validated_username, username_error = self.validate_username(username)
        if username_valid:
            validated_data['username'] = validated_username
        else:
            errors.append(f"Username: {username_error}")

        # Validate password
        password_valid, password_error = self.validate_password(password)
        if password_valid:
            validated_data['password'] = password
        else:
            errors.append(f"Password: {password_error}")

        # Validate notes (optional)
        if notes:
            notes_valid, validated_notes, notes_error = self.validate_notes(notes)
            if notes_valid:
                validated_data['notes'] = validated_notes
            else:
                errors.append(f"Notes: {notes_error}")
        else:
            validated_data['notes'] = ""

        all_valid = len(errors) == 0
        return all_valid, validated_data, errors


# Example usage and testing
if __name__ == "__main__":
    # Test input validation
    validator = InputValidator()

    print("Testing Taala InputValidator...")

    # Test site validation
    test_sites = [
        "google.com",
        "https://www.example.com/login",
        "sub.domain.co.uk",
        "invalid..domain",
        "http://localhost:8080",
        "bad-site.com/path?query=1"
    ]

    print("\nSite validation tests:")
    for site in test_sites:
        valid, normalized, error = validator.validate_site(site)
        print(f"'{site}' -> {valid}, '{normalized}', '{error}'")

    # Test username validation
    test_usernames = [
        "user@example.com",
        "john_doe123",
        "invalid@email",
        "user@domain.com",
        "bad<script>username"
    ]

    print("\nUsername validation tests:")
    for username in test_usernames:
        valid, cleaned, error = validator.validate_username(username)
        print(f"'{username}' -> {valid}, '{cleaned}', '{error}'")

    # Test master password validation
    test_passwords = [
        "weak",
        "StrongP@ss123",
        "NoNumbers!",
        "nocaps123!",
        "NOLOWER123!"
    ]

    print("\nMaster password validation tests:")
    for password in test_passwords:
        valid, error = validator.validate_master_password(password)
        print(f"'{password}' -> {valid}, '{error}'")

    # Test complete entry validation
    print("\nComplete entry validation test:")
    all_valid, data, errors = validator.validate_all_entry_data(
        site="https://www.github.com/login",
        username="developer@example.com",
        password="MySecureP@ssw0rd123",
        notes="Development account for GitHub"
    )

    print(f"All valid: {all_valid}")
    print(f"Validated data: {data}")
    print(f"Errors: {errors}")

    print("\nInputValidator test completed successfully!")
