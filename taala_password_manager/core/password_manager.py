"""
Main Password Manager class for Taala Password Manager

Coordinates all password management operations including encryption,
storage, validation, and user interaction. This is the primary interface
for all password management functionality.

Features:
- Secure initialization and master password setup
- Add, retrieve, update, and delete password entries
- Password generation and strength analysis
- Data import/export capabilities
- Comprehensive error handling and security logging
"""

import json
import getpass
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from cryptography.fernet import InvalidToken

from .crypto import CryptoManager
from .storage import StorageManager
from ..utils.validators import InputValidator, ValidationError
from ..utils.password_generator import PasswordGenerator, PasswordComplexity
from ..utils.password_strength import PasswordStrengthChecker, PasswordStrength


@dataclass
class PasswordEntry:
    """Data class representing a password entry."""
    site: str
    username: str
    password: str
    notes: str = ""
    created_at: str = ""
    modified_at: str = ""

    def __post_init__(self):
        """Set timestamps if not provided."""
        current_time = datetime.now().isoformat()
        if not self.created_at:
            self.created_at = current_time
        if not self.modified_at:
            self.modified_at = current_time

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PasswordEntry':
        """Create entry from dictionary."""
        return cls(**data)


class PasswordManagerError(Exception):
    """Custom exception for password manager operations."""
    pass


class PasswordManager:
    """
    Main password manager class providing secure password storage and management.

    This class coordinates all password management operations:
    - Secure initialization with master password
    - Encrypted storage of password entries
    - Password generation and strength analysis
    - Input validation and sanitization
    - Data import/export capabilities

    Security Features:
    - All data encrypted with AES-256 via Fernet
    - Master password derived with PBKDF2 (100,000 iterations)
    - Input validation prevents injection attacks
    - Atomic file operations prevent data corruption
    - Automatic backup creation
    """

    def __init__(self, data_directory: str = "data"):
        """
        Initialize password manager components.

        Args:
            data_directory: Directory for storing encrypted data files
        """
        self.crypto = CryptoManager()
        self.storage = StorageManager(data_directory)
        self.validator = InputValidator()
        self.password_generator = PasswordGenerator()
        self.strength_checker = PasswordStrengthChecker()

        self._master_password = None
        self._is_unlocked = False
        self._vault_data = {}  # In-memory password vault

    def is_initialized(self) -> bool:
        """Check if password manager has been set up."""
        return self.storage.is_initialized()

    def initialize(self, master_password: str) -> Tuple[bool, str]:
        """
        Initialize password manager with master password.

        Args:
            master_password: Master password for encryption

        Returns:
            Tuple of (success, error_message)

        Security Notes:
            - Master password is hashed with unique salt for verification
            - Encryption key derived separately for data protection
            - Creates empty encrypted vault file
        """
        if self.is_initialized():
            return False, "Password manager already initialized"

        # Validate master password
        valid, error = self.validator.validate_master_password(master_password)
        if not valid:
            return False, error

        try:
            # Generate salt for master password hashing
            password_salt = self.crypto.generate_salt()
            master_hash = self.crypto.hash_master_password(master_password, password_salt)

            # Save configuration
            config = {
                'master_password_hash': master_hash.hex(),
                'password_salt': password_salt.hex(),
                'created_at': datetime.now().isoformat(),
                'version': '1.0'
            }
            self.storage.save_config(config)

            # Create empty vault
            empty_vault = {}
            vault_json = json.dumps(empty_vault)
            encrypted_data, vault_salt = self.crypto.encrypt_data(vault_json, master_password)
            self.storage.save_vault_data(encrypted_data, vault_salt)

            return True, "Password manager initialized successfully"

        except Exception as e:
            return False, f"Initialization failed: {str(e)}"

    def unlock(self, master_password: str) -> Tuple[bool, str]:
        """
        Unlock password manager with master password.

        Args:
            master_password: Master password for authentication

        Returns:
            Tuple of (success, error_message)
        """
        if not self.is_initialized():
            return False, "Password manager not initialized"

        if self._is_unlocked:
            return True, "Already unlocked"

        try:
            # Load configuration and verify master password
            config = self.storage.load_config()
            stored_hash = bytes.fromhex(config['master_password_hash'])
            password_salt = bytes.fromhex(config['password_salt'])

            if not self.crypto.verify_master_password(master_password, stored_hash, password_salt):
                return False, "Invalid master password"

            # Load and decrypt vault data
            encrypted_data, vault_salt = self.storage.load_vault_data()
            vault_json = self.crypto.decrypt_data(encrypted_data, vault_salt, master_password)
            self._vault_data = json.loads(vault_json)

            # Set session state
            self._master_password = master_password
            self._is_unlocked = True

            return True, "Password manager unlocked successfully"

        except InvalidToken:
            return False, "Invalid master password or corrupted data"
        except FileNotFoundError as e:
            return False, f"Required file not found: {str(e)}"
        except Exception as e:
            return False, f"Unlock failed: {str(e)}"

    def lock(self) -> None:
        """Lock password manager and clear sensitive data from memory."""
        self._master_password = None
        self._is_unlocked = False
        self._vault_data.clear()

    def add_entry(
        self,
        site: str,
        username: str,
        password: str,
        notes: str = ""
    ) -> Tuple[bool, str]:
        """
        Add new password entry.

        Args:
            site: Website/service domain
            username: Username or email
            password: Password for the account
            notes: Optional notes

        Returns:
            Tuple of (success, error_message)
        """
        if not self._is_unlocked:
            return False, "Password manager is locked"

        # Validate all input data
        valid, validated_data, errors = self.validator.validate_all_entry_data(
            site, username, password, notes
        )

        if not valid:
            return False, "; ".join(errors)

        try:
            # Create password entry
            entry = PasswordEntry(
                site=validated_data['site'],
                username=validated_data['username'],
                password=validated_data['password'],
                notes=validated_data['notes']
            )

            # Check if entry already exists
            entry_key = f"{entry.site}::{entry.username}"
            if entry_key in self._vault_data:
                return False, f"Entry already exists for {entry.site} with username {entry.username}"

            # Add entry to vault
            self._vault_data[entry_key] = entry.to_dict()

            # Save vault
            success, error = self._save_vault()
            if not success:
                # Remove from memory if save failed
                del self._vault_data[entry_key]
                return False, f"Failed to save entry: {error}"

            return True, "Password entry added successfully"

        except Exception as e:
            return False, f"Failed to add entry: {str(e)}"

    def get_entry(self, site: str, username: str = None) -> Tuple[bool, Optional[PasswordEntry], str]:
        """
        Retrieve password entry.

        Args:
            site: Website/service domain
            username: Username (optional, returns first match if not provided)

        Returns:
            Tuple of (success, password_entry, error_message)
        """
        if not self._is_unlocked:
            return False, None, "Password manager is locked"

        # Validate and normalize site
        site_valid, normalized_site, site_error = self.validator.validate_site(site)
        if not site_valid:
            return False, None, f"Invalid site: {site_error}"

        try:
            if username:
                # Look for specific entry
                entry_key = f"{normalized_site}::{username}"
                if entry_key in self._vault_data:
                    entry_data = self._vault_data[entry_key]
                    entry = PasswordEntry.from_dict(entry_data)
                    return True, entry, ""
                else:
                    return False, None, f"No entry found for {normalized_site} with username {username}"
            else:
                # Find first entry for site
                for key, entry_data in self._vault_data.items():
                    if key.startswith(f"{normalized_site}::"):
                        entry = PasswordEntry.from_dict(entry_data)
                        return True, entry, ""

                return False, None, f"No entries found for {normalized_site}"

        except Exception as e:
            return False, None, f"Failed to retrieve entry: {str(e)}"

    def list_entries(self, site_filter: str = None) -> List[Dict[str, str]]:
        """
        List all password entries (without passwords).

        Args:
            site_filter: Optional site filter

        Returns:
            List of entry summaries (site, username, created_at)
        """
        if not self._is_unlocked:
            return []

        entries = []

        for entry_data in self._vault_data.values():
            # Apply site filter if provided
            if site_filter and site_filter.lower() not in entry_data['site'].lower():
                continue

            entries.append({
                'site': entry_data['site'],
                'username': entry_data['username'],
                'created_at': entry_data['created_at'],
                'has_notes': bool(entry_data.get('notes', ''))
            })

        # Sort by site, then username
        entries.sort(key=lambda x: (x['site'], x['username']))
        return entries

    def update_entry(
        self,
        site: str,
        username: str,
        new_password: str = None,
        new_notes: str = None
    ) -> Tuple[bool, str]:
        """
        Update existing password entry.

        Args:
            site: Website/service domain
            username: Username for the entry
            new_password: New password (optional)
            new_notes: New notes (optional)

        Returns:
            Tuple of (success, error_message)
        """
        if not self._is_unlocked:
            return False, "Password manager is locked"

        # Find existing entry
        success, entry, error = self.get_entry(site, username)
        if not success:
            return False, error

        try:
            entry_key = f"{entry.site}::{entry.username}"

            # Update fields if provided
            if new_password is not None:
                password_valid, password_error = self.validator.validate_password(new_password)
                if not password_valid:
                    return False, f"Invalid password: {password_error}"
                entry.password = new_password

            if new_notes is not None:
                notes_valid, cleaned_notes, notes_error = self.validator.validate_notes(new_notes)
                if not notes_valid:
                    return False, f"Invalid notes: {notes_error}"
                entry.notes = cleaned_notes

            # Update modification time
            entry.modified_at = datetime.now().isoformat()

            # Save updated entry
            self._vault_data[entry_key] = entry.to_dict()

            # Save vault
            save_success, save_error = self._save_vault()
            if not save_success:
                return False, f"Failed to save updated entry: {save_error}"

            return True, "Entry updated successfully"

        except Exception as e:
            return False, f"Failed to update entry: {str(e)}"

    def delete_entry(self, site: str, username: str) -> Tuple[bool, str]:
        """
        Delete password entry.

        Args:
            site: Website/service domain
            username: Username for the entry

        Returns:
            Tuple of (success, error_message)
        """
        if not self._is_unlocked:
            return False, "Password manager is locked"

        # Find existing entry
        success, entry, error = self.get_entry(site, username)
        if not success:
            return False, error

        try:
            entry_key = f"{entry.site}::{entry.username}"

            # Remove from vault
            del self._vault_data[entry_key]

            # Save vault
            save_success, save_error = self._save_vault()
            if not save_success:
                # Restore entry if save failed
                self._vault_data[entry_key] = entry.to_dict()
                return False, f"Failed to save after deletion: {save_error}"

            return True, "Entry deleted successfully"

        except Exception as e:
            return False, f"Failed to delete entry: {str(e)}"

    def generate_password(
        self,
        length: int = 16,
        complexity: PasswordComplexity = PasswordComplexity.STRONG
    ) -> str:
        """
        Generate secure password.

        Args:
            length: Password length
            complexity: Password complexity level

        Returns:
            Generated password string
        """
        return self.password_generator.generate_password(length, complexity)

    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Analyze password strength.

        Args:
            password: Password to analyze

        Returns:
            Dictionary with strength analysis results
        """
        analysis = self.strength_checker.analyze_password(password)

        return {
            'strength': analysis.strength.name,
            'score': analysis.score,
            'max_score': analysis.max_score,
            'entropy': analysis.entropy,
            'crack_time': analysis.estimated_crack_time,
            'issues': analysis.issues,
            'recommendations': analysis.recommendations
        }

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get password manager statistics.

        Returns:
            Dictionary with various statistics
        """
        if not self._is_unlocked:
            return {'error': 'Password manager is locked'}

        total_entries = len(self._vault_data)
        sites = set()
        weak_passwords = 0
        entries_with_notes = 0

        for entry_data in self._vault_data.values():
            sites.add(entry_data['site'])

            if entry_data.get('notes'):
                entries_with_notes += 1

            # Check password strength
            strength_analysis = self.strength_checker.analyze_password(entry_data['password'])
            if strength_analysis.strength.value <= 2:  # VERY_WEAK or WEAK
                weak_passwords += 1

        vault_info = self.storage.get_vault_info()

        return {
            'total_entries': total_entries,
            'unique_sites': len(sites),
            'entries_with_notes': entries_with_notes,
            'weak_passwords': weak_passwords,
            'vault_size_bytes': vault_info.get('size_bytes', 0),
            'backup_count': vault_info.get('backup_count', 0),
            'created_at': vault_info.get('created', 'Unknown'),
            'last_modified': vault_info.get('modified', 'Unknown')
        }

    def export_data(self, export_password: str = None) -> Tuple[bool, Optional[str], str]:
        """
        Export vault data as JSON.

        Args:
            export_password: Optional different password for export encryption

        Returns:
            Tuple of (success, json_data, error_message)
        """
        if not self._is_unlocked:
            return False, None, "Password manager is locked"

        try:
            export_data = {
                'metadata': {
                    'version': '1.0',
                    'exported_at': datetime.now().isoformat(),
                    'entry_count': len(self._vault_data)
                },
                'entries': list(self._vault_data.values())
            }

            json_data = json.dumps(export_data, indent=2)

            # Optionally encrypt with different password
            if export_password:
                encrypted_data, salt = self.crypto.encrypt_data(json_data, export_password)
                json_data = json.dumps({
                    'encrypted': True,
                    'data': encrypted_data.hex(),
                    'salt': salt.hex()
                }, indent=2)

            return True, json_data, ""

        except Exception as e:
            return False, None, f"Export failed: {str(e)}"

    def _save_vault(self) -> Tuple[bool, str]:
        """
        Save vault data to storage.

        Returns:
            Tuple of (success, error_message)
        """
        try:
            vault_json = json.dumps(self._vault_data)
            encrypted_data, vault_salt = self.crypto.encrypt_data(vault_json, self._master_password)
            self.storage.save_vault_data(encrypted_data, vault_salt)
            return True, ""

        except Exception as e:
            return False, str(e)


# Example usage demonstration
if __name__ == "__main__":
    # Demonstration of password manager usage
    print("Testing Taala PasswordManager...")

    # Create password manager instance
    pm = PasswordManager("test_data")

    # Test initialization
    if not pm.is_initialized():
        print("Initializing password manager...")
        success, error = pm.initialize("TestMasterPassword123!")
        print(f"Initialization: {success}, {error}")

    # Test unlock
    print("\nUnlocking password manager...")
    success, error = pm.unlock("TestMasterPassword123!")
    print(f"Unlock: {success}, {error}")

    if success:
        # Test adding entries
        print("\nAdding test entries...")

        test_entries = [
            ("github.com", "developer@example.com", "GitHubP@ssw0rd123", "Development account"),
            ("gmail.com", "user@gmail.com", "GmailSecure456!", "Personal email"),
        ]

        for site, username, password, notes in test_entries:
            success, error = pm.add_entry(site, username, password, notes)
            print(f"Add {site}: {success}, {error}")

        # Test listing entries
        print("\nListing entries:")
        entries = pm.list_entries()
        for entry in entries:
            print(f"- {entry['site']} ({entry['username']})")

        # Test password generation
        print("\nGenerating strong password:")
        strong_password = pm.generate_password(16, PasswordComplexity.STRONG)
        print(f"Generated: {strong_password}")

        # Test password strength analysis
        print("\nAnalyzing password strength:")
        analysis = pm.check_password_strength(strong_password)
        print(f"Strength: {analysis['strength']} ({analysis['score']}/{analysis['max_score']})")

        # Test statistics
        print("\nPassword manager statistics:")
        stats = pm.get_statistics()
        for key, value in stats.items():
            print(f"- {key}: {value}")

        print("\nPasswordManager test completed successfully!")

    # Clean up
    pm.lock()
