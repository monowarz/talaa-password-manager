"""
Storage management for Taala Password Manager

Handles secure persistence of encrypted password data to local files.
Implements proper file handling with atomic operations and backup mechanisms.

Storage Format:
- JSON-based encrypted storage
- Atomic file operations to prevent corruption
- Backup creation before modifications
"""

import os
import json
import shutil
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path


class StorageManager:
    """
    Manages secure storage and retrieval of encrypted password data.

    Features:
    - JSON-based storage format
    - Atomic file operations to prevent data corruption
    - Automatic backup creation
    - Proper error handling and recovery
    - Metadata tracking (creation/modification dates)
    """

    def __init__(self, data_directory: str = "data"):
        """
        Initialize storage manager with data directory.

        Args:
            data_directory: Path to directory for storing encrypted data
        """
        self.data_dir = Path(data_directory)
        self.data_dir.mkdir(exist_ok=True)  # Create directory if it doesn't exist

        # File paths
        self.vault_file = self.data_dir / "password_vault.enc"
        self.config_file = self.data_dir / "config.json"
        self.backup_dir = self.data_dir / "backups"

        # Ensure backup directory exists
        self.backup_dir.mkdir(exist_ok=True)

    def save_vault_data(self, encrypted_data: bytes, salt: bytes) -> None:
        """
        Save encrypted vault data to file using atomic operations.

        Args:
            encrypted_data: Encrypted password vault data
            salt: Salt used for encryption (stored separately)

        Security Notes:
            - Uses atomic write operations to prevent corruption
            - Creates backup before modifying existing data
            - Stores salt separately from encrypted data
        """
        # Create backup of existing vault if it exists
        if self.vault_file.exists():
            self._create_backup()

        # Prepare data structure
        vault_data = {
            'encrypted_data': encrypted_data.hex(),  # Convert bytes to hex string
            'salt': salt.hex(),
            'created_at': datetime.now().isoformat(),
            'version': '1.0'
        }

        # Use atomic write operation
        self._atomic_write(self.vault_file, json.dumps(vault_data, indent=2))

    def load_vault_data(self) -> Tuple[bytes, bytes]:
        """
        Load encrypted vault data and salt from file.

        Returns:
            Tuple of (encrypted_data, salt) as bytes

        Raises:
            FileNotFoundError: If vault file doesn't exist
            ValueError: If vault file is corrupted or invalid format
        """
        if not self.vault_file.exists():
            raise FileNotFoundError(f"Vault file not found: {self.vault_file}")

        try:
            with open(self.vault_file, 'r') as f:
                vault_data = json.load(f)

            # Extract and convert hex strings back to bytes
            encrypted_data = bytes.fromhex(vault_data['encrypted_data'])
            salt = bytes.fromhex(vault_data['salt'])

            return encrypted_data, salt

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ValueError(f"Corrupted vault file: {e}")

    def save_config(self, config_data: Dict[str, Any]) -> None:
        """
        Save configuration data (master password hash, etc.).

        Args:
            config_data: Dictionary containing configuration

        Configuration typically includes:
        - master_password_hash: Hashed master password
        - password_salt: Salt for password hashing
        - security_settings: Various security parameters
        - metadata: Creation date, version, etc.
        """
        # Add metadata
        config_data.update({
            'last_modified': datetime.now().isoformat(),
            'version': '1.0'
        })

        # Use atomic write for configuration
        self._atomic_write(self.config_file, json.dumps(config_data, indent=2))

    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration data from file.

        Returns:
            Dictionary containing configuration data

        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If config file is corrupted
        """
        if not self.config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")

        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Corrupted configuration file: {e}")

    def vault_exists(self) -> bool:
        """Check if password vault file exists."""
        return self.vault_file.exists()

    def config_exists(self) -> bool:
        """Check if configuration file exists."""
        return self.config_file.exists()

    def is_initialized(self) -> bool:
        """Check if password manager has been initialized."""
        return self.vault_exists() and self.config_exists()

    def _atomic_write(self, file_path: Path, content: str) -> None:
        """
        Perform atomic write operation to prevent file corruption.

        Args:
            file_path: Target file path
            content: Content to write

        Security Notes:
            - Writes to temporary file first
            - Only replaces target file if write is successful
            - Prevents partial writes that could corrupt data
        """
        # Create temporary file in same directory as target
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                dir=file_path.parent,
                delete=False,
                prefix=f".{file_path.name}.tmp"
            ) as f:
                temp_file = Path(f.name)
                f.write(content)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk

            # Atomically replace target file
            temp_file.replace(file_path)

        except Exception as e:
            # Clean up temp file if something goes wrong
            if temp_file and temp_file.exists():
                temp_file.unlink()
            raise e

    def _create_backup(self) -> None:
        """
        Create timestamped backup of existing vault file.

        Backups are stored in backups/ subdirectory with timestamp.
        Only keeps last 10 backups to prevent disk space issues.
        """
        if not self.vault_file.exists():
            return

        # Create timestamped backup filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"vault_backup_{timestamp}.enc"

        # Copy vault file to backup
        shutil.copy2(self.vault_file, backup_file)

        # Clean up old backups (keep only last 10)
        self._cleanup_old_backups()

    def _cleanup_old_backups(self, keep_count: int = 10) -> None:
        """
        Remove old backup files, keeping only the most recent ones.

        Args:
            keep_count: Number of backup files to keep
        """
        backup_files = list(self.backup_dir.glob("vault_backup_*.enc"))

        # Sort by modification time (newest first)
        backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

        # Remove old backups beyond keep_count
        for old_backup in backup_files[keep_count:]:
            try:
                old_backup.unlink()
            except OSError:
                pass  # Ignore errors when removing old backups

    def get_vault_info(self) -> Dict[str, Any]:
        """
        Get information about the vault file.

        Returns:
            Dictionary with vault metadata (size, dates, etc.)
        """
        if not self.vault_file.exists():
            return {"exists": False}

        stat = self.vault_file.stat()

        return {
            "exists": True,
            "size_bytes": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "backup_count": len(list(self.backup_dir.glob("vault_backup_*.enc")))
        }

    def export_vault(self, export_path: str) -> None:
        """
        Export encrypted vault to specified location.

        Args:
            export_path: Path where to export the vault file

        Note:
            Exports the raw encrypted vault file.
            User needs master password to decrypt exported vault.
        """
        if not self.vault_file.exists():
            raise FileNotFoundError("No vault file to export")

        export_file = Path(export_path)
        export_file.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(self.vault_file, export_file)

    def clear_all_data(self) -> None:
        """
        Securely remove all password manager data.

        Warning:
            This permanently deletes all stored passwords and configuration.
            This operation cannot be undone.
        """
        # Remove main files
        files_to_remove = [self.vault_file, self.config_file]

        for file_path in files_to_remove:
            if file_path.exists():
                file_path.unlink()

        # Remove all backups
        for backup_file in self.backup_dir.glob("vault_backup_*.enc"):
            backup_file.unlink()


# Example usage for testing
if __name__ == "__main__":
    # Test storage operations
    print("Testing Taala StorageManager...")

    # Create test storage manager
    storage = StorageManager("test_data")

    # Test configuration saving/loading
    test_config = {
        "master_password_hash": "test_hash_value",
        "password_salt": "test_salt_value",
        "security_level": "high"
    }

    print("Testing configuration save/load...")
    storage.save_config(test_config)
    loaded_config = storage.load_config()
    print(f"Config saved and loaded successfully: {loaded_config['security_level'] == 'high'}")

    # Test vault data operations
    test_encrypted_data = b"encrypted_test_data"
    test_salt = b"test_salt_16byte"

    print("Testing vault save/load...")
    storage.save_vault_data(test_encrypted_data, test_salt)
    loaded_encrypted, loaded_salt = storage.load_vault_data()

    print(f"Vault data saved and loaded successfully: {test_encrypted_data == loaded_encrypted}")
    print(f"Salt saved and loaded successfully: {test_salt == loaded_salt}")

    # Test vault info
    vault_info = storage.get_vault_info()
    print(f"Vault info: {vault_info['exists']} exists, {vault_info['size_bytes']} bytes")

    print("StorageManager test completed successfully!")
