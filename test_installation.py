#!/usr/bin/env python3
"""
Test script to verify Taala Password Manager installation.
"""

import sys
import os
from pathlib import Path

def test_directory_structure():
    """Test if directory structure is correct."""
    print("🔍 Testing directory structure...")

    required_dirs = [
        "taala_password_manager",
        "taala_password_manager/core",
        "taala_password_manager/utils", 
        "taala_password_manager/cli",
        "taala_password_manager/data"
    ]

    required_files = [
        "taala_password_manager/__init__.py",
        "taala_password_manager/core/__init__.py",
        "taala_password_manager/core/crypto.py",
        "taala_password_manager/core/storage.py",
        "taala_password_manager/core/password_manager.py",
        "taala_password_manager/utils/__init__.py",
        "taala_password_manager/utils/password_generator.py",
        "taala_password_manager/utils/password_strength.py",
        "taala_password_manager/utils/validators.py",
        "taala_password_manager/cli/__init__.py",
        "taala_password_manager/cli/main.py"
    ]

    missing_dirs = []
    missing_files = []

    for directory in required_dirs:
        if not Path(directory).exists():
            missing_dirs.append(directory)

    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)

    if missing_dirs:
        print(f"❌ Missing directories: {missing_dirs}")
        return False

    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False

    print("✅ Directory structure is correct!")
    return True

def test_dependencies():
    """Test if required dependencies are installed."""
    print("\n🔍 Testing dependencies...")

    try:
        import cryptography
        print("✅ cryptography library found")
    except ImportError:
        print("❌ cryptography library not found - run: pip install cryptography")
        return False

    try:
        import colorama
        print("✅ colorama library found")
    except ImportError:
        print("⚠️  colorama library not found - run: pip install colorama (optional)")

    return True

def test_imports():
    """Test if modules can be imported."""
    print("\n🔍 Testing module imports...")

    # Add current directory to path
    sys.path.insert(0, str(Path.cwd()))

    try:
        from taala_password_manager.core.crypto import CryptoManager
        print("✅ CryptoManager imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import CryptoManager: {e}")
        return False

    try:
        from taala_password_manager.core.storage import StorageManager
        print("✅ StorageManager imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import StorageManager: {e}")
        return False

    try:
        from taala_password_manager.core.password_manager import PasswordManager
        print("✅ PasswordManager imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import PasswordManager: {e}")
        return False

    try:
        from taala_password_manager.utils.password_generator import PasswordGenerator
        print("✅ PasswordGenerator imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import PasswordGenerator: {e}")
        return False

    try:
        from taala_password_manager.cli.main import main
        print("✅ CLI main imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import CLI main: {e}")
        return False

    return True

def test_basic_functionality():
    """Test basic functionality."""
    print("\n🔍 Testing basic functionality...")

    try:
        from taala_password_manager.core.crypto import CryptoManager

        # Test crypto operations
        crypto = CryptoManager()
        test_data = "test encryption data"
        test_password = "test_password_123"

        # Test encryption/decryption
        encrypted_data, salt = crypto.encrypt_data(test_data, test_password)
        decrypted_data = crypto.decrypt_data(encrypted_data, salt, test_password)

        if decrypted_data == test_data:
            print("✅ Encryption/decryption working correctly")
        else:
            print("❌ Encryption/decryption failed")
            return False

        # Test password generation
        from taala_password_manager.utils.password_generator import PasswordGenerator
        generator = PasswordGenerator()
        password = generator.generate_password(16)

        if len(password) == 16:
            print("✅ Password generation working correctly")
        else:
            print("❌ Password generation failed")
            return False

        return True

    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🧪 Taala Password Manager Installation Test")
    print("=" * 50)

    all_passed = True

    # Run tests
    all_passed &= test_directory_structure()
    all_passed &= test_dependencies()
    all_passed &= test_imports()
    all_passed &= test_basic_functionality()

    print("\n" + "=" * 50)

    if all_passed:
        print("🎉 All tests passed! Taala Password Manager is ready to use.")
        print("\n🚀 Quick start:")
        print("   python run_taala.py init       # Initialize password manager")
        print("   python run_taala.py add        # Add a password")
        print("   python run_taala.py generate   # Generate a password")
    else:
        print("❌ Some tests failed. Please fix the issues above.")
        print("\n🔧 Common fixes:")
        print("   pip install cryptography colorama")
        print("   Check that all files are in correct directories")
        print("   Make sure __init__.py files exist")

    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
