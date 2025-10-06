#!/usr/bin/env python3
"""
Setup script to organize Taala Password Manager files into correct structure.
Run this script in the directory containing all the downloaded files.
"""

import os
import shutil
from pathlib import Path

def create_directory_structure():
    """Create the required directory structure."""

    directories = [
        "taala_password_manager",
        "taala_password_manager/core", 
        "taala_password_manager/utils",
        "taala_password_manager/cli",
        "taala_password_manager/data",
        "tests",
        "docs"
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {directory}")

def move_files():
    """Move files to their correct locations."""

    file_moves = {
        # Core module files
        "crypto.py": "taala_password_manager/core/crypto.py",
        "storage.py": "taala_password_manager/core/storage.py", 
        "password_manager.py": "taala_password_manager/core/password_manager.py",

        # Utils module files
        "password_generator.py": "taala_password_manager/utils/password_generator.py",
        "password_strength.py": "taala_password_manager/utils/password_strength.py",
        "validators.py": "taala_password_manager/utils/validators.py",

        # CLI module files
        "main.py": "taala_password_manager/cli/main.py",

        # Test files
        "test_crypto.py": "tests/test_crypto.py",

        # Documentation
        "SECURITY.md": "docs/SECURITY.md",

        # Data directory
        "data_gitkeep.txt": "taala_password_manager/data/.gitkeep",

        # Root files stay in root
        "README.md": "README.md",
        "requirements.txt": "requirements.txt",
        "setup.py": "setup.py", 
        ".gitignore": ".gitignore",
        "__main__.py": "taala_password_manager/__main__.py",
        "PROJECT_STRUCTURE.md": "PROJECT_STRUCTURE.md"
    }

    moved_count = 0
    for source, destination in file_moves.items():
        if os.path.exists(source):
            # Create destination directory if it doesn't exist
            dest_dir = os.path.dirname(destination)
            if dest_dir:
                Path(dest_dir).mkdir(parents=True, exist_ok=True)

            shutil.move(source, destination)
            print(f"Moved {source} -> {destination}")
            moved_count += 1
        else:
            print(f"Warning: {source} not found (this might be normal)")

    print(f"Successfully moved {moved_count} files")

def create_init_files():
    """Create __init__.py files for Python packages."""

    init_files = {
        "taala_password_manager/__init__.py": '''"""
Taala Password Manager - A lightweight, educational password manager
"""

__version__ = "1.0.0"
__author__ = "Mohtashim Monowar"
''',

        "taala_password_manager/core/__init__.py": '''"""
Core functionality modules for Taala Password Manager
"""
''',

        "taala_password_manager/utils/__init__.py": '''"""
Utility modules for Taala Password Manager
"""
''',

        "taala_password_manager/cli/__init__.py": '''"""
Command Line Interface for Taala Password Manager
"""
'''
    }

    for file_path, content in init_files.items():
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"Created {file_path}")

def fix_imports():
    """Fix import statements in the main CLI file."""
    main_py_path = "taala_password_manager/cli/main.py"

    if os.path.exists(main_py_path):
        with open(main_py_path, 'r') as f:
            content = f.read()

        # Fix the import path at the top of main.py
        fixed_content = content.replace(
            "from taala_password_manager.core.password_manager import PasswordManager",
            "import sys\nimport os\nsys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))\nfrom taala_password_manager.core.password_manager import PasswordManager"
        )

        with open(main_py_path, 'w') as f:
            f.write(fixed_content)

        print("Fixed imports in main.py")

def main():
    """Main setup function."""
    print("🔧 Setting up Taala Password Manager project structure...")
    print("=" * 60)

    create_directory_structure()
    print()

    move_files()
    print()

    create_init_files()
    print()

    fix_imports()
    print()

    print("✅ Setup complete!")
    print("=" * 60)
    print("Next steps:")
    print("1. Install dependencies:")
    print("   pip install cryptography colorama")
    print()
    print("2. Test the setup:")
    print("   cd taala_password_manager")  
    print("   python -m cli.main --help")
    print()
    print("3. Initialize the password manager:")
    print("   python -m cli.main init")
    print()
    print("4. Add your first password:")
    print("   python -m cli.main add")
    print()
    print("5. Generate a secure password:")
    print("   python -m cli.main generate")

if __name__ == "__main__":
    main()
