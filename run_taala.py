#!/usr/bin/env python3
"""
Simple launcher for Taala Password Manager.
This script can be run from anywhere and will find the correct modules.
"""

import sys
import os
from pathlib import Path

def find_taala_root():
    """Find the root directory containing taala_password_manager."""
    current_dir = Path.cwd()

    # Check current directory and parent directories
    for path in [current_dir] + list(current_dir.parents):
        taala_dir = path / "taala_password_manager"
        if taala_dir.exists() and (taala_dir / "cli" / "main.py").exists():
            return path

    return None

def main():
    """Main launcher function."""
    # Find the project root
    project_root = find_taala_root()

    if not project_root:
        print("❌ Error: Could not find taala_password_manager directory.")
        print("Make sure you're running this from the project directory or a subdirectory.")
        sys.exit(1)

    # Add project root to Python path
    sys.path.insert(0, str(project_root))

    try:
        # Import and run the CLI
        from taala_password_manager.cli.main import main as cli_main
        cli_main()
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("\nTroubleshooting steps:")
        print("1. Install dependencies: pip install cryptography colorama")
        print("2. Check that all files are in the correct directories")
        print("3. Make sure __init__.py files exist in all package directories")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
