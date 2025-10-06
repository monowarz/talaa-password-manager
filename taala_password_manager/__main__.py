"""
Entry point for running Taala Password Manager as a module.

This allows the password manager to be run with:
    python -m taala_password_manager

Delegates to the CLI main function.
"""

from .cli.main import main

if __name__ == '__main__':
    main()
