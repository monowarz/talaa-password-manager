# Taala Password Manager

A lightweight, educational password manager.

## Features

- **Secure Local Storage**: All passwords encrypted with AES-256 via Fernet
- **Master Password Protection**: PBKDF2 key derivation with 100,000 iterations
- **Password Strength Analysis**: Built-in password strength checker
- **Educational Focus**: Demonstrates cryptographic best practices

## Quick Start

### Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Initialize the password manager:
```bash
cd taala_password_manager
python -m cli.main init
```

3. Add your first password:
```bash
python -m cli.main add --site github.com --username your-email@example.com --generate
```

### Basic Commands

```bash
# Add a password (with generation)
python -m cli.main add --site example.com --username user@example.com --generate

# Retrieve a password
python -m cli.main get example.com

# List all entries
python -m cli.main list

# Generate secure password
python -m cli.main generate --length 16 --complexity strong

# Check password strength
python -m cli.main strength

# View statistics
python -m cli.main stats
```

## Security Features

- **AES-256 Encryption**: All data encrypted with Fernet
- **PBKDF2 Key Derivation**: 100,000 iterations with SHA-256
- **Secure Random Generation**: Cryptographically secure password generation
- **Input Validation**: Prevents injection attacks
- **Atomic File Operations**: Prevents data corruption

## Educational Value

This project demonstrates:
- Practical cryptography implementation
- OWASP security guidelines compliance
- Professional software architecture
- Command-line interface development
- Security best practices

## Disclaimer

This is an educational project. While it implements industry-standard security practices, use caution when storing highly sensitive production passwords.

## Documentation

- [Security Architecture](docs/SECURITY.md)
- [Project Structure](PROJECT_STRUCTURE.md)

## Testing

Run the unit tests:
```bash
python tests/test_crypto.py
```

## Author

Mohtashim Monowar
Created as a cybersecurity project demonstrating practical application of encryption and secure coding principles.
