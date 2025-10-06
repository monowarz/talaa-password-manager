# Security Architecture of Taala Password Manager

## Overview

Taala Password Manager implements industry-standard security practices to protect user passwords and sensitive data. This document outlines the security architecture and design decisions.

## Encryption

### Primary Encryption: Fernet (AES-256)

- **Algorithm**: AES-256 in CBC mode with HMAC-SHA256 authentication
- **Library**: Python `cryptography` package's Fernet implementation
- **Key Size**: 256-bit encryption keys
- **Authentication**: Built-in HMAC provides integrity and authenticity verification

### Key Derivation: PBKDF2

- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000 (following OWASP recommendations)
- **Salt Size**: 128-bit (16 bytes) cryptographically random salt
- **Key Length**: 256-bit derived keys for Fernet encryption

## Master Password Security

### Password Hashing
- Master passwords are hashed using SHA-256 with unique salts
- Hash verification uses constant-time comparison to prevent timing attacks
- Original passwords are never stored, only secure hashes

### Password Validation
- Minimum 8 characters (12+ recommended)
- Requires at least 3 of 4 character types (upper, lower, digits, symbols)
- Strength analysis provides educational feedback to users

## Data Storage Security

### File Security
- All sensitive data encrypted before writing to disk
- Atomic file operations prevent corruption during writes
- Automatic backup creation before modifications
- Secure file permissions (readable only by owner)

### Data Separation
- Configuration data stored separately from encrypted vault
- Salt values stored with encrypted data but separate from keys
- Master password hash stored in configuration, not with passwords

## Memory Security

### Sensitive Data Handling
- Master passwords cleared from memory after use
- Vault data cleared when password manager is locked
- No plain-text passwords persist in memory longer than necessary

### Input Validation
- All user inputs validated and sanitized
- SQL injection prevention through parameterized operations
- Path traversal prevention in file operations
- Length limits to prevent DoS attacks

## Cryptographic Best Practices

### Random Number Generation
- Uses `os.urandom()` for cryptographically secure randomness
- All salts and keys generated using secure random sources
- Password generation uses `secrets` module (cryptographically secure)

### Key Management
- Unique salt for each encryption operation
- Master password and encryption keys derived separately
- No hardcoded cryptographic constants or keys

## Attack Resistance

### Brute Force Protection
- High iteration count (100,000) increases computation cost
- Strong password requirements reduce attack surface
- Password strength analysis educates users about security

### Dictionary Attacks
- Unique salts prevent rainbow table attacks
- PBKDF2 with high iterations makes offline attacks expensive
- Common password detection warns users

### Timing Attacks
- Constant-time comparison for password verification
- No early returns in cryptographic operations
- Consistent operation timing regardless of input

## Limitations and Considerations

### Local Storage Only
- No cloud synchronization reduces attack surface
- User responsible for backup and recovery
- Single point of failure if master password forgotten
