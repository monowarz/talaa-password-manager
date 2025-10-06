# Taala Password Manager

A lightweight, password manager built to demonstrate hands-on implementation of encryption and password management principles.
---

## Features

- **Secure Local Storage**: Passwords are fully encrypted using AES-256 (Fernet)
- **Master Password Protection**: Strong PBKDF2 key derivation and salted hashing (100,000 iterations)
- **CLI Interface**: Simple and secure command-line tool for all operations
- **Password Strength Analysis**: Automated and educational feedback on password ecology
- **Password Generation**: Customizable, secure password creation with complexity options
- **Atomic File Operations**: Prevents data corruption and provides robust backup on update
- **No Cloud or Sync**: All data stays on your own device (local-first by design)

---

## Quick Start

### **Installation**

1. **Clone the repo and install pips:**
    ```bash
    git clone https://github.com/monowarz/talaa-password-manager.git
    cd talaa-password-manager
    pip install -r requirements.txt
    ```

---

### **Basic Workflow**

**Initialize vault with a master password:**
```bash
python run_taala.py init
```

**Add your first password:**
```bash
python run_taala.py add --site example.com --username user@example.com --generate
```

**List all stored entries:**
```bash
python run_taala.py list
```

**Retrieve a password:**
```bash
python run_taala.py get example.com
```

**Generate a secure password:**
```bash
python run_taala.py generate --length 20 --complexity strong
```

**Check password strength:**
```bash
python run_taala.py strength --password My$uperStrongP455w0rd!
```

**View overall statistics:**
```bash
python run_taala.py stats
```

---

## 📝 **Command Reference**

| Command                                         | What It Does                                                         |
|-------------------------------------------------|----------------------------------------------------------------------|
| `python run_taala.py init`                      | Initialize manager and set master password (run ONCE)                |
| `python run_taala.py add --site [site]...`      | Adds (or updates) a password for given site/username                 |
| `python run_taala.py get [site]`                | Retrieves password entry for given site (prompts for master PW)      |
| `python run_taala.py list`                      | Lists all stored site/username pairs (no passwords shown here)       |
| `python run_taala.py generate --length [N] ...` | Generates a new random password (optionally sets complexity)         |
| `python run_taala.py strength --password [pw]`  | Analyzes a password and shows entropy, crack time, suggestions       |
| `python run_taala.py stats`                     | View summary stats (number of entries, unique domains, weak pw's)    |

### **Adding Passwords - Detailed Examples**

```bash
# Interactive mode (prompts for all fields)
python run_taala.py add

# Generate password automatically
python run_taala.py add --site github.com --username your@email.com --generate

# Specify your own password
python run_taala.py add --site facebook.com --username your@email.com --password MySecretPassword123

# Add with notes
python run_taala.py add --site work-email.com --username john.doe@company.com --notes "Work email account"

# Different complexity levels for generated passwords
python run_taala.py add --site test.com --username user --generate --complexity simple
python run_taala.py add --site test.com --username user --generate --complexity moderate  
python run_taala.py add --site test.com --username user --generate --complexity strong
```

### **Password Generation Options**

```bash
# Basic generation
python run_taala.py generate

# Custom length
python run_taala.py generate --length 24

# Different complexity levels
python run_taala.py generate --complexity simple      # Letters and numbers only
python run_taala.py generate --complexity moderate    # Letters, numbers, basic symbols
python run_taala.py generate --complexity strong      # Full character set

# Generate multiple passwords at once
python run_taala.py generate --count 5 --length 16
```

### **Password Strength Analysis**

```bash
# Analyze a password interactively (secure input)
python run_taala.py strength

# Analyze a specific password
python run_taala.py strength --password "MyPassword123!"

# The analysis will show:
# - Strength level (Very Weak to Very Strong)
# - Entropy score and bits
# - Estimated crack time
# - Specific issues found
# - Recommendations for improvement
```

---

## **How It Works**

- Your **master password** is never stored—only a salted hash is kept for verification.
- ALL password data is encrypted with a key derived using PBKDF2 from your master password.
- **Each password vault update is backed up** automatically before being replaced.
- Passwords can only be revealed after decrypting with your master password every time.
- The application uses industry-standard cryptographic libraries and follows OWASP security guidelines.

---

## **Security Features**

- **AES-256 Encryption**: All data encrypted with Fernet (AES-256-CBC + HMAC)
- **PBKDF2 Key Derivation**: 100,000 iterations with SHA-256 (prevents brute force attacks)
- **Secure Random Generation**: Uses Python's `secrets` module for cryptographically secure passwords
- **Input Validation**: Comprehensive validation prevents injection attacks and malformed data
- **Atomic File Operations**: Prevents data corruption during saves
- **Constant-Time Comparison**: Prevents timing attacks during password verification
- **Unique Salts**: Each encryption operation uses a unique salt

---

## **Important Notes**

### **Site Name Format**
When adding passwords, use **domain names** only (not company names):
- ✅ Correct: `gmail.com`, `github.com`, `facebook.com`
- ❌ Incorrect: `Gmail`, `Google`, `Facebook`

### **Master Password Requirements**
Your master password should be:
- At least 12 characters long (16+ recommended)
- Include uppercase letters, lowercase letters, numbers, and symbols
- Be unique and not used elsewhere
- Be memorable but not predictable (avoid personal information)

### **Data Location**
All encrypted data is stored locally in the `data/` folder:
- `data/password_vault.enc` - Your encrypted password vault
- `data/config.json` - Configuration and master password hash
- `data/backups/` - Automatic backups of your vault

---

## **Security & Usage Tips**

- **Treat your master password like the key to a safe**: if you forget it, your data is forever lost!
- **Use strong, unique passwords**: The password generator can help create secure passwords.

---

## **Testing**

Run the provided unit tests:
```bash
python tests/test_crypto.py
```

Test the installation:
```bash
python test_installation.py
```

---

## **Documentation**

- [Security Architecture](docs/SECURITY.md)
- [Project Structure](PROJECT_STRUCTURE.md) 

---

## **Getting Started Checklist**

- [ ] Install dependencies: `pip install -r requirements.txt`
- [ ] Initialize vault: `python run_taala.py init`
- [ ] Choose a strong master password (write it down safely!)
- [ ] Add your first password: `python run_taala.py add --generate`
- [ ] Test retrieval: `python run_taala.py get [site]`
- [ ] Explore other commands: `python run_taala.py --help`

---

## **Contributing**

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Submit a pull request

For bugs or feature requests, please open an issue.

---

## **License**

This project is open source. Please see the LICENSE file for details.

---

## **Author**

**Mohtashim Monowar**  
Built as cybersecurity project to demonstrate hands-on implementation of secure coding, encryption, and password management principles.

Connect with me:
- GitHub: [@monowarz](https://github.com/monowarz)
- Portfolio: [Monowar](https://monowar.eu.org/p/works.html)
- Email: mmonowar@fandm.edu

---

## ⭐ **Show Your Support**

If this project helped you learn about cybersecurity or password management, please consider giving it a star! ⭐

---

*This project demonstrates practical application of cryptographic security principles for educational purposes.*
