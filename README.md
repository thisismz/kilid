# 🔐 Kilid - Deterministic PGP Key Generator & File Encryption

**Kilid** (Persian for "Key") is a secure, deterministic PGP key generator and file encryption tool that creates reproducible cryptographic keys from BIP39 mnemonic seed phrases. Perfect for secure file encryption, backup systems, and deterministic key management.

## ✨ Features

- 🔑 **Deterministic PGP Key Generation**: Generate the same PGP keys from a given seed phrase
- 🌱 **BIP39 Mnemonic Support**: Uses industry-standard BIP39 for seed phrase generation
- 🔐 **File Encryption/Decryption**: Encrypt and decrypt files using generated PGP keys
- 💾 **Local Key Storage**: Save keys and mnemonics to local files with proper permissions
- 🛡️ **Security Focused**: Uses ChaCha20 for deterministic randomness and ProtonMail's go-crypto
- 🎯 **CLI Interface**: Simple command-line interface for easy automation
- 📦 **Go Native**: Written in Go for cross-platform compatibility

## 🚀 Quick Start

### Prerequisites

- Go 1.24.1 or higher
- Git

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/thisismz/kilid.git
   cd kilid
   ```

2. **Install dependencies**:
   ```bash
   go mod download
   ```

3. **Build the application**:
   ```bash
   go build -o kilid main.go
   ```

## 📖 Usage

### Command Line Interface

Kilid provides a comprehensive CLI with the following commands:

#### Generate and Save Keys

```bash
# Generate PGP keys and save to current directory
./kilid --save

# Generate PGP keys and save to specific directory
./kilid --save --output /path/to/secure/directory

# Customize user details
./kilid --save --user-name "John Doe" --user-email "john@example.com" --bip39-passphrase "my-secret-passphrase"
```

#### Encrypt Files

```bash
# Encrypt a file using a seed phrase
./kilid --encrypt --seed "your-seed-phrase-here" --input document.txt --encrypted document.enc

# Customize encryption parameters
./kilid --encrypt \
  --seed "your-seed-phrase-here" \
  --input sensitive.txt \
  --encrypted sensitive.enc \
  --user-name "Alice" \
  --user-email "alice@example.com"
```

#### Decrypt Files

```bash
# Decrypt a file using the same seed phrase
./kilid --decrypt --seed "your-seed-phrase-here" --encrypted document.enc --decrypted document.txt

# Customize decryption parameters
./kilid --decrypt \
  --seed "your-seed-phrase-here" \
  --encrypted sensitive.enc \
  --decrypted sensitive.txt \
  --user-name "Alice" \
  --user-email "alice@example.com"
```

### Command Line Options

| Flag | Description | Default | Required |
|------|-------------|---------|----------|
| `--save` | Save mnemonic and PGP keys to files | `false` | No |
| `--output` | Directory to save files | `.` | No |
| `--encrypt` | Encrypt a file | `false` | No |
| `--decrypt` | Decrypt a file | `false` | No |
| `--input` | Input file path | `test.txt` | Yes (for encrypt/decrypt) |
| `--encrypted` | Encrypted file path | `encrypted.txt` | No |
| `--decrypted` | Decrypted file path | `decrypted.txt` | No |
| `--user-name` | User name for PGP key | `thisismz` | No |
| `--user-email` | User email for PGP key | `mahdimozaffari@outlook.com` | No |
| `--bip39-passphrase` | BIP39 passphrase | `my-super-secret-passphrase` | No |
| `--seed` | Seed phrase for deterministic key generation | `` | Yes (for encrypt/decrypt) |

## 🔧 Examples

### Example 1: Generate Keys for Backup

```bash
# Generate a new set of PGP keys
./kilid --save --output ~/backup-keys

# This creates:
# - ~/backup-keys/mnemonic.txt (your seed phrase)
# - ~/backup-keys/public.asc (public key)
# - ~/backup-keys/private.asc (private key)
```

### Example 2: Encrypt Important Documents

```bash
# First, generate and save your keys
./kilid --save --output ~/my-keys

# Note the mnemonic from mnemonic.txt, then encrypt a file
./kilid --encrypt \
  --seed "your-mnemonic-phrase-from-file" \
  --input important-document.pdf \
  --encrypted important-document.enc
```

### Example 3: Decrypt Files on Another Machine

```bash
# On any machine with the same seed phrase, decrypt the file
./kilid --decrypt \
  --seed "your-mnemonic-phrase" \
  --encrypted important-document.enc \
  --decrypted important-document.pdf
```

### Example 4: Automated Backup Script

```bash
#!/bin/bash
# backup.sh - Automated encrypted backup

SEED_PHRASE="your-seed-phrase-here"
BACKUP_DIR="/backup"
SOURCE_DIR="/important-data"

# Create encrypted backup
tar -czf - "$SOURCE_DIR" | ./kilid --encrypt \
  --seed "$SEED_PHRASE" \
  --input - \
  --encrypted "$BACKUP_DIR/backup-$(date +%Y%m%d).enc"
```

## 🏗️ Architecture

### Project Structure

```
kilid/
├── main.go                 # CLI entry point and command handling
├── internal/
│   ├── generator/
│   │   ├── bip_seed.go     # BIP39 seed generation
│   │   └── key.go          # PGP key generation and management
│   └── sezar/
│       ├── encrypt.go      # File encryption logic
│       └── decrypt.go      # File decryption logic
├── go.mod                  # Go module dependencies
└── README.md              # This file
```

### Key Components

#### 1. **BIP39 Seed Generation** (`internal/generator/bip_seed.go`)
- Generates cryptographically secure entropy
- Creates human-readable mnemonic phrases
- Derives deterministic seeds from passphrases

#### 2. **PGP Key Generation** (`internal/generator/key.go`)
- Uses ChaCha20 for deterministic randomness
- Generates PGP key pairs from seeds
- Provides functions to get keys as strings or bytes
- Handles key serialization and storage

#### 3. **File Encryption** (`internal/sezar/encrypt.go`)
- Encrypts files using PGP public keys
- Streams large files efficiently
- Uses ProtonMail's go-crypto library

#### 4. **File Decryption** (`internal/sezar/decrypt.go`)
- Decrypts files using PGP private keys
- Verifies PGP signatures
- Handles encrypted file formats

## 🔒 Security Features

### Deterministic Key Generation
- **ChaCha20 Cipher**: Uses ChaCha20 for deterministic pseudo-random number generation
- **Seed-based**: All keys are derived from a single seed phrase
- **Reproducible**: Same seed always produces the same keys

### File Security
- **PGP Encryption**: Industry-standard OpenPGP encryption
- **Armored Format**: Keys and encrypted files use ASCII-armored format
- **Permission Control**: Files are created with restricted permissions (0600)

### Best Practices
- **Secure Storage**: Mnemonics and private keys are stored with proper file permissions
- **No Hardcoded Secrets**: All secrets are passed via command line or environment variables
- **Error Handling**: Comprehensive error handling prevents data loss

## 🛠️ Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/thisismz/kilid.git
cd kilid

# Install dependencies
go mod download

# Build the application
go build -o kilid main.go

# Run tests
go test ./...
```

### Dependencies

- **github.com/ProtonMail/go-crypto**: PGP encryption/decryption
- **github.com/tyler-smith/go-bip39**: BIP39 mnemonic generation
- **github.com/thisismz/env**: Environment variable management
- **golang.org/x/crypto**: Cryptographic primitives

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

- **Issues**: Report bugs and feature requests on [GitHub Issues](https://github.com/thisismz/kilid/issues)
- **Discussions**: Join the conversation on [GitHub Discussions](https://github.com/thisismz/kilid/discussions)
- **Security**: For security issues, please email security@example.com

## 🙏 Acknowledgments

- **ProtonMail**: For the excellent go-crypto library
- **BIP39**: For the mnemonic standard
- **OpenPGP**: For the encryption standard

---

**⚠️ Security Notice**: Always keep your seed phrases secure and never share them. The security of your encrypted files depends on the secrecy of your seed phrase. 