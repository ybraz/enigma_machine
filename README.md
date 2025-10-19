# Enigma Machine v2.1 - Modern Cryptography

Educational cryptography system based on the historic Enigma Machine, modernized with strong cryptography using **AES-GCM (AEAD)**, **Argon2id** for key derivation, and advanced security features.

## Security Improvements

### 1. AES-GCM (AEAD) with Random IV
- **Replaced**: AES-CBC with derived IV (insecure)
- **Implemented**: AES-GCM with 12-byte random IV per message
- **Benefits**:
  - Confidentiality + Integrity in a single operation
  - Message authentication (detects tampering)
  - Unique random IV for each operation

### 2. Argon2id for Key Derivation
- **Replaced**: Direct SHA-256 (vulnerable to brute force)
- **Implemented**: Argon2id with strong parameters:
  - Time cost: 3 iterations
  - Memory cost: 64 MB
  - Parallelism: 4 threads
  - Unique 32-byte salt per message
- **Benefits**: Resistant to GPU/ASIC attacks

### 3. MD5 Completely Removed
- **Removed**: MD5 usage for deriving IVs
- **Implemented**: `os.urandom()` for cryptographically secure generation

### 4. Versioning and Authenticated Headers
- **Structured header** containing:
  - Format version
  - KDF used (argon2id)
  - KDF parameters
  - Salt (32 bytes)
  - Config salt (16 bytes)
  - IV (12 bytes)
- **Authentication**: Header used as AAD in AES-GCM
- **Compatibility**: Version checking during decryption

### 5. Non-Deterministic Configuration Derivation
- **Configuration salt** unique per message
- Same password can generate different Enigma configurations
- Prevents attacks based on known configurations

### 6. Password Strength Meter
- Password entropy calculation
- Visual feedback on password strength
- Warnings about weak passwords
- Improvement recommendations

### 7. Hybrid Scheme (X25519 + AES-GCM)
- X25519 keypair generation
- ECDH for key exchange
- Enables encryption without shared password
- Ephemeral keys for forward secrecy

### 8. File Encryption with Streaming
- Support for large files
- 64 KB chunks
- Progress bar
- Each chunk with unique IV

### 9. Robust CLI
- Subcommands: `encrypt`, `decrypt`, `encrypt-file`, `decrypt-file`
- Interactive mode
- Command-line mode

### 10. Web Interface
- **Modern web GUI**: Built with Flask
- **Real-time password strength indicator**: Visual feedback with colors
- **File upload/download**: Easy file encryption/decryption
- **Clipboard integration**: Copy/paste functionality
- **Responsive design**: Works on all screen sizes

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd enigma_machine

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Web Interface (GUI) - Recommended

The easiest way to use is through the web interface:

```bash
python3 enigma_gui.py
```

Then open your browser at: **http://127.0.0.1:5000**

**GUI Features:**
- 🎨 Modern and intuitive interface
- 🔒 Tab for encrypting messages
- 🔓 Tab for decrypting messages
- 📁 Tab for encrypting files
- 📂 Tab for decrypting files
- 💪 Real-time password strength indicator with visual feedback
- 📋 Copy/paste buttons with clipboard integration
- ⚡ Async operations with loading indicators
- 📊 Progress feedback for all operations
- 🌐 Works on any modern browser
- 📱 Responsive design

### Interactive Mode (Terminal)

```bash
python enigma_machine_aesv2.py
```

Interactive menu with options:
1. Encrypt message
2. Decrypt message
3. Encrypt file
4. Decrypt file

### CLI Mode

#### Encrypt Message

```bash
# With interactive prompt
python enigma_machine_aesv2.py encrypt

# With inline message
python enigma_machine_aesv2.py encrypt -m "Secret message"

# Save to file
python enigma_machine_aesv2.py encrypt -m "Secret message" -o encrypted.txt
```

#### Decrypt Message

```bash
# From file
python enigma_machine_aesv2.py decrypt -f encrypted.txt

# Inline
python enigma_machine_aesv2.py decrypt -m "AgIJYXJnb24yaWQfeyJ0..."
```

#### Encrypt File

```bash
python enigma_machine_aesv2.py encrypt-file -i document.pdf -o document.pdf.enc
```

#### Decrypt File

```bash
python enigma_machine_aesv2.py decrypt-file -i document.pdf.enc -o document_decrypted.pdf
```

## Encryption Format

### Header

```
[version: 1 byte]
[kdf_name_len: 1 byte]
[kdf_name: variable]
[kdf_params_len: 2 bytes]
[kdf_params_json: variable]
[salt: 32 bytes]
[config_salt: 16 bytes]
[iv: 12 bytes]
```

### Body

```
[AES-GCM ciphertext + tag]
```

### AAD (Additional Authenticated Data)

The complete header is used as AAD, ensuring any tampering is detected.

## Usage Examples

### Example 1: Simple Message

```bash
$ python enigma_machine_aesv2.py encrypt -m "Hello, World!"
Enter password:
Password strength: STRONG (entropy: 87.3 bits)
✓ Good password!
🔐 Starting encryption...
🔑 Deriving cryptographic key with Argon2id...
⚙️  Configuring Enigma Machine...
🔍 Configuration fingerprint: A3F2B8C1
🎰 Processing with Enigma...
🔒 Applying AES-GCM...

AgIJYXJnb24yaWQfeyJ0aW1lX2Nvc3QiOjMsIm1lbW9yeV9jb3N0Ijo2NTUzNi...

✅ Copied to clipboard!
```

### Example 2: Large File

```bash
$ python enigma_machine_aesv2.py encrypt-file -i large_video.mp4 -o encrypted.bin
Enter password:
Password strength: VERY STRONG (entropy: 142.1 bits)
✓ Excellent password!
📁 Encrypting file: large_video.mp4
🔑 Deriving key...
🔒 Encrypting...
Progress: 100.0%
✅ Encrypted file saved to: encrypted.bin
```

## Security

### Threat Model

This system is **educational** and **experimental**. For production use:

- Use established libraries: **NaCl/libsodium**, **Age**, **GPG/PGP**
- This code has not been audited by security experts
- May contain implementation bugs

### Implemented Protections

- ✅ Confidentiality (AES-GCM)
- ✅ Integrity (AES-GCM tag)
- ✅ Authentication (AAD)
- ✅ Brute force resistance (Argon2id)
- ✅ Unique IVs (os.urandom)
- ✅ Unique salts per message
- ✅ Versioning for future compatibility
- ✅ Tampering detection

### Limitations

- ⚠️ Educational code, not audited
- ⚠️ Historic Enigma is weak; security comes from AES-GCM
- ⚠️ No protection against side-channel attacks
- ⚠️ No protection against keyloggers/malware
- ⚠️ Weak passwords are still vulnerable

## Security Parameters

```python
ARGON2_TIME_COST = 3         # Iterations
ARGON2_MEMORY_COST = 65536   # 64 MB
ARGON2_PARALLELISM = 4       # Threads
ARGON2_HASH_LEN = 32         # 256 bits
SALT_LENGTH = 32             # 256 bits
IV_LENGTH = 12               # 96 bits (GCM recommended)
CONFIG_SALT_LENGTH = 16      # 128 bits
```

To increase security (but slower):
- Increase `ARGON2_TIME_COST` to 4-5
- Increase `ARGON2_MEMORY_COST` to 131072 (128 MB)

## Future Development

Possible improvements (PRs welcome):

- [x] Web GUI with Flask ✅
- [ ] Desktop notifications
- [ ] YubiKey/hardware token support
- [ ] `hybrid-encrypt` command using X25519
- [ ] Complete unit tests
- [ ] Performance benchmarks
- [ ] Security audit

## License

MIT License - Use at your own risk!

## References

- [NIST SP 800-38D (GCM)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [RFC 9106 (Argon2)](https://www.rfc-editor.org/rfc/rfc9106.html)
- [RFC 7748 (X25519)](https://www.rfc-editor.org/rfc/rfc7748)
- [Cryptography Library Docs](https://cryptography.io/)

## Version History

### v2.1 (2025)
- ✅ Web interface with Flask
- ✅ Modern GUI optimized for all platforms
- ✅ Real-time password strength checker
- ✅ Async operations with loading indicators
- ✅ Full clipboard integration
- ✅ Responsive design

### v2.0 (2025)
- ✅ AES-GCM with random IV
- ✅ Argon2id for KDF
- ✅ MD5 removed
- ✅ Versioning and headers
- ✅ Password strength meter
- ✅ Hybrid scheme X25519
- ✅ File encryption
- ✅ Robust CLI
- ✅ Clipboard and fingerprints

### v1.0 (previous)
- ⚠️ AES-CBC (insecure)
- ⚠️ Direct SHA-256 (weak)
- ⚠️ MD5 for IV (broken)
- ⚠️ No versioning

---

**WARNING**: This project is for educational purposes. For critical security applications, use established and audited solutions.
