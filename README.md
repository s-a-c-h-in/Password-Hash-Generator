# Password Hash Generator

A Python tool that generates password hashes using multiple cryptographic algorithms. This interactive command-line application allows users to select from 10 different hashing methods and instantly generate secure hashes for their passwords.

## Features

- **10 Hash Algorithms**: Choose from MD5, SHA1, SHA256, SHA512, BLAKE2b, BLAKE2s, bcrypt, PBKDF2, SHA3-256, and SHA3-512
- **Interactive Menu**: Simple numbered selection system
- **Security Warnings**: Alerts users about cryptographically weak algorithms
- **Error Handling**: Robust input validation and error management
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Supported Hash Algorithms

| Algorithm | Description | Security Level |
|-----------|-------------|----------------|
| MD5 | Fast but cryptographically weak | ⚠ Not recommended |
| SHA1 | Fast but cryptographically weak | ⚠ Not recommended |
| SHA256 | Strong cryptographic hash | Good |
| SHA512 | Strong cryptographic hash | Good |
| BLAKE2b | Modern, fast, and secure | Excellent |
| BLAKE2s | Modern, fast, and secure (smaller output) | Excellent |
| bcrypt | Specifically designed for password hashing | Recommended |
| PBKDF2 | Key derivation function with salt | Recommended |
| SHA3-256 | Latest SHA-3 standard | Excellent |
| SHA3-512 | Latest SHA-3 standard (larger output) | Excellent |

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/password-hash-generator.git
cd password-hash-generator
```

2. Install required dependencies:
```bash
pip install bcrypt cryptography
```

## Usage

Run the program:
```bash
python password_hasher.py
```

Follow the interactive prompts:
1. Select a hash algorithm by entering its number (1-10)
2. Enter your password when prompted
3. View the generated hash

### Example Output

```
==================================================
         PASSWORD HASH GENERATOR
==================================================

Available Hash Algorithms:
------------------------------
1. MD5
2. SHA1
3. SHA256
4. SHA512
5. BLAKE2b
6. BLAKE2s
7. bcrypt (recommended for passwords)
8. PBKDF2 (recommended for passwords)
9. SHA3-256
10. SHA3-512
------------------------------

Select hash algorithm (enter number): 7

Selected: bcrypt (recommended for passwords)
Enter password to hash: mypassword123

Generating hash...

==================================================
Algorithm: bcrypt (recommended for passwords)
Hash: $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj1VjPMpH2xy
==================================================
```

## Security Recommendations

- **For Password Storage**: Use **bcrypt** (option 7) or **PBKDF2** (option 8)
- **For General Hashing**: Use SHA256, SHA512, BLAKE2b, or SHA3 algorithms
- **Avoid**: MD5 and SHA1 for security-sensitive applications

## Requirements

- Python 3.6+
- bcrypt library
- cryptography library

## Dependencies

Install the required packages using pip:

```bash
pip install -r requirements.txt
```

Create a `requirements.txt` file with:
```
bcrypt>=4.0.0
cryptography>=3.0.0
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and legitimate security purposes only. Users are responsible for complying with applicable laws and regulations when using this software.

## Author

Your Name - [@sachine]

## Acknowledgments

- Built with Python's hashlib library
- Uses bcrypt for secure password hashing
- Implements PBKDF2 using the cryptography library
