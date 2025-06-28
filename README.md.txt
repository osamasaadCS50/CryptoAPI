# CryptoAPI

## Overview
CryptoAPI is a secure Python-based cryptography API designed to perform encryption and decryption using symmetric (AES) and asymmetric (RSA) algorithms, along with SHA-256 hashing. It features an intuitive graphical user interface (GUI) built with tkinter, optimized for ease of use and extensibility, making it suitable for Security Operations Center (SOC) applications such as secure data handling and key management.

## Features
- Supports multiple cryptosystems: AES for symmetric encryption, RSA for asymmetric encryption, and SHA-256 for hashing.
- User-friendly GUI built with tkinter, allowing seamless selection of cryptosystems, key input, and plaintext/ciphertext processing.
- Robust security measures, including input validation to prevent vulnerabilities like buffer overflow.
- Extensible design for adding new cryptographic algorithms in the future.
- Comprehensive documentation and a demo video showcasing functionality.

## Technologies
- **Python**: Core programming language.
- **tkinter**: For building the graphical user interface.
- **pycryptodome**: For implementing AES, RSA, and SHA-256 algorithms.
- **re**: For input validation and secure data handling.

## Installation
1. Ensure Python 3.8+ is installed on your system.
2. Install the required dependencies:
   ```bash
   pip install pycryptodome