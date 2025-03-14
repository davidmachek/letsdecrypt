# Let's Decrypt

Let's Decrypt is a powerful decryption tool supporting multiple encryption standards. It allows users to decrypt messages and files using various cryptographic algorithms and efficiently manage decrypted outputs.

## Supported Encryption Methods

Let's Decrypt supports the following encryption methods:

- **Fernet** (Symmetric encryption ensuring message integrity)
- **AES-128** (Advanced Encryption Standard with a 128-bit key)
- **AES-192** (Advanced Encryption Standard with a 192-bit key)
- **AES-256** (Advanced Encryption Standard with a 256-bit key)
- **ChaCha20** (A high-performance stream cipher alternative to AES)

## Installation

You can install Let's Decrypt using one of the following methods:

### Install via pip

For Python users, install Let's Decrypt using `pip`:

```sh
pip install letsdecrypt --break-system-packages
```

### Install via Snap

For Linux users, install Let's Decrypt using Snap:

```sh
snap install letsdecrypt
```

## Usage

Let's Decrypt can be used for encryption and decryption of text messages and files.

### Basic Command Syntax

```sh
letsdecrypt.py [-h] [--fernet] [--aes-128] [--aes-192] [--aes-256] [--chacha20] [--key KEY]
               [--key-file KEY_FILE] [--go-decrypt GO_DECRYPT] [--go-decrypt-file GO_DECRYPT_FILE]
               [--save-decrypt SAVE_DECRYPT] [--save-output SAVE_OUTPUT]
               [--save-decrypt-random SAVE_DECRYPT_RANDOM] [--save-output-random SAVE_OUTPUT_RANDOM]
               [--verbose] [--silence]
```

### Decryption Methods

- `--fernet` → Use the **Fernet** encryption standard for decryption.
- `--aes-128` → Decrypt using **AES-128** encryption.
- `--aes-192` → Decrypt using **AES-192** encryption.
- `--aes-256` → Decrypt using **AES-256** encryption.
- `--chacha20` → Decrypt using **ChaCha20** encryption.

### Key Input Options

- `--key KEY` → Provide the decryption key as direct input.
- `--key-file KEY_FILE` → Provide a file containing the decryption key.

### Decryption Options

- `--go-decrypt GO_DECRYPT` → Decrypt a message directly from input.
- `--go-decrypt-file GO_DECRYPT_FILE` → Specify a file containing an encrypted message for decryption.

### Output Options

- `--save-decrypt SAVE_DECRYPT` → Save the decrypted message to a specified file.
- `--save-output SAVE_OUTPUT` → Save the entire program output to a file.
- `--save-decrypt-random SAVE_DECRYPT_RANDOM` → Save the decrypted message to a randomly named file.
- `--save-output-random SAVE_OUTPUT_RANDOM` → Save the complete program output to a randomly named file.

### Additional Settings

- `--verbose` → Enable verbose mode for detailed output.
- `--silence` → Display only the decrypted message without logs.

### Example Usage
## Security Considerations

- Always store your encryption keys securely.
- Do not use weak passwords for encryption.
- Use **Fernet** for an easy and secure encryption method.

## License

This project is licensed under the MIT License. You are free to use, modify, and distribute it as needed.

## Contributing

If you have suggestions or improvements, feel free to open an issue or submit a pull request on GitHub.

## Contact

- **Email:** rasmnout@gmail.com
- **GitHub:** [github.com/rasmnout](https://github.com/rasmnout)
- **Website:** [rasmnout.tech/letsdecrypt](https://rasmnout.tech/letsdecrypt)

---
Thank you for using Let's Decrypt!

