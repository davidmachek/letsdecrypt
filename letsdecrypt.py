import argparse, time, sys
import random, string
import base64
from colorama import *
import messagebox as messagebox
import fernet as fernet
import aes as aes
import aes_192 as aes_192
import aes_256 as aes_256
import chacha20 as chacha20
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES, Blowfish, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
print("Let's Decrypt ( https://rasmnout.tech/letsdecrypt ) V0.0.1 - Powerful tool for Decryption")
def main():
    parser = argparse.ArgumentParser(
        description="Let's Decrypt V0.0.1 - Powerful decryption tool supporting multiple encryption standards. This tool allows you to decrypt messages and files using various cryptographic algorithms and manage decrypted outputs efficiently."
    )
    
    # Encryption method selection
    encryption_group = parser.add_argument_group("Decryption Methods")
    encryption_group.add_argument("--fernet", action="store_true", help="Use the Fernet encryption standard for decryption. Fernet is a symmetric encryption method that ensures that messages cannot be manipulated or read without the correct key.")
    encryption_group.add_argument("--aes-128", action="store_true", help="Use AES (Advanced Encryption Standard) with a 128-bit key for decryption. AES is a widely used encryption algorithm known for its security and efficiency.")
    encryption_group.add_argument("--aes-192", action="store_true", help="Use AES with a 192-bit key for decryption. Offers higher security than AES-128 at the cost of slightly more processing power.")
    encryption_group.add_argument("--aes-256", action="store_true", help="Use AES with a 256-bit key for decryption. The highest level of AES security, suitable for protecting highly sensitive data.")
    encryption_group.add_argument("--chacha20", action="store_true", help="Use the ChaCha20 encryption method for decryption. ChaCha20 is an alternative to AES that offers high security and performance, especially on lower-power devices.")
    
    # Key input
    key_group = parser.add_argument_group("Key Input")
    key_group.add_argument("--key", help="Specify the decryption key as a direct input. This key is required for decrypting messages and files, and must match the encryption key used previously.")
    key_group.add_argument("--key-file", help="Provide a file containing the decryption key. This is useful for securely storing keys and avoiding direct input in command-line arguments.")
    
    # Decryption options
    decrypt_group = parser.add_argument_group("Decryption Options")
    decrypt_group.add_argument("--go-decrypt", help="Provide a message directly as input to decrypt. This option is useful for quick decryption of short texts without needing a file.")
    decrypt_group.add_argument("--go-decrypt-file", help="Specify a file containing an encrypted message that needs to be decrypted. This allows decryption of larger texts or structured data.")
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--save-decrypt", help="Save the decrypted message to a specified file. This option is useful for keeping a permanent record of decrypted data.")
    output_group.add_argument("--save-output", help="Save the entire program output, including logs and decrypted messages, to a specified file for later review.")
    output_group.add_argument("--save-decrypt-random", help="Save the decrypted message to a file with a randomly generated name. Useful for preventing overwrites or organizing multiple decryptions.")
    output_group.add_argument("--save-output-random", help="Save the complete output of Let's Decrypt to a randomly named file. Ensures that previous outputs are not overwritten and maintains log integrity.")
    
    # Additional settings
    settings_group = parser.add_argument_group("Additional Settings")
    settings_group.add_argument("--verbose", action="store_true", help="Enable verbose mode. This mode provides detailed output, including processing steps, encryption details, and potential errors.")
    settings_group.add_argument("--silence", action="store_true", help="Only display the decrypted message without any additional logs or metadata. Ideal for clean and minimal output.")
    args = parser.parse_args()

    verbose = False
    save_decrypt = False
    write_output = False
    not_silence = True
    if args.fernet:
        if args.silence:
            not_silence = False
        if args.save_output_random:
            choices = string.digits + string.ascii_uppercase
            random_file = ''.join(random.choices(choices, k=6))
            write_output = f"{random_file}.txt"
        if args.save_output:
            write_output = args.save_output
        if args.verbose:
            verbose = True
            messagebox.info("Verbose was set to True",write=write_output,print2=not_silence)
        if args.save_output_random:
            messagebox.info(f"All Output from Let's Decrypt will be wrote to: '{write_output}'",write=write_output,print2=not_silence)
        if args.save_output:
            messagebox.info(f"All Output from Let's Decrypt will be wrote to: '{write_output}'",write=write_output,print2=not_silence)
        if args.key:
            key = args.key
            if verbose:
                messagebox.info(f"Key was set to '{key}'",write=write_output,print2=not_silence)
        elif args.key_file:
            if verbose:
                messagebox.info("Key File",write=write_output,print2=not_silence)
                messagebox.create_space_info("Working with File:",write=write_output,print2=not_silence)
                messagebox.space("Trying to open a file to read a key",write=write_output,print2=not_silence)
            with open(args.key_file, "r") as f:
                if verbose:
                    messagebox.end_space("Reading key from file",write=write_output,print2=not_silence)
                key = f.read().strip()
                if verbose:
                    messagebox.create_space_info("Key was read from a file",write=write_output,print2=not_silence)
                    messagebox.space("Stripping the Key from File",write=write_output,print2=not_silence)
                    messagebox.end_space(f"Key was set to '{key}'",write=write_output,print2=not_silence)
        else:
            messagebox.error("No key or key file provided",write=write_output,print2=not_silence)
            messagebox.error("Use --key '<Key>' or --key-file <File>",write=write_output,print2=not_silence)
            sys.exit(0)
        if args.go_decrypt:
            message_decrypt = args.go_decrypt
            if verbose:
                messagebox.info(f"Go-Decrypt (Message to be decrypted) was set to '{message_decrypt}'",write=write_output,print2=not_silence)
        elif args.go_decrypt_file:
            if verbose:
                messagebox.info("Go Decrypt File",write=write_output,print2=not_silence)
                messagebox.create_space_info("Working with File:",write=write_output,print2=not_silence)
                messagebox.space("Trying to open a file to read a key",write=write_output,print2=not_silence)
            with open(args.go_decrypt_file, "r") as f:
                if verbose:
                    messagebox.end_space("Reading Go-Decrypt Message from file",write=write_output,print2=not_silence)
                message_decrypt = f.read()
                if verbose:
                    messagebox.create_space_info("Go-Decrypt Message was read from a file",write=write_output,print2=not_silence)
                    messagebox.end_space(f"Go-Decrypt Message was set to '{key}'",write=write_output,print2=not_silence)
        else:
            messagebox.error("No Go-Decrypt or Go-Decrypt File provided",write=write_output,print2=not_silence)
            messagebox.error("Use --go-decrypt '<Encrypted Message>' or --go-decrypt-file <File>",write=write_output,print2=not_silence)
            sys.exit(0)
        if args.save_decrypt:
            save_decrypt = True
            save_decrypt_file = args.save_decrypt
            if verbose:
                messagebox.create_space_info(f"Save Decrypt was set to '{save_decrypt}'",write=write_output,print2=not_silence)
                messagebox.end_space(f"Final Decryption will be save to: '{save_decrypt_file}'",write=write_output,print2=not_silence)
        if args.save_decrypt_random:
            save_decrypt = True
            choices = string.digits + string.ascii_uppercase
            random_file = ''.join(random.choices(choices, k=6))
            save_decrypt_file = f"{random_file}.txt"
            if verbose:
                messagebox.create_space_info(f"Save Decrypt was set to '{save_decrypt}'",write=write_output,print2=not_silence)
                messagebox.end_space(f"Final Decryption will be save to: '{save_decrypt_file}'",write=write_output,print2=not_silence)
        messagebox.info("Starting Decrypting",write=write_output,print2=not_silence)
        fernet.decrypt(message_decrypt,verbose,key,save_decrypt,save_decrypt_file,write_output,not_silence)
    elif args.aes_128 or args.aes_192 or args.aes_256:
        if args.silence:
            not_silence = False

        if args.save_output_random:
            choices = string.digits + string.ascii_uppercase
            random_file = ''.join(random.choices(choices, k=6))
            write_output = f"{random_file}.txt"
        if args.save_output:
            write_output = args.save_output
        if args.verbose:
            verbose = True
            messagebox.info("Verbose was set to True", write=write_output, print2=not_silence)
        if args.save_output_random:
            messagebox.info(f"All Output from Let's Decrypt will be wrote to: '{write_output}'", write=write_output, print2=not_silence)
        if args.save_output:
            messagebox.info(f"All Output from Let's Decrypt will be wrote to: '{write_output}'", write=write_output, print2=not_silence)

        if args.key:
            key = args.key.encode('utf-8')  # AES key should be bytes
            if args.aes_128 and len(key) != 16:
                messagebox.error("AES-128 requires a 16-byte key", write=write_output, print2=not_silence)
                sys.exit(0)
            elif args.aes_192 and len(key) != 24:
                messagebox.error("AES-192 requires a 24-byte key", write=write_output, print2=not_silence)
                sys.exit(0)
            elif args.aes_256 and len(key) != 32:
                messagebox.error("AES-256 requires a 32-byte key", write=write_output, print2=not_silence)
                sys.exit(0)

            if verbose:
                messagebox.info(f"Key was set to '{key.decode()}'", write=write_output, print2=not_silence)

        elif args.key_file:
            if verbose:
                messagebox.info("Key File", write=write_output, print2=not_silence)
                messagebox.create_space_info("Working with File:", write=write_output, print2=not_silence)
                messagebox.space("Trying to open a file to read a key", write=write_output, print2=not_silence)
            with open(args.key_file, "r") as f:
                if verbose:
                    messagebox.end_space("Reading key from file", write=write_output, print2=not_silence)
                key = f.read().strip().encode('utf-8')
                if args.aes_128 and len(key) != 16:
                    messagebox.error("AES-128 requires a 16-byte key", write=write_output, print2=not_silence)
                    sys.exit(0)
                elif args.aes_192 and len(key) != 24:
                    messagebox.error("AES-192 requires a 24-byte key", write=write_output, print2=not_silence)
                    sys.exit(0)
                elif args.aes_256 and len(key) != 32:
                    messagebox.error("AES-256 requires a 32-byte key", write=write_output, print2=not_silence)
                    sys.exit(0)
                if verbose:
                    messagebox.create_space_info("Key was read from a file", write=write_output, print2=not_silence)
                    messagebox.space("Stripping the Key from File", write=write_output, print2=not_silence)
                    messagebox.end_space(f"Key was set to '{key.decode()}'", write=write_output, print2=not_silence)

        else:
            messagebox.error("No key or key file provided", write=write_output, print2=not_silence)
            messagebox.error("Use --key '<Key>' or --key-file <File>", write=write_output, print2=not_silence)
            sys.exit(0)

        if args.go_decrypt:
            message_decrypt = args.go_decrypt
            if verbose:
                messagebox.info(f"Go-Decrypt (Message to be decrypted) was set to '{message_decrypt}'", write=write_output, print2=not_silence)
        elif args.go_decrypt_file:
            if verbose:
                messagebox.info("Go Decrypt File", write=write_output, print2=not_silence)
                messagebox.create_space_info("Working with File:", write=write_output, print2=not_silence)
                messagebox.space("Trying to open a file to read a key", write=write_output, print2=not_silence)
            with open(args.go_decrypt_file, "r") as f:
                if verbose:
                    messagebox.end_space("Reading Go-Decrypt Message from file", write=write_output, print2=not_silence)
                message_decrypt = f.read()
                if verbose:
                    messagebox.create_space_info("Go-Decrypt Message was read from a file", write=write_output, print2=not_silence)
                    messagebox.end_space(f"Go-Decrypt Message was set to '{key}'", write=write_output, print2=not_silence)
        else:
            messagebox.error("No Go-Decrypt or Go-Decrypt File provided", write=write_output, print2=not_silence)
            messagebox.error("Use --go-decrypt '<Encrypted Message>' or --go-decrypt-file <File>", write=write_output, print2=not_silence)
            sys.exit(0)

        if args.save_decrypt:
            save_decrypt = True
            save_decrypt_file = args.save_decrypt
            if verbose:
                messagebox.create_space_info(f"Save Decrypt was set to '{save_decrypt}'", write=write_output, print2=not_silence)
                messagebox.end_space(f"Final Decryption will be saved to: '{save_decrypt_file}'", write=write_output, print2=not_silence)

        if args.save_decrypt_random:
            save_decrypt = True
            choices = string.digits + string.ascii_uppercase
            random_file = ''.join(random.choices(choices, k=6))
            save_decrypt_file = f"{random_file}.txt"
            if verbose:
                messagebox.create_space_info(f"Save Decrypt was set to '{save_decrypt}'", write=write_output, print2=not_silence)
                messagebox.end_space(f"Final Decryption will be saved to: '{save_decrypt_file}'", write=write_output, print2=not_silence)

        messagebox.info("Starting Decrypting", write=write_output, print2=not_silence)
        aes.encrypt(verbose, message_decrypt, write_output, not_silence, save_decrypt, save_decrypt_file, key)
    elif args.chacha20:
        if args.key:
            key = args.key.encode('utf-8')
            # ChaCha20 requires 32-byte key
            if len(key) != 32:
                messagebox.error("ChaCha20 requires a 32-byte key", write=write_output, print2=not_silence)
                sys.exit(0)
            if verbose:
                messagebox.info(f"Key was set for ChaCha20", write=write_output, print2=not_silence)
        elif args.key_file:
            if verbose:
                messagebox.info("Key File for ChaCha20", write=write_output, print2=not_silence)
                messagebox.create_space_info("Working with File:", write=write_output, print2=not_silence)
            with open(args.key_file, "r") as f:
                key = f.read().strip().encode('utf-8')
                if len(key) != 32:
                    messagebox.error("ChaCha20 requires a 32-byte key", write=write_output, print2=not_silence)
                    sys.exit(0)
                if verbose:
                    messagebox.end_space(f"Key was set for ChaCha20", write=write_output, print2=not_silence)
        else:
            messagebox.error("No key or key file provided for ChaCha20", write=write_output, print2=not_silence)
            sys.exit(0)

        # Process message to decrypt
        if args.go_decrypt:
            message_decrypt = args.go_decrypt
        elif args.go_decrypt_file:
            with open(args.go_decrypt_file, "r") as f:
                message_decrypt = f.read()
        else:
            messagebox.error("No Go-Decrypt or Go-Decrypt File provided", write=write_output, print2=not_silence)
            sys.exit(0)

        # Handle save options
        if args.save_decrypt:
            save_decrypt = True
            save_decrypt_file = args.save_decrypt
        if args.save_decrypt_random:
            save_decrypt = True
            choices = string.digits + string.ascii_uppercase
            random_file = ''.join(random.choices(choices, k=6))
            save_decrypt_file = f"{random_file}.txt"

        messagebox.info("Starting ChaCha20 Decryption", write=write_output, print2=not_silence)
        try:
            if verbose:
                messagebox.create_space_info("Decrypting with ChaCha20", write=write_output, print2=not_silence)

            # Decode base64 and prepare for decryption
            encrypted_data = base64.b64decode(message_decrypt)
            nonce = encrypted_data[:8]  # ChaCha20 in PyCryptodome uses 8-byte nonce
            ciphertext = encrypted_data[8:]

            # Create ChaCha20 cipher object
            cipher = ChaCha20.new(key=key, nonce=nonce)

            # Decrypt (ChaCha20 doesn't need padding)
            plaintext = cipher.decrypt(ciphertext).decode('utf-8')

            if verbose:
                messagebox.end_space("ChaCha20 decryption successful!", write=write_output, print2=not_silence)

            messagebox.info(f"Decrypted Message: '{plaintext}'", write=write_output, print2=True)

            if save_decrypt:
                messagebox.info(f"Writing Decrypted Message to: '{save_decrypt_file}'", write=write_output, print2=not_silence)
                with open(save_decrypt_file, "a") as fi:
                    fi.write(plaintext)
                    if verbose:
                        messagebox.info("Written to file", write=write_output, print2=not_silence)
        except Exception as e:
            messagebox.error(f"ChaCha20 decryption failed: {e}", write=write_output, print2=not_silence)
    else:
        parser.print_help()
    
if __name__ == "__main__":
    main()
