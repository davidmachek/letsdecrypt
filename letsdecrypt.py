import argparse, time, sys
import random, string
from colorama import *
import messagebox as messagebox
import fernet as fernet
import aes as aes
import chacha20 as chacha20
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES, Blowfish, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from Cryptodome.Cipher import AES, ChaCha20, Blowfish, PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.Util.Padding import unpad
from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.Hash import SHA256
import binascii
import benchmark
print("Let's Decrypt ( https://rasmnout.tech/letsdecrypt ) V0.0.2 - Powerful tool for Decryption")
def main():
    parser = argparse.ArgumentParser(
        description="Let's Decrypt V0.0.2 - Powerful decryption tool supporting multiple encryption standards. This tool allows you to decrypt messages and files using various cryptographic algorithms and manage decrypted outputs efficiently."
    )
    
    parser.add_argument("--version", action="store_true", help="Version of Let's Decrypt")
    encryption_group = parser.add_argument_group("Decryption Methods")
    encryption_group.add_argument("--fernet", action="store_true", help="Use the Fernet encryption standard for decryption. Fernet is a symmetric encryption method that ensures that messages cannot be manipulated or read without the correct key.")
    encryption_group.add_argument("--aes-128", action="store_true", help="Use AES (Advanced Encryption Standard) with a 128-bit key for decryption. AES is a widely used encryption algorithm known for its security and efficiency.")
    encryption_group.add_argument("--aes-192", action="store_true", help="Use AES with a 192-bit key for decryption. Offers higher security than AES-128 at the cost of slightly more processing power.")
    encryption_group.add_argument("--aes-256", action="store_true", help="Use AES with a 256-bit key for decryption. The highest level of AES security, suitable for protecting highly sensitive data.")
    encryption_group.add_argument("--chacha20", action="store_true", help="Use the ChaCha20 encryption method for decryption. ChaCha20 is an alternative to AES that offers high security and performance, especially on lower-power devices.")
    encryption_group.add_argument("--base64", action="store_true", help="Use base64 encoding/decoding method. Base64 is commonly used for encoding binary data into a textual format, making it easier to transmit over text-based protocols.")
    encryption_group.add_argument("--base32", action="store_true", help="Use base32 encoding/decoding method. Base32 is commonly used to encode binary data into a text-based format for easier transmission.")  
    encryption_group.add_argument("--base16", action="store_true", help="Use base16 (hexadecimal) encoding/decoding method. Base16 represents binary data in a readable hexadecimal format.")  
    encryption_group.add_argument("--rsa", action="store_true", help="Use RSA encryption/decryption method. RSA is a widely used asymmetric cryptographic algorithm for secure communication and digital signatures.")  
    encryption_group.add_argument("--blowfish", action="store_true", help="Use Blowfish encryption/decryption method. Blowfish is a symmetric block cipher known for its speed and security in various applications.")  
    # Key input
    key_group = parser.add_argument_group("Key Input")
    key_group.add_argument("--key", help="Specify the decryption key as a direct input. This key is required for decrypting messages and files, and must match the encryption key used previously.")
    key_group.add_argument("--key-file", help="Provide a file containing the decryption key. This is useful for securely storing keys and avoiding direct input in command-line arguments.")
    key_group.add_argument("--iv", help="Specify the initialization vector (IV) as a direct input. This IV is required for decrypting messages and files, and must match the IV used during encryption.")
    key_group.add_argument("--iv-file", help="Specify a file containing the initialization vector (IV). The IV must match the one used during encryption for successful decryption of messages and files.")  
    key_group.add_argument("--nonce", help="A unique number used once for cryptographic operations. It helps prevent replay attacks and ensures message freshness.")  
    key_group.add_argument("--nonce-file", help="Specify a file containing the nonce. The nonce is a unique value used once to ensure cryptographic security and prevent replay attacks.")  
    key_group.add_argument("--private-key", help="The private key used for encryption, decryption, or digital signing. Keep it secure and never share it.")  
    key_group.add_argument("--signature", help="A digital signature used to verify the integrity and authenticity of a message or data.")  
    # Decryption options
    decrypt_group = parser.add_argument_group("Decryption Options")
    decrypt_group.add_argument("--go-decrypt", help="Provide a message directly as input to decrypt. This option is useful for quick decryption of short texts without needing a file.")
    decrypt_group.add_argument("--go-decrypt-file", help="Specify a file containing an encrypted message that needs to be decrypted. This allows decryption of larger texts or structured data.")
    decrypt_group.add_argument("--detect", action="store_true", help="Detect the encryption method used in the input. This will automatically identify the encryption type, such as AES or ChaCha20, for decryption.")
    decrypt_group.add_argument("--benchmark",type=int, help="(Use MegaBytes MB). Measures decryption time and displays statistics (e.g. useful for comparing AES vs ChaCha20).")
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
    write = False
    save_decrypt_file = ""
    if args.version:
        print("Rasmnout Let's Decrypt (Version 0.0.2)")
        sys.exit(1)
    elif args.benchmark:
        benchmark_str = str(args.benchmark)
        mb = int(benchmark_str) if len(benchmark_str) > 1 else 1
        benchmark.run_benchmark(mb)
        sys.exit(1)
    elif args.detect:
        if args.silence:
            not_silence = False
        if args.save_output_random:
            choices = string.digits + string.ascii_uppercase
            random_file = ''.join(random.choices(choices, k=6))
            write_output = f"{random_file}.txt"
            messagebox.info(f"All Output from Let's Decrypt will be wrote to: '{write_output}'",write=write_output,print2=not_silence)
        if args.save_output:
            write_output = args.save_output
            messagebox.info(f"All Output from Let's Decrypt will be wrote to: '{write_output}'",write=write_output,print2=not_silence)
        if args.verbose:
            verbose = True
            messagebox.info("Verbose was set to True",write=write_output,print2=not_silence)
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
        messagebox.info("Started trying all the ciphers",write=write_output,print2=not_silence)
        msg = message_decrypt
        key = key
        iv = args.iv
        nonce = args.nonce
        private_key_path = args.private_key
        signature = args.signature
        if verbose:
            messagebox.info("Decoding bytes",write=write_output,print2=not_silence)
        if verbose:
            messagebox.create_space_info("Tried and tested ciphers")
        try:
            msg_bytes = binascii.unhexlify(msg)
        except binascii.Error:
            msg_bytes = msg.encode()

        if key:
            try:
                key_bytes = binascii.unhexlify(key)
            except binascii.Error:
                key_bytes = key.encode()
        else:
            key_bytes = None

        if iv:
            try:
                iv_bytes = binascii.unhexlify(iv)
            except binascii.Error:
                iv_bytes = iv.encode()
        else:
            iv_bytes = None

        if nonce:
            try:
                nonce_bytes = binascii.unhexlify(nonce)
            except binascii.Error:
                nonce_bytes = nonce.encode()
        else:
            nonce_bytes = None

        if signature:
            try:
                signature_bytes = binascii.unhexlify(signature)
            except binascii.Error:
                signature_bytes = signature.encode()
        else:
            signature_bytes = None
        private_key_rsa = None
        private_key_ecc = None
        if private_key_path:
            try:
                with open(private_key_path, 'rb') as key_file:
                    key_data = key_file.read()
                    try:
                        private_key_rsa = RSA.import_key(key_data)
                        if verbose:
                            messagebox.space("-- RSA key loaded successfully",write=write_output,print2=not_silence)
                    except ValueError:
                        try:
                            private_key_ecc = ECC.import_key(key_data)
                            if verbose:
                                messagebox.space(f"-- ECC key loaded successfully (curve: {private_key_ecc.curve})",write=write_output,print2=not_silence)
                        except ValueError:
                            messagebox.error("Could not load key as RSA",write=write_output,print2=not_silence)
            except Exception as e:
                messagebox.error(f"Error loading key file: {e}",write=write_output,print2=not_silence)
        try:
            if base64.b64encode(base64.b64decode(msg_bytes)).rstrip(b'=') == msg_bytes.rstrip(b'='):
                messagebox.space("Base64: Successfully",write=write_output)
            else:
                if verbose:
                    messagebox.space("Base64: Failed",write=write_output,print2=not_silence)
        except Exception as e:
            if verbose:
                messagebox.space(f"Base64: Failed: {e}",write=write_output,print2=not_silence)
        try:
            if base64.b32encode(base64.b32decode(msg_bytes)).rstrip(b'=') == msg_bytes.rstrip(b'='):
                messagebox.space("Base32: Successfully",write=write_output)
            else:
                if verbose:
                    messagebox.space("Base32: Failed",write=write_output,print2=not_silence)
        except Exception as e:
            if verbose:
                messagebox.space(f"Base32: Failed: {e}",write=write_output,print2=not_silence)

        try:
            if base64.b16encode(base64.b16decode(msg_bytes)).rstrip(b'=') == msg_bytes.rstrip(b'='):
                messagebox.space("Base16: Successfully",write=write_output)
            else:
                if verbose:
                    messagebox.space("Base16: Failed",write=write_output,print2=not_silence)
        except Exception as e:
            if verbose:
                messagebox.space(f"Base16: Failed: {e}",write=write_output,print2=not_silence)
        if key_bytes:
            try:
                cipher = Fernet(key_bytes)
                decrypted_message = cipher.decrypt(msg_bytes)
                messagebox.space(f"Fernet: Successfully",write=write_output)
            except Exception as e:
                if verbose:
                    messagebox.space(f"Fernet: Failed {e}",write=write_output,print2=not_silence)
        if key_bytes and iv_bytes:
            if len(key_bytes) >= 16:
                try:
                    cipher = AES.new(key_bytes[:16], AES.MODE_CBC, iv_bytes)
                    decrypted_data = unpad(cipher.decrypt(msg_bytes), AES.block_size)
                    messagebox.space("AES-128: Successfully",write=write_output)
                except Exception as e:
                    if verbose:
                        messagebox.space(f"AES-128: Failed: {e}",write=write_output,print2=not_silence)
            if len(key_bytes) >= 24:
                try:
                    cipher = AES.new(key_bytes[:24], AES.MODE_CBC, iv_bytes)
                    decrypted_data = unpad(cipher.decrypt(msg_bytes), AES.block_size)
                    messagebox.space("AES-192: Successfully",write=write_output)
                except Exception as e:
                    if verbose:
                        messagebox.space(f"AES-192: Failed: {e}",write=write_output,print2=not_silence)
            if len(key_bytes) >= 32:
                try:
                    cipher = AES.new(key_bytes[:32], AES.MODE_CBC, iv_bytes)
                    decrypted_data = unpad(cipher.decrypt(msg_bytes), AES.block_size)
                    messagebox.space("AES-256: Successfully",write=write_output)
                except Exception as e:
                    if verbose:
                        messagebox.space(f"AES-256: Failed: {e}",write=write_output,print2=not_silence)
        if key_bytes and nonce_bytes:
            if len(key_bytes) >= 32 and len(nonce_bytes) >= 8:
                try:
                    cipher = ChaCha20.new(key=key_bytes[:32], nonce=nonce_bytes[:8])
                    decrypted_data = cipher.decrypt(msg_bytes)
                    messagebox.space("ChaCha20: Successfully",write=write_output)
                except Exception as e:
                    if verbose:
                        messagebox.space(f"ChaCha20: Failed: {e}",write=write_output,print2=not_silence)
        if key_bytes and iv_bytes:
            try:
                cipher = Blowfish.new(key_bytes, Blowfish.MODE_CBC, iv_bytes[:8])
                decrypted_data = unpad(cipher.decrypt(msg_bytes), 8)
                messagebox.space("Blowfish: Successfully",write=write_output)
            except Exception as e:
                if verbose:
                    messagebox.space(f"Blowfish: Failed: {e}",write=write_output,print2=not_silence)
        if private_key_rsa:
            try:
                cipher = PKCS1_OAEP.new(private_key_rsa)
                decrypted_data = cipher.decrypt(msg_bytes)
                messagebox.space("RSA: Successfully",write=write_output)
            except Exception as e:
                if verbose:
                    messagebox.space(f"RSA: Failed: {e}",write=write_output,print2=not_silence)
            if signature_bytes:
                try:
                    h = SHA256.new(msg_bytes)
                    verifier = pkcs1_15.new(private_key_rsa.publickey())
                    verifier.verify(h, signature_bytes)
                    messagebox.space("RSA Signature Verification: Successfully",write=write_output,print2=not_silence)
                except Exception as e:
                    if verbose:
                        messagebox.space(f"RSA Signature Verification: Failed: {e}",write=write_output,print2=not_silence)
        messagebox.end_space("Tried every cipher it supports.")
    elif args.fernet:
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
        iv = args.iv
        aes.encrypt(iv,verbose, message_decrypt, write_output, not_silence, save_decrypt, save_decrypt_file, key)
    elif args.chacha20:
        if args.key:
            key = args.key.encode('utf-8')
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
        if args.nonce:
            nonce = args.nonce.encode('utf-8')
            if len(nonce) != 12:
                messagebox.error("ChaCha20 requires a 12-byte nonce", write=write_output, print2=not_silence)
                sys.exit(0)
            if verbose:
                messagebox.info(f"Nonce was set for ChaCha20", write=write_output, print2=not_silence)
        elif args.nonce_file:
            if verbose:
                messagebox.info("Nonce File for ChaCha20", write=write_output, print2=not_silence)
                messagebox.create_space_info("Working with File:", write=write_output, print2=not_silence)
            with open(args.nonce_file, "r") as f:
                nonce = f.read().strip().encode('utf-8')
                if len(nonce) != 12:
                    messagebox.error("ChaCha20 requires a 12-byte nonce", write=write_output, print2=not_silence)
                    sys.exit(0)
                if verbose:
                    messagebox.end_space(f"Nonce was set for ChaCha20", write=write_output, print2=not_silence)
        else:
            messagebox.error("No nonce or nonce file provided for ChaCha20", write=write_output, print2=not_silence)
            sys.exit(0)
        if args.go_decrypt:
            message_decrypt = args.go_decrypt
        elif args.go_decrypt_file:
            with open(args.go_decrypt_file, "r") as f:
                message_decrypt = f.read()
        else:
            messagebox.error("No Go-Decrypt or Go-Decrypt File provided", write=write_output, print2=not_silence)
            sys.exit(0)
        if args.save_decrypt:
            save_decrypt = True
            save_decrypt_file = args.save_decrypt
        if args.save_decrypt_random:
            save_decrypt = True
            choices = string.digits + string.ascii_uppercase
            random_file = ''.join(random.choices(choices, k=6))
            save_decrypt_file = f"{random_file}.txt"

        messagebox.info("Starting ChaCha20 Decryption", write=write_output, print2=not_silence)
        
    else:
        parser.print_help()
    
if __name__ == "__main__":
    main()
