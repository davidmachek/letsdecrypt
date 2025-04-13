from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES, Blowfish, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import messagebox as messagebox
import base64

def encrypt(verbose, write_output, not_silence, message_decrypt, key, save_decrypt, save_decrypt_file):
    try:
            if verbose:
                messagebox.create_space_info("Decrypting with ChaCha20", write=write_output, print2=not_silence)
            key = bytes.fromhex(str(key))
            nonce = bytes.fromhex(str(nonce))
            ciphertext = bytes.fromhex(str(message_decrypt))
            cipher = ChaCha20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            if verbose:
                messagebox.end_space("ChaCha20 decryption successful!", write=write_output, print2=not_silence)

            messagebox.info(f"Decrypted Message: '{plaintext.decode()}'", write=write_output, print2=True)

            if save_decrypt:
                messagebox.info(f"Writing Decrypted Message to: '{save_decrypt_file}'", write=write_output, print2=not_silence)
                with open(save_decrypt_file, "a") as fi:
                    fi.write(plaintext.decode())
                    if verbose:
                        messagebox.info("Written to file", write=write_output, print2=not_silence)
    except Exception as e:
            messagebox.error(f"ChaCha20 decryption failed: {e}", write=write_output, print2=not_silence)
