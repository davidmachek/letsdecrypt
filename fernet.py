import messagebox as messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES, Blowfish, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
def decrypt(message_decrypt,verbose,key,save_decrypt,save_decrypt_file,write_output,not_silence):
    try:
            if verbose:
                messagebox.create_space_info("Decrypting",write=write_output,print2=not_silence)
                messagebox.space("Creating a Fernet object for decryption",write=write_output,print2=not_silence)
            f = Fernet(key)
            if verbose:
                messagebox.space(f"Decrypting message: '{message_decrypt}' with key: '{key}'",write=write_output,print2=not_silence)
            else:
                messagebox.info(f"Decrypting message: '{message_decrypt}' with key: '{key}'",write=write_output,print2=not_silence)
            msg = f.decrypt(message_decrypt)
            if verbose:
                messagebox.end_space(f"The message was successfully decrypted!",write=write_output,print2=not_silence)
            else:
                messagebox.info(f"The message was successfully decrypted!",write=write_output,print2=not_silence)
            messagebox.info(f"Decrypted Message: '{msg.decode()}'",write=write_output,print2=True)
            if save_decrypt:
                messagebox.info(f"Writing Decrypted Message to: '{save_decrypt_file}'",write=write_output,print2=not_silence)
                with open(save_decrypt_file, "a") as fi:
                    fi.write(msg.decode())
                    if verbose:
                        messagebox.info("Writed to file",write=write_output,print2=not_silence)
    except Exception as e:
            messagebox.error(e)