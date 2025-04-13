import time
import base64
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def timeit(func):
    start = time.time()
    func()
    end = time.time()
    return round(end - start, 6)

def generate_data(mb):
    return os.urandom(mb * 1024 * 1024)

def run_benchmark(mb=1):
    print("[+] Running heavy decryption benchmark...\n")
    data = generate_data(mb)

    results = {}

    # Fernet
    f_key = Fernet.generate_key()
    fernet = Fernet(f_key)
    f_encrypted = fernet.encrypt(data)
    results['Fernet'] = timeit(lambda: Fernet(f_key).decrypt(f_encrypted))

    # AES-128
    key128 = os.urandom(16)
    iv128 = os.urandom(16)
    cipher128 = Cipher(algorithms.AES(key128), modes.CFB(iv128), backend=default_backend())
    encrypted128 = cipher128.encryptor().update(data) + cipher128.encryptor().finalize()
    def decrypt_aes128():
        cipher = Cipher(algorithms.AES(key128), modes.CFB(iv128), backend=default_backend())
        return cipher.decryptor().update(encrypted128) + cipher.decryptor().finalize()
    results['AES-128'] = timeit(decrypt_aes128)

    # AES-192
    key192 = os.urandom(24)
    iv192 = os.urandom(16)
    cipher192 = Cipher(algorithms.AES(key192), modes.CFB(iv192), backend=default_backend())
    encrypted192 = cipher192.encryptor().update(data) + cipher192.encryptor().finalize()
    def decrypt_aes192():
        cipher = Cipher(algorithms.AES(key192), modes.CFB(iv192), backend=default_backend())
        return cipher.decryptor().update(encrypted192) + cipher.decryptor().finalize()
    results['AES-192'] = timeit(decrypt_aes192)

    # AES-256
    key256 = os.urandom(32)
    iv256 = os.urandom(16)
    cipher256 = Cipher(algorithms.AES(key256), modes.CFB(iv256), backend=default_backend())
    encrypted256 = cipher256.encryptor().update(data) + cipher256.encryptor().finalize()
    def decrypt_aes256():
        cipher = Cipher(algorithms.AES(key256), modes.CFB(iv256), backend=default_backend())
        return cipher.decryptor().update(encrypted256) + cipher.decryptor().finalize()
    results['AES-256'] = timeit(decrypt_aes256)

    # ChaCha20
    cha_key = ChaCha20Poly1305.generate_key()
    cha_nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(cha_key)
    cha_encrypted = chacha.encrypt(cha_nonce, data, None)
    def decrypt_chacha():
        chacha = ChaCha20Poly1305(cha_key)
        return chacha.decrypt(cha_nonce, cha_encrypted, None)
    results['ChaCha20'] = timeit(decrypt_chacha)

    # Base64
    b64 = base64.b64encode(data)
    results['Base64'] = timeit(lambda: base64.b64decode(b64))

    # Base32
    b32 = base64.b32encode(data)
    results['Base32'] = timeit(lambda: base64.b32decode(b32))

    # Base16
    b16 = base64.b16encode(data)
    results['Base16'] = timeit(lambda: base64.b16decode(b16))

    # RSA (max len omezen — rozdělíme na bloky 190 bajtů)
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public_key = rsa_private_key.public_key()
    chunk_size = 190
    rsa_chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    rsa_encrypted = [rsa_public_key.encrypt(chunk, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)) for chunk in rsa_chunks]
    def decrypt_rsa():
        return b''.join([
            rsa_private_key.decrypt(chunk, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            for chunk in rsa_encrypted
        ])
    results['RSA-2048'] = timeit(decrypt_rsa)

    # Blowfish (⚠️ deprecated)
    from cryptography.hazmat.decrepit.ciphers import algorithms as depr_algos
    bf_key = os.urandom(16)
    bf_iv = os.urandom(8)
    cipher_bf = Cipher(depr_algos.Blowfish(bf_key), modes.CFB(bf_iv), backend=default_backend())
    encrypted_bf = cipher_bf.encryptor().update(data) + cipher_bf.encryptor().finalize()
    def decrypt_blowfish():
        cipher = Cipher(depr_algos.Blowfish(bf_key), modes.CFB(bf_iv), backend=default_backend())
        return cipher.decryptor().update(encrypted_bf) + cipher.decryptor().finalize()
    results['Blowfish'] = timeit(decrypt_blowfish)

    print(f"\n[+] Benchmark results (decryption time for {mb} MB):\n")
    for k, v in results.items():
        print(f"   {k:<10} : {v:.6f} sec")
    print("\n[+] Benchmark done! 🔥")

if __name__ == "__main__":
    mb = int(args.benchmark) if len(args.benchmark) > 1 else 1
    run_benchmark(mb)
