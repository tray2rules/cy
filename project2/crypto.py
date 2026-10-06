import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Encrypt a file using AES-256-GCM."""
    salt = os.urandom(16)
    nonce = os.urandom(12)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # 256-bit AES key
        salt=salt,
        iterations=600_000,
    )
    key = kdf.derive(password.encode("utf-8"))

    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    # Store salt + nonce + ciphertext in the output file.
    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

#ChatGPT, "Write me a Python function that encrypts a file with AES"
