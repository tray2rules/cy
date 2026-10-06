"""Password-based file encryption with AES-256-GCM (corrected version).
 
File format (all integers big-endian):
    MAGIC (4) | VERSION (1) | ITERATIONS (4) | SALT (16) | NONCE (12) | CIPHERTEXT+TAG
 
The whole header is passed to AES-GCM as associated data, together with a
"context" label (by default the encrypted file's name), so the header cannot
be altered and a file cannot be swapped in under a different name.
"""
 
import os
import struct
import tempfile
 
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
 
MAGIC = b"CYEN"
VERSION = 1
DEFAULT_ITERATIONS = 600_000
MIN_ITERATIONS = 600_000        # refuse files that claim weaker settings
MAX_ITERATIONS = 10_000_000     # refuse absurd values (stops a slow-down attack)
SALT_LEN, NONCE_LEN = 16, 12
HEADER_FMT = ">4sBI16s12s"
HEADER_LEN = struct.calcsize(HEADER_FMT)
PAD_BLOCK = 4096                # plaintext is padded to a multiple of this
MIN_PASSWORD_LEN = 14
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678", "123456789",
    "qwerty", "letmein", "iloveyou", "admin", "welcome", "monkey", "dragon",
    "sunshine", "football", "passwordpassword", "qwertyuiopasdf",
}
 
 
class DecryptionError(Exception):
    """Wrong password, wrong context, or a modified/corrupted file."""
 
 
# ---------- FIX 1: the password is the real key space ----------
 
def check_password(password: str) -> None:
    """Reject passwords that are short or well known."""
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    if password.lower() in COMMON_PASSWORDS or len(set(password)) < 5:
        raise ValueError("Password is too common or too repetitive.")
 
 
def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))
 
 
# ---------- FIX 3: length padding (limits the size leak) ----------
 
def pad(data: bytes) -> bytes:
    framed = struct.pack(">Q", len(data)) + data
    return framed + b"\x00" * (-len(framed) % PAD_BLOCK)
 
 
def unpad(framed: bytes) -> bytes:
    (length,) = struct.unpack(">Q", framed[:8])
    if length > len(framed) - 8:
        raise DecryptionError("Corrupted length field.")
    return framed[8:8 + length]
 
 
# ---------- Safe output writing ----------
 
def atomic_write(path: str, data: bytes) -> None:
    """Write to a temp file, then rename, so a crash never leaves half a file."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
 
 
def _context(path: str, context: str | None) -> bytes:
    return (context if context is not None else os.path.basename(path)).encode("utf-8")
 
 
# ---------- Encrypt / decrypt ----------
 
def encrypt_file(input_path: str, output_path: str, password: str,
                 context: str | None = None) -> None:
    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Output must not overwrite the input file.")
    check_password(password)
 
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    # FIX 2: versioned header that records its own parameters
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, DEFAULT_ITERATIONS, salt, nonce)
    key = derive_key(password, salt, DEFAULT_ITERATIONS)
 
    with open(input_path, "rb") as f:
        plaintext = f.read()
 
    # FIX 2: header + context are authenticated as associated data
    aad = header + _context(output_path, context)
    ciphertext = AESGCM(key).encrypt(nonce, pad(plaintext), aad)
    atomic_write(output_path, header + ciphertext)
 
 
def decrypt_file(input_path: str, output_path: str, password: str,
                 context: str | None = None) -> None:
    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Output must not overwrite the input file.")
    with open(input_path, "rb") as f:
        blob = f.read()
    if len(blob) < HEADER_LEN + 16:
        raise DecryptionError("File too short.")
 
    header, ciphertext = blob[:HEADER_LEN], blob[HEADER_LEN:]
    magic, version, iterations, salt, nonce = struct.unpack(HEADER_FMT, header)
    if magic != MAGIC or version != VERSION:
        raise DecryptionError("Unknown file format or version.")
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise DecryptionError("Iteration count out of allowed range.")
 
    key = derive_key(password, salt, iterations)
    aad = header + _context(input_path, context)
    try:
        framed = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise DecryptionError("Wrong password, wrong file, or file was modified.") from None
    atomic_write(output_path, unpad(framed))
 
