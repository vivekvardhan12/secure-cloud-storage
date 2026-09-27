"""
crypto_utils.py
================
All cryptographic operations for SecureVault live in this one module.

Provides:
    - load_key()      : validate and convert the hex key from .env into bytes
    - encrypt_data()  : AES-256-GCM encryption (confidentiality + integrity)
    - decrypt_data()  : AES-256-GCM decryption with tamper detection
    - sha256_hex()    : SHA-256 fingerprint of data, as a hex string

Encrypted data format (what gets written to disk):
    [ 12-byte nonce ][ ciphertext ][ 16-byte authentication tag ]

Design rule: no other file in the project should import from
`cryptography` directly. Keeping crypto in one place makes it
easy to audit, test, and upgrade.
"""

import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------
# Constants
# ---------------------------------------------------------------

# AES-256 requires a 32-byte (256-bit) key.
KEY_SIZE_BYTES = 32

# 12 bytes (96 bits) is the nonce size recommended by NIST for GCM.
# Other sizes are allowed but are slower and less well analysed.
NONCE_SIZE_BYTES = 12

# GCM appends a 16-byte (128-bit) authentication tag to the ciphertext.
TAG_SIZE_BYTES = 16


# ---------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------

class DecryptionError(Exception):
    """
    Raised when encrypted data cannot be decrypted.

    This happens when:
        - the data was modified (tampered with or corrupted), or
        - the wrong key was used.

    GCM cannot tell these two cases apart, and that is intentional:
    telling an attacker *why* decryption failed would leak information.
    """


# ---------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------

def load_key(hex_key: str | None) -> bytes:
    """
    Convert the hex-encoded key from the .env file into raw bytes
    and validate that it is exactly 32 bytes long.

    Args:
        hex_key: The 64-character hex string from FILE_ENCRYPTION_KEY.

    Returns:
        The 32-byte key as bytes, ready for AES-256.

    Raises:
        ValueError: If the key is missing, not valid hex, or the wrong length.
                    We fail loudly at startup rather than run with a bad key.
    """
    if not hex_key:
        raise ValueError(
            "FILE_ENCRYPTION_KEY is missing. Check that your .env file "
            "exists in the project folder and contains this variable."
        )

    try:
        key_bytes = bytes.fromhex(hex_key.strip())
    except ValueError:
        # "from None" hides the confusing internal traceback from the user.
        raise ValueError(
            "FILE_ENCRYPTION_KEY must contain only hex characters (0-9, a-f)."
        ) from None

    if len(key_bytes) != KEY_SIZE_BYTES:
        raise ValueError(
            f"FILE_ENCRYPTION_KEY must be {KEY_SIZE_BYTES} bytes "
            f"({KEY_SIZE_BYTES * 2} hex characters), but got "
            f"{len(key_bytes)} bytes. Regenerate it with: "
            'python -c "import secrets; print(secrets.token_hex(32))"'
        )

    return key_bytes


# ---------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------

def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data with AES-256-GCM.

    A fresh random nonce is generated on EVERY call. This guarantees
    that encrypting the same file twice produces different output,
    and it prevents the catastrophic nonce-reuse attack on GCM.

    Args:
        plaintext: The original file contents.
        key:       The 32-byte key returned by load_key().

    Returns:
        nonce + ciphertext + tag, as a single bytes object,
        ready to be written to disk.
    """
    # os.urandom uses the operating system's cryptographically secure
    # random number generator (unpredictable, unlike the `random` module).
    nonce = os.urandom(NONCE_SIZE_BYTES)

    cipher = AESGCM(key)

    # The third argument is "associated data" (AAD): extra data that is
    # authenticated but not encrypted. We don't need it, so we pass None.
    # The library appends the 16-byte tag to the end of the ciphertext.
    ciphertext_with_tag = cipher.encrypt(nonce, plaintext, None)

    # Store the nonce in front so decrypt_data() can find it.
    # The nonce is not secret; only the key is.
    return nonce + ciphertext_with_tag


def decrypt_data(encrypted_blob: bytes, key: bytes) -> bytes:
    """
    Decrypt data produced by encrypt_data() and verify its integrity.

    If even one bit of the blob was changed, GCM's tag check fails
    and NO plaintext is returned. We never hand back unverified data.

    Args:
        encrypted_blob: The bytes read from disk (nonce + ciphertext + tag).
        key:            The same 32-byte key used for encryption.

    Returns:
        The original plaintext bytes.

    Raises:
        DecryptionError: If the data is too short, tampered with,
                         or encrypted with a different key.
    """
    # The smallest valid blob is an empty file: 12-byte nonce + 16-byte tag.
    minimum_length = NONCE_SIZE_BYTES + TAG_SIZE_BYTES
    if len(encrypted_blob) < minimum_length:
        raise DecryptionError("Encrypted data is too short to be valid.")

    # Split the blob back into its parts using slicing.
    nonce = encrypted_blob[:NONCE_SIZE_BYTES]
    ciphertext_with_tag = encrypted_blob[NONCE_SIZE_BYTES:]

    cipher = AESGCM(key)

    try:
        # decrypt() recomputes the tag and compares it with the stored one.
        # If they differ, it raises InvalidTag instead of returning data.
        return cipher.decrypt(nonce, ciphertext_with_tag, None)
    except InvalidTag:
        raise DecryptionError(
            "Integrity check failed: the file was modified, corrupted, "
            "or encrypted with a different key."
        ) from None


# ---------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    """
    Compute the SHA-256 fingerprint of data.

    Used to show users a checksum of their ORIGINAL file, so they can
    verify a download independently (e.g. with `certutil -hashfile`).

    Args:
        data: Any bytes (normally the original, unencrypted file).

    Returns:
        A 64-character lowercase hex string.
    """
    return hashlib.sha256(data).hexdigest()