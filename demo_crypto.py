"""
demo_crypto.py
===============
Live demonstration of crypto_utils.py. NOT part of the web app.

Shows five security properties:
    1. Hashing produces a fixed-size fingerprint
    2. Same input encrypted twice -> different ciphertext (random nonce)
    3. Decryption recovers the exact original (hash matches)
    4. Tampering with ONE bit is detected and rejected (GCM tag)
    5. The wrong key is rejected

Run from the project folder:  python demo_crypto.py
"""

import os

from dotenv import load_dotenv

from crypto_utils import (
    DecryptionError,
    decrypt_data,
    encrypt_data,
    load_key,
    sha256_hex,
)


def main() -> None:
    """Run each demonstration step and print the results."""
    # Read .env into environment variables, then load and validate the key.
    load_dotenv()
    key = load_key(os.getenv("FILE_ENCRYPTION_KEY"))

    original = b"This is a confidential file for the CNS project."

    # --- 1. Hashing ---
    print("1) HASHING")
    print("   Original data :", original)
    print("   SHA-256       :", sha256_hex(original))

    # --- 2. Encryption with random nonces ---
    encrypted_first = encrypt_data(original, key)
    encrypted_second = encrypt_data(original, key)
    print("\n2) ENCRYPTION")
    print("   Encrypted (first 48 hex chars):", encrypted_first.hex()[:48], "...")
    print(f"   Size: {len(original)} bytes -> {len(encrypted_first)} bytes "
          "(+28 = 12 nonce + 16 tag)")
    print("   Same input, same output twice? ", encrypted_first == encrypted_second)

    # --- 3. Decryption ---
    recovered = decrypt_data(encrypted_first, key)
    print("\n3) DECRYPTION")
    print("   Recovered data:", recovered)
    print("   Hash matches original?", sha256_hex(recovered) == sha256_hex(original))

    # --- 4. Tamper detection ---
    # Copy the bytes into a mutable bytearray and flip a single bit
    # inside the ciphertext (byte 20 is past the 12-byte nonce).
    tampered = bytearray(encrypted_first)
    tampered[20] ^= 0b00000001
    print("\n4) TAMPER DETECTION (flipped 1 bit)")
    try:
        decrypt_data(bytes(tampered), key)
        print("   FAILURE: tampered data was accepted!")
    except DecryptionError as error:
        print("   Rejected:", error)

    # --- 5. Wrong key ---
    wrong_key = os.urandom(32)
    print("\n5) WRONG KEY")
    try:
        decrypt_data(encrypted_first, wrong_key)
        print("   FAILURE: wrong key was accepted!")
    except DecryptionError as error:
        print("   Rejected:", error)


# Only run main() when this file is executed directly,
# not when it is imported by another module.
if __name__ == "__main__":
    main()