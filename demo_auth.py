"""
demo_auth.py
=============
Live demonstration of auth.py (Part 1: pure logic). NOT part of the web app.

Shows:
    1. Same password -> different hashes (random salt); verification works
    2. Validation rejects bad usernames and passwords
    3. Registration works; duplicates rejected (case-insensitive)
    4. Login succeeds/fails correctly, and all attempts take similar TIME
       (so attackers can't tell which usernames exist)

Uses a throwaway demo_auth.db that is deleted at the end.
Run from the project folder:  python demo_auth.py
"""

import os
import time

import auth
import database

DEMO_DB_PATH = "demo_auth.db"
DEMO_PASSWORD = "CorrectHorse42"


def main() -> None:
    """Run each demonstration step and print the results."""
    if os.path.exists(DEMO_DB_PATH):
        os.remove(DEMO_DB_PATH)

    try:
        database.init_db(DEMO_DB_PATH)

        # --- 1. Hashing with salts ---
        print("1) PASSWORD HASHING")
        first_hash = auth.hash_password(DEMO_PASSWORD)
        second_hash = auth.hash_password(DEMO_PASSWORD)
        print("   Hash 1:", first_hash)
        print("   Hash 2:", second_hash)
        print("   Same password, same hash?", first_hash == second_hash)
        print("   Verify correct password   :", auth.verify_password(first_hash, DEMO_PASSWORD))
        print("   Verify wrong-case password:", auth.verify_password(first_hash, DEMO_PASSWORD.lower()))

        # --- 2. Validation ---
        print("\n2) VALIDATION")
        bad_inputs = [
            ("ab", "longenough1"),        # username too short
            ("bad name!", "longenough1"),  # illegal characters
            ("charlie", "short"),          # password too short
            ("charlie12", "CHARLIE12"),    # password equals username
        ]
        for username, password in bad_inputs:
            try:
                auth.register_user(DEMO_DB_PATH, username, password)
                print(f"   FAILURE: {username!r} was accepted!")
            except auth.ValidationError as error:
                print(f"   {username!r:12} / {password!r:14} -> {error}")

        # --- 3. Registration ---
        print("\n3) REGISTRATION")
        user_id = auth.register_user(DEMO_DB_PATH, "alice", DEMO_PASSWORD)
        print(f"   Registered 'alice' with id={user_id}")
        try:
            auth.register_user(DEMO_DB_PATH, "ALICE", "AnotherPass99")
            print("   FAILURE: duplicate was accepted!")
        except database.UsernameTakenError as error:
            print("   Duplicate rejected:", error)

        # --- 4. Login + timing ---
        print("\n4) LOGIN ATTEMPTS (watch the timings)")
        attempts = [
            ("alice", DEMO_PASSWORD, "correct password"),
            ("ALICE", DEMO_PASSWORD, "username in capitals"),
            ("alice", "WrongPassword1", "wrong password"),
            ("nobody_here", DEMO_PASSWORD, "user doesn't exist"),
        ]
        for username, password, label in attempts:
            start_time = time.perf_counter()
            result = auth.authenticate_user(DEMO_DB_PATH, username, password)
            elapsed_seconds = time.perf_counter() - start_time
            outcome = "SUCCESS" if result else "FAILED "
            print(f"   {label:22} -> {outcome}  ({elapsed_seconds:.2f}s)")

    finally:
        if os.path.exists(DEMO_DB_PATH):
            os.remove(DEMO_DB_PATH)
            print("\nCleaned up", DEMO_DB_PATH)


# Only run main() when this file is executed directly.
if __name__ == "__main__":
    main()