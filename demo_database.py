"""
demo_database.py
=================
Live demonstration of database.py. NOT part of the web app.

Shows:
    1. Tables are created
    2. Users can be created; duplicate usernames are rejected (case-insensitive)
    3. CHECK constraints reject invalid data
    4. File metadata can be stored and listed
    5. IDOR protection: another user cannot fetch or delete your file
    6. SQL injection input is treated as plain text, not code

Uses a throwaway demo.db file that is deleted at the end.
Run from the project folder:  python demo_database.py
"""

import os
import sqlite3

import database

DEMO_DB_PATH = "demo.db"

# A fake 64-char hash, just for this demo (real hashing comes in Module 5).
FAKE_SHA256 = "a" * 64


def main() -> None:
    """Run each demonstration step and print the results."""
    # Start fresh in case a previous run crashed and left the file behind.
    if os.path.exists(DEMO_DB_PATH):
        os.remove(DEMO_DB_PATH)

    try:
        # --- 1. Create tables ---
        database.init_db(DEMO_DB_PATH)
        print("1) Tables created in", DEMO_DB_PATH)

        # --- 2. Users and duplicates ---
        # "fake-hash" stands in for a real password hash (Module 4).
        alice_id = database.create_user(DEMO_DB_PATH, "alice", "fake-hash")
        bob_id = database.create_user(DEMO_DB_PATH, "bob", "fake-hash")
        print(f"\n2) Created alice (id={alice_id}) and bob (id={bob_id})")
        try:
            database.create_user(DEMO_DB_PATH, "ALICE", "fake-hash")
            print("   FAILURE: duplicate username was accepted!")
        except database.UsernameTakenError as error:
            print("   Duplicate rejected:", error)

        # --- 3. CHECK constraint ---
        print("\n3) CHECK CONSTRAINT (username too short)")
        try:
            database.create_user(DEMO_DB_PATH, "ab", "fake-hash")
            print("   FAILURE: 2-character username was accepted!")
        except sqlite3.IntegrityError as error:
            print("   Rejected by database:", error)

        # --- 4. Store and list file metadata ---
        file_id = database.add_file(
            DEMO_DB_PATH,
            owner_id=alice_id,
            original_name="secret-notes.pdf",
            stored_name="3f9a1c7e.enc",
            size_bytes=2048,
            sha256=FAKE_SHA256,
        )
        alice_files = database.list_files_for_user(DEMO_DB_PATH, alice_id)
        print(f"\n4) Alice uploaded file id={file_id}")
        print("   Alice's files:", [f["original_name"] for f in alice_files])
        print("   Bob's files  :", database.list_files_for_user(DEMO_DB_PATH, bob_id))

        # --- 5. IDOR protection ---
        print("\n5) IDOR PROTECTION (Bob tries to access Alice's file)")
        stolen = database.get_file_for_user(DEMO_DB_PATH, file_id, owner_id=bob_id)
        print("   Bob fetches it  ->", stolen)
        deleted = database.delete_file_for_user(DEMO_DB_PATH, file_id, owner_id=bob_id)
        print("   Bob deletes it  ->", deleted)
        still_there = database.get_file_for_user(DEMO_DB_PATH, file_id, owner_id=alice_id)
        print("   Alice still has it?", still_there is not None)

        # --- 6. SQL injection attempt ---
        print("\n6) SQL INJECTION ATTEMPT")
        malicious_input = "' OR '1'='1"
        result = database.get_user_by_username(DEMO_DB_PATH, malicious_input)
        print(f"   Login lookup for {malicious_input!r} ->", result)

    finally:
        # Always remove the demo database, even if a step above failed.
        if os.path.exists(DEMO_DB_PATH):
            os.remove(DEMO_DB_PATH)
            print("\nCleaned up", DEMO_DB_PATH)


# Only run main() when this file is executed directly.
if __name__ == "__main__":
    main()