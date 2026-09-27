"""
database.py
============
All database access for SecureVault (SQLite).

Tables:
    users  - registered accounts (password HASHES only, never passwords)
    files  - metadata for each encrypted file stored on disk

Security rules followed in this module:
    1. EVERY query is parameterized (uses ? placeholders).
       No user input is ever inserted into SQL with f-strings or +.
       This prevents SQL injection.
    2. File lookups ALWAYS filter by owner_id as well as file id.
       This prevents IDOR (users accessing other users' files).
    3. Foreign keys are switched on for every connection,
       so the database enforces relationships itself.

Every public function takes `db_path` as its first argument
(dependency injection), so the app and the tests can use
different database files.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

# ---------------------------------------------------------------
# Schema
# ---------------------------------------------------------------
# "IF NOT EXISTS" makes this safe to run on every app start:
# it creates tables the first time and does nothing afterwards.

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE
                          CHECK (length(username) BETWEEN 3 AND 30),
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id      INTEGER NOT NULL
                          REFERENCES users(id) ON DELETE CASCADE,
    original_name TEXT    NOT NULL,
    stored_name   TEXT    NOT NULL UNIQUE,
    size_bytes    INTEGER NOT NULL CHECK (size_bytes >= 0),
    sha256        TEXT    NOT NULL CHECK (length(sha256) = 64),
    uploaded_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Speeds up "list all files for this user" (the dashboard query).
CREATE INDEX IF NOT EXISTS idx_files_owner_id ON files(owner_id);
"""


# ---------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------

class UsernameTakenError(Exception):
    """Raised when someone tries to register a username that already exists."""


# ---------------------------------------------------------------
# Connection helper (private)
# ---------------------------------------------------------------

@contextmanager
def _connect(db_path: str) -> Iterator[sqlite3.Connection]:
    """
    Open a database connection, and ALWAYS clean it up afterwards.

    Usage:
        with _connect(db_path) as connection:
            connection.execute(...)

    What it guarantees:
        - rows come back as sqlite3.Row (access columns by name)
        - foreign key enforcement is ON (SQLite defaults it to OFF!)
        - changes are committed if the block succeeds
        - changes are rolled back if anything raises an error
        - the connection is closed no matter what

    Note: sqlite3's own `with connection:` commits/rolls back but does
    NOT close the connection. That's why we write this helper.

    The leading underscore in the name means "internal to this module".
    """
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


# ---------------------------------------------------------------
# Setup
# ---------------------------------------------------------------

def init_db(db_path: str) -> None:
    """
    Create the tables and index if they don't already exist.
    Called once when the app starts. Safe to call repeatedly.

    Args:
        db_path: Path to the SQLite file (created automatically if missing).
    """
    with _connect(db_path) as connection:
        connection.executescript(SCHEMA_SQL)


# ---------------------------------------------------------------
# User queries
# ---------------------------------------------------------------

def create_user(db_path: str, username: str, password_hash: str) -> int:
    """
    Insert a new user.

    Args:
        db_path:       Path to the SQLite file.
        username:      The chosen username (already validated by the caller).
        password_hash: The HASHED password. Never pass a plain password here.

    Returns:
        The new user's id.

    Raises:
        UsernameTakenError: If the username already exists (case-insensitive).
        sqlite3.IntegrityError: If another constraint fails (e.g. length CHECK).
    """
    try:
        with _connect(db_path) as connection:
            cursor = connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            return cursor.lastrowid
    except sqlite3.IntegrityError as error:
        # Translate the database's generic error into a clear, specific one.
        if "UNIQUE" in str(error):
            raise UsernameTakenError(
                f"The username '{username}' is already taken."
            ) from None
        raise


def get_user_by_username(db_path: str, username: str) -> dict | None:
    """
    Look up a user by username (case-insensitive). Used during login.

    Returns:
        A dict with id, username, password_hash, created_at, or None if not found.
    """
    with _connect(db_path) as connection:
        row = connection.execute(
            "SELECT id, username, password_hash, created_at "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(db_path: str, user_id: int) -> dict | None:
    """
    Look up a user by id. Used to load the logged-in user from the session.

    Returns:
        A dict with id, username, created_at, or None if not found.
        (password_hash is deliberately NOT returned: this function is used
        on every page load, and code that doesn't need the hash shouldn't get it.
        This is the principle of least privilege.)
    """
    with _connect(db_path) as connection:
        row = connection.execute(
            "SELECT id, username, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------
# File queries
# ---------------------------------------------------------------

def add_file(
    db_path: str,
    owner_id: int,
    original_name: str,
    stored_name: str,
    size_bytes: int,
    sha256: str,
) -> int:
    """
    Record metadata for a newly uploaded (already encrypted) file.

    Args:
        owner_id:      id of the user who uploaded the file.
        original_name: The filename the user uploaded (display only).
        stored_name:   The random filename used on disk.
        size_bytes:    Size of the ORIGINAL (unencrypted) file.
        sha256:        SHA-256 hex digest of the ORIGINAL file.

    Returns:
        The new file's id.
    """
    with _connect(db_path) as connection:
        cursor = connection.execute(
            "INSERT INTO files "
            "(owner_id, original_name, stored_name, size_bytes, sha256) "
            "VALUES (?, ?, ?, ?, ?)",
            (owner_id, original_name, stored_name, size_bytes, sha256),
        )
        return cursor.lastrowid


def list_files_for_user(db_path: str, owner_id: int) -> list[dict]:
    """
    Get every file owned by one user, newest first. Used by the dashboard.

    Returns:
        A list of dicts (empty list if the user has no files).
    """
    with _connect(db_path) as connection:
        rows = connection.execute(
            "SELECT id, original_name, stored_name, size_bytes, sha256, uploaded_at "
            "FROM files WHERE owner_id = ? "
            "ORDER BY uploaded_at DESC, id DESC",
            (owner_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_file_for_user(db_path: str, file_id: int, owner_id: int) -> dict | None:
    """
    Get ONE file, but only if it belongs to the given user.

    This is the IDOR protection: filtering on BOTH id and owner_id means
    a user who guesses another file's id simply gets None ("not found").

    Returns:
        A dict of the file's metadata, or None if it doesn't exist
        OR belongs to someone else (the caller can't tell which, on purpose).
    """
    with _connect(db_path) as connection:
        row = connection.execute(
            "SELECT id, owner_id, original_name, stored_name, size_bytes, "
            "sha256, uploaded_at "
            "FROM files WHERE id = ? AND owner_id = ?",
            (file_id, owner_id),
        ).fetchone()
    return dict(row) if row else None


def delete_file_for_user(db_path: str, file_id: int, owner_id: int) -> bool:
    """
    Delete ONE file's database record, only if it belongs to the given user.
    (Deleting the encrypted file on disk is the caller's job, in Module 5.)

    Returns:
        True if a row was deleted, False if nothing matched.
    """
    with _connect(db_path) as connection:
        cursor = connection.execute(
            "DELETE FROM files WHERE id = ? AND owner_id = ?",
            (file_id, owner_id),
        )
        return cursor.rowcount == 1