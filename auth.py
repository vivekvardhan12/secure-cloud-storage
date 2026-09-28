"""
auth.py
========
Authentication for SecureVault: "who is this user?"

Part 1 - Pure logic (works without Flask running, easy to test):
    validate_username()   - enforce username rules
    validate_password()   - enforce password rules (NIST SP 800-63B style)
    hash_password()       - PBKDF2-HMAC-SHA256, 600,000 iterations, random salt
    verify_password()     - check a password against a stored hash
    register_user()       - validate + hash + save a new account
    authenticate_user()   - check login credentials safely

Part 2 - Flask session helpers (only work inside a web request):
    log_in()              - start a fresh session for a user
    log_out()             - end the session
    load_logged_in_user() - runs before every request, sets g.user
    login_required        - decorator that protects private pages

Security properties:
    - Passwords are HASHED (one-way), never stored or logged in plain text.
    - Every hash has a unique random salt (defeats rainbow tables).
    - 600,000 iterations make brute-force guessing very slow.
    - Login failures return the same result whether the username or the
      password was wrong, and take the same TIME (prevents user enumeration).
"""

import re
from functools import wraps

from flask import current_app, flash, g, redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import database

# ---------------------------------------------------------------
# Rules and settings
# ---------------------------------------------------------------

USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 30
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128

# Letters, digits and underscore only. Used with fullmatch(), which
# requires the WHOLE string to match (safer than ^...$, because in
# Python's re module "$" also matches just before a trailing newline).
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_]+")

# PBKDF2 with HMAC-SHA256 and 600,000 iterations (OWASP recommendation).
# Werkzeug's own default is scrypt; we choose PBKDF2 explicitly because
# it is NIST-approved and straightforward to explain.
PASSWORD_HASH_METHOD = "pbkdf2:sha256:600000"

# A throwaway hash used ONLY to keep login timing constant when the
# username doesn't exist (see authenticate_user). Computed once at import.
_DUMMY_PASSWORD_HASH = generate_password_hash(
    "dummy-password-for-constant-timing", method=PASSWORD_HASH_METHOD
)


# ---------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------

class ValidationError(Exception):
    """
    Raised when registration input breaks a rule.
    The message is written to be safe and helpful to show to the user.
    """


# ===============================================================
# PART 1: Pure logic
# ===============================================================

def validate_username(username: str) -> str:
    """
    Check a username against the rules.

    Args:
        username: Raw input from the registration form.

    Returns:
        The cleaned username (leading/trailing spaces removed).

    Raises:
        ValidationError: With a user-friendly explanation if a rule is broken.
    """
    cleaned_username = username.strip()

    if not USERNAME_MIN_LENGTH <= len(cleaned_username) <= USERNAME_MAX_LENGTH:
        raise ValidationError(
            f"Username must be {USERNAME_MIN_LENGTH}-{USERNAME_MAX_LENGTH} characters long."
        )

    if not USERNAME_PATTERN.fullmatch(cleaned_username):
        raise ValidationError(
            "Username can only contain letters, numbers and underscores."
        )

    return cleaned_username


def validate_password(password: str, username: str) -> None:
    """
    Check a password against the rules.

    Note: the password is NOT stripped of spaces. Spaces are allowed
    and may be part of a passphrase.

    Args:
        password: Raw password from the registration form.
        username: The (already cleaned) username, to block password == username.

    Raises:
        ValidationError: With a user-friendly explanation if a rule is broken.
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValidationError(
            f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
        )

    if len(password) > PASSWORD_MAX_LENGTH:
        raise ValidationError(
            f"Password must be at most {PASSWORD_MAX_LENGTH} characters long."
        )

    if password.lower() == username.lower():
        raise ValidationError("Password must not be the same as your username.")


def hash_password(password: str) -> str:
    """
    Hash a password with PBKDF2-HMAC-SHA256 and a fresh random salt.

    Returns:
        A self-describing string: "pbkdf2:sha256:600000$<salt>$<hash>".
        It contains everything needed to verify the password later.
    """
    return generate_password_hash(password, method=PASSWORD_HASH_METHOD)


def verify_password(stored_hash: str, password: str) -> bool:
    """
    Check whether a password matches a stored hash.

    Werkzeug reads the method, iterations and salt from the stored string,
    re-hashes the given password the same way, and compares the results
    using a constant-time comparison (so the comparison itself doesn't
    leak timing information).

    Returns:
        True if the password is correct, otherwise False.
    """
    return check_password_hash(stored_hash, password)


def register_user(db_path: str, username: str, password: str) -> int:
    """
    Create a new account: validate input, hash the password, save the user.

    Args:
        db_path:  Path to the SQLite database.
        username: Raw username from the form.
        password: Raw password from the form.

    Returns:
        The new user's id.

    Raises:
        ValidationError:             If the username or password breaks a rule.
        database.UsernameTakenError: If the username already exists.
    """
    cleaned_username = validate_username(username)
    validate_password(password, cleaned_username)

    # Only the HASH goes to the database. The plain password is discarded
    # when this function returns.
    password_hash = hash_password(password)
    return database.create_user(db_path, cleaned_username, password_hash)


def authenticate_user(db_path: str, username: str, password: str) -> dict | None:
    """
    Check login credentials.

    Security behaviour:
        - Returns None for BOTH "no such user" and "wrong password", so the
          caller can only ever show one generic error message.
        - If the user doesn't exist, we still run a full password check
          against a dummy hash, so both failure cases take the same time.
          Without this, response timing would reveal which usernames exist.

    Returns:
        {"id": ..., "username": ...} on success, otherwise None.
    """
    user = database.get_user_by_username(db_path, username.strip())

    if user is None:
        # Burn the same amount of time as a real check, then fail.
        check_password_hash(_DUMMY_PASSWORD_HASH, password)
        return None

    if not verify_password(user["password_hash"], password):
        return None

    # Return only what the caller needs: never pass the hash around.
    return {"id": user["id"], "username": user["username"]}


# ===============================================================
# PART 2: Flask session helpers (require an active web request)
# ===============================================================

def log_in(user: dict) -> None:
    """
    Start a logged-in session for a user.

    session.clear() first throws away any existing session data.
    This defeats session fixation attacks: the logged-in session is
    always brand new, never one an attacker prepared in advance.

    Only the user id is stored. Flask session cookies are SIGNED
    (tamper-proof) but NOT encrypted (readable), so never put
    secrets in the session.
    """
    session.clear()
    session["user_id"] = user["id"]


def log_out() -> None:
    """End the session by removing all session data."""
    session.clear()


def load_logged_in_user() -> None:
    """
    Runs before EVERY request (registered in app.py in Module 5).

    Reads the user id from the session cookie and loads that user into
    `g.user`, so any page can check who is logged in.
    (`g` is Flask's per-request storage: it is reset for every request.)

    If the session points to a user that no longer exists, the stale
    session is cleared instead of trusted.
    """
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
        return

    g.user = database.get_user_by_id(current_app.config["DATABASE_PATH"], user_id)

    if g.user is None:
        session.clear()


def login_required(view):
    """
    Decorator that protects a page so only logged-in users can see it.

    Usage (in Module 5):
        @app.route("/dashboard")
        @login_required
        def dashboard():
            ...

    If nobody is logged in, the user is sent to the login page with a
    message, and the protected code never runs.
    """
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.get("user") is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view