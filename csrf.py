"""
csrf.py
========
CSRF (Cross-Site Request Forgery) protection using the
"synchronizer token" pattern.

How it works:
    1. Each session gets one random secret token, stored in the
       (signed) session cookie.
    2. Every HTML form includes that token in a hidden field:
           <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    3. Before handling ANY state-changing request (POST, PUT, DELETE...),
       the server checks that the form's token matches the session's token.

An attacker's website can make your browser SEND a request to us,
but it cannot READ our pages (same-origin policy), so it can never
learn the token. Its forged requests are rejected with 400.

Production alternative: the Flask-WTF library (CSRFProtect).
"""

import hmac
import secrets

from flask import abort, request, session

# Key used to store the token inside the session.
CSRF_SESSION_KEY = "_csrf_token"

# Name of the hidden form field that carries the token.
CSRF_FORM_FIELD = "csrf_token"

# "Safe" methods only read data, so they don't need a token.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def get_csrf_token() -> str:
    """
    Return this session's CSRF token, creating one if it doesn't exist yet.

    Made available to every template as csrf_token() (registered in app.py).

    Note: auth.log_in() clears the session, which also discards the old
    token. A fresh token is created after login, so a token obtained
    before logging in can't be reused afterwards.
    """
    token = session.get(CSRF_SESSION_KEY)
    if token is None:
        # 32 random bytes from the OS's secure generator, URL-safe text.
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def verify_csrf_token() -> None:
    """
    Runs before every request (registered in app.py).

    For state-changing methods, abort with 400 unless the submitted
    form token matches the session token.

    hmac.compare_digest() compares in constant time, so response timing
    can't reveal how many characters of a guessed token were correct.
    Both values are encoded to bytes first, because compare_digest only
    accepts ASCII when given str, and form input could contain anything.
    """
    if request.method in SAFE_METHODS:
        return

    expected_token = session.get(CSRF_SESSION_KEY)
    submitted_token = request.form.get(CSRF_FORM_FIELD, "")

    if not expected_token or not hmac.compare_digest(
        expected_token.encode("utf-8"), submitted_token.encode("utf-8")
    ):
        abort(400, description="Invalid or missing security token. "
                               "Please go back, refresh the page, and try again.")