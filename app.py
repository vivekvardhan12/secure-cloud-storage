"""
app.py
=======
Entry point and controller layer for SecureVault.

Responsibilities:
    - Build the Flask app (application factory: create_app)
    - Load configuration and secrets from environment variables / .env
    - Wire together auth, csrf, crypto_utils and database
    - Define every route (register, login, upload, download, ...)
    - Add security headers to every response
    - Turn errors into friendly pages without leaking internals

Run locally (development):
    python app.py
  or
    flask --app app run

The HTML templates used here are built in Module 6:
    base.html, login.html, register.html, dashboard.html, error.html
"""

import io
import logging
import os
import uuid
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

import auth
import crypto_utils
import csrf
import database

# ---------------------------------------------------------------
# Constants
# ---------------------------------------------------------------

# Absolute path of the folder containing this file. Using it for default
# paths means the app works no matter which folder you launch it from.
BASE_DIR = Path(__file__).resolve().parent

DEFAULT_MAX_UPLOAD_MB = 10
MAX_ORIGINAL_NAME_LENGTH = 255
BYTES_PER_MB = 1024 * 1024

# One named logger for the whole app. Output format example:
# 2026-09-28 14:03:11,512 INFO securevault: Upload: user_id=1 file_id=3 ...
logger = logging.getLogger("securevault")


# ---------------------------------------------------------------
# Small helper functions
# ---------------------------------------------------------------

def format_file_size(size_bytes: int) -> str:
    """
    Turn a byte count into a human-friendly string for the dashboard.
    Registered as the Jinja template filter "filesize" (Module 6).

    Examples: 512 -> "512 B", 2048 -> "2.0 KB", 5242880 -> "5.0 MB"
    """
    units = ["B", "KB", "MB", "GB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size_bytes} B"  # Unreachable; keeps static checkers happy.


def clean_original_filename(raw_filename: str) -> str:
    """
    Make the user's filename safe to DISPLAY and to use as a download name.
    (It is never used on disk; disk names are random UUIDs.)

    Steps:
        1. Keep only the last path component. Some browsers send
           "C:\\fakepath\\report.pdf", and attackers can send "../../x".
        2. Remove non-printable characters (newlines, tabs, control codes),
           which could break headers or logs.
        3. Fall back to a default if nothing is left; cap the length.
    """
    name_only = raw_filename.replace("\\", "/").split("/")[-1]
    printable_name = "".join(ch for ch in name_only if ch.isprintable()).strip()
    if not printable_name:
        printable_name = "unnamed_file"
    return printable_name[:MAX_ORIGINAL_NAME_LENGTH]


# ---------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------

def create_app(test_config: dict | None = None) -> Flask:
    """
    Build and return a fully configured SecureVault app.

    Args:
        test_config: Optional settings that override the defaults.
                     Tests use this to point at a temporary database
                     and storage folder (Module 7).

    Returns:
        A ready-to-run Flask application.

    Raises:
        RuntimeError / ValueError: If secrets are missing or invalid.
        The app refuses to start rather than run insecurely.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Read .env into environment variables. Existing environment variables
    # are NOT overwritten, so a hosting platform's settings win (Module 8).
    load_dotenv()

    app = Flask(__name__)

    _load_config(app, test_config)

    # Make sure the storage folder and database tables exist.
    Path(app.config["STORAGE_FOLDER"]).mkdir(parents=True, exist_ok=True)
    database.init_db(app.config["DATABASE_PATH"])

    _register_hooks(app)
    _register_routes(app)
    _register_error_handlers(app)

    logger.info("SecureVault started. Database: %s | Storage: %s",
                app.config["DATABASE_PATH"], app.config["STORAGE_FOLDER"])
    return app


# ---------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------

def _load_config(app: Flask, test_config: dict | None) -> None:
    """
    Load settings from environment variables, apply test overrides,
    then validate the secrets.

    Cookie settings:
        HTTPONLY - JavaScript cannot read the session cookie (limits XSS damage)
        SAMESITE - browser won't send the cookie on cross-site POSTs (limits CSRF)
        SECURE   - cookie only sent over HTTPS; enable in production
                   (it must be off locally, since http://127.0.0.1 isn't HTTPS)
    """
    max_upload_mb = int(os.getenv("MAX_UPLOAD_MB", str(DEFAULT_MAX_UPLOAD_MB)))

    app.config.from_mapping(
        SECRET_KEY=os.getenv("FLASK_SECRET_KEY"),
        FILE_ENCRYPTION_KEY=os.getenv("FILE_ENCRYPTION_KEY"),
        DATABASE_PATH=os.getenv("DATABASE_PATH", str(BASE_DIR / "securevault.db")),
        STORAGE_FOLDER=os.getenv("STORAGE_FOLDER", str(BASE_DIR / "storage")),
        MAX_CONTENT_LENGTH=max_upload_mb * BYTES_PER_MB,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    )

    if test_config:
        app.config.update(test_config)

    # Fail fast on a missing or weak session-signing key.
    secret_key = app.config["SECRET_KEY"]
    if not secret_key or len(secret_key) < 32:
        raise RuntimeError(
            "FLASK_SECRET_KEY is missing or too short (need 32+ characters). "
            "Check your .env file."
        )

    # Validate and convert the file key once, at startup (Module 2).
    app.config["FILE_KEY_BYTES"] = crypto_utils.load_key(app.config["FILE_ENCRYPTION_KEY"])


# ---------------------------------------------------------------
# 2. Hooks: code that runs around every request
# ---------------------------------------------------------------

def _register_hooks(app: Flask) -> None:
    """Register before/after-request functions, template helpers and filters."""

    # Before each request: load the logged-in user, then check CSRF.
    app.before_request(auth.load_logged_in_user)
    app.before_request(csrf.verify_csrf_token)

    # Makes {{ csrf_token() }} available inside every template.
    @app.context_processor
    def inject_csrf_token() -> dict:
        """Expose the CSRF token generator to templates."""
        return {"csrf_token": csrf.get_csrf_token}

    # Makes {{ file.size_bytes | filesize }} work inside templates.
    app.add_template_filter(format_file_size, "filesize")

    @app.after_request
    def add_security_headers(response):
        """Attach security headers to every response (see Concept 6)."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'"
        )
        # Private pages must not be cached; static CSS can be.
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response


# ---------------------------------------------------------------
# 3. Routes
# ---------------------------------------------------------------

def _register_routes(app: Flask) -> None:
    """Define every URL the app responds to."""

    # Read settings once; the route functions below use these values.
    db_path = app.config["DATABASE_PATH"]
    storage_folder = Path(app.config["STORAGE_FOLDER"])
    file_key = app.config["FILE_KEY_BYTES"]
    max_upload_mb = app.config["MAX_CONTENT_LENGTH"] // BYTES_PER_MB

    @app.route("/")
    def index():
        """Home: send users where they belong."""
        if g.user:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        """GET: show the sign-up form. POST: create the account."""
        if g.user:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if password != confirm_password:
                flash("Passwords do not match.", "error")
                return render_template("register.html", username=username)

            try:
                user_id = auth.register_user(db_path, username, password)
            except (auth.ValidationError, database.UsernameTakenError) as error:
                flash(str(error), "error")
                return render_template("register.html", username=username)

            logger.info("New user registered: user_id=%s", user_id)
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html", username="")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """GET: show the login form. POST: check credentials and start a session."""
        if g.user:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")

            user = auth.authenticate_user(db_path, username, password)
            if user is None:
                # %r escapes newlines, preventing log injection.
                logger.warning("Failed login for username=%r from ip=%s",
                               username, request.remote_addr)
                flash("Invalid username or password.", "error")
                return render_template("login.html", username=username)

            auth.log_in(user)
            logger.info("User logged in: user_id=%s", user["id"])
            return redirect(url_for("dashboard"))

        return render_template("login.html", username="")

    @app.route("/logout", methods=["POST"])
    def logout():
        """End the session. POST-only, so other sites can't log you out."""
        if g.user:
            logger.info("User logged out: user_id=%s", g.user["id"])
        auth.log_out()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @auth.login_required
    def dashboard():
        """Show the logged-in user's files and the upload form."""
        files = database.list_files_for_user(db_path, g.user["id"])
        return render_template("dashboard.html", files=files,
                               max_upload_mb=max_upload_mb)

    @app.route("/upload", methods=["POST"])
    @auth.login_required
    def upload():
        """Hash, encrypt and store an uploaded file, then record its metadata."""
        uploaded_file = request.files.get("file")
        if uploaded_file is None or uploaded_file.filename == "":
            flash("Please choose a file to upload.", "error")
            return redirect(url_for("dashboard"))

        original_name = clean_original_filename(uploaded_file.filename)
        file_bytes = uploaded_file.read()

        # Hash the ORIGINAL, then encrypt. Plaintext never touches the disk.
        file_hash = crypto_utils.sha256_hex(file_bytes)
        encrypted_bytes = crypto_utils.encrypt_data(file_bytes, file_key)

        # Random, unguessable disk name (uuid4 = 122 random bits).
        stored_name = f"{uuid.uuid4().hex}.enc"
        stored_path = storage_folder / stored_name
        stored_path.write_bytes(encrypted_bytes)

        try:
            file_id = database.add_file(
                db_path,
                owner_id=g.user["id"],
                original_name=original_name,
                stored_name=stored_name,
                size_bytes=len(file_bytes),
                sha256=file_hash,
            )
        except Exception:
            # Don't leave an orphaned encrypted file if the database write fails.
            stored_path.unlink(missing_ok=True)
            logger.exception("Upload metadata save failed; removed %s", stored_name)
            raise

        logger.info("Upload: user_id=%s file_id=%s size=%s",
                    g.user["id"], file_id, len(file_bytes))
        flash(f"'{original_name}' uploaded and encrypted.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/download/<int:file_id>")
    @auth.login_required
    def download(file_id: int):
        """Check ownership, decrypt, verify integrity twice, then send the file."""
        file_record = database.get_file_for_user(db_path, file_id, g.user["id"])
        if file_record is None:
            abort(404)  # Not yours or doesn't exist; we don't say which.

        stored_path = storage_folder / file_record["stored_name"]
        if not stored_path.is_file():
            logger.error("Encrypted file missing on disk: file_id=%s", file_id)
            flash("This file could not be found in storage.", "error")
            return redirect(url_for("dashboard"))

        integrity_message = ("Integrity check failed: this file appears to have been "
                             "tampered with or corrupted. Download blocked.")

        # Check 1: AES-GCM authentication tag.
        try:
            plaintext = crypto_utils.decrypt_data(stored_path.read_bytes(), file_key)
        except crypto_utils.DecryptionError:
            logger.warning("INTEGRITY FAILURE (GCM tag): file_id=%s user_id=%s",
                           file_id, g.user["id"])
            flash(integrity_message, "error")
            return redirect(url_for("dashboard"))

        # Check 2: SHA-256 of the original (catches swapped .enc files).
        if crypto_utils.sha256_hex(plaintext) != file_record["sha256"]:
            logger.warning("INTEGRITY FAILURE (SHA-256 mismatch): file_id=%s user_id=%s",
                           file_id, g.user["id"])
            flash(integrity_message, "error")
            return redirect(url_for("dashboard"))

        logger.info("Download: user_id=%s file_id=%s", g.user["id"], file_id)

        # octet-stream + attachment = always download, never render.
        # This prevents uploaded HTML/JS from running on our site (stored XSS).
        return send_file(
            io.BytesIO(plaintext),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=file_record["original_name"],
        )

    @app.route("/delete/<int:file_id>", methods=["POST"])
    @auth.login_required
    def delete(file_id: int):
        """Delete a file's record and its encrypted data."""
        file_record = database.get_file_for_user(db_path, file_id, g.user["id"])
        if file_record is None:
            abort(404)

        # Database first: if disk deletion then fails, we're left with an
        # unreachable (and still encrypted) file, which is harmless. The reverse
        # order could leave a record pointing at a missing file.
        database.delete_file_for_user(db_path, file_id, g.user["id"])
        (storage_folder / file_record["stored_name"]).unlink(missing_ok=True)

        logger.info("Delete: user_id=%s file_id=%s", g.user["id"], file_id)
        flash(f"'{file_record['original_name']}' deleted.", "success")
        return redirect(url_for("dashboard"))


# ---------------------------------------------------------------
# 4. Error handlers
# ---------------------------------------------------------------

def _register_error_handlers(app: Flask) -> None:
    """Show friendly error pages without leaking internal details."""

    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(error):
        """413: the upload exceeded MAX_CONTENT_LENGTH."""
        limit_mb = app.config["MAX_CONTENT_LENGTH"] // BYTES_PER_MB
        flash(f"File is too large. The maximum size is {limit_mb} MB.", "error")
        return redirect(url_for("dashboard"))

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        """Any other HTTP error (400, 404, 405...): show the error page."""
        return render_template(
            "error.html",
            error_code=error.code,
            error_title=error.name,
            error_message=error.description,
        ), error.code

    @app.errorhandler(500)
    def handle_internal_error(error):
        """
        500: a bug. Flask has already logged the full traceback.
        The user sees a generic message: stack traces reveal file paths,
        library versions and code, which help attackers.
        """
        return render_template(
            "error.html",
            error_code=500,
            error_title="Internal Server Error",
            error_message="Something went wrong on our side. Please try again.",
        ), 500


# ---------------------------------------------------------------
# Run with:  python app.py
# ---------------------------------------------------------------

if __name__ == "__main__":
    application = create_app()
    # NEVER enable debug mode in production: the debugger lets anyone who
    # reaches an error page run Python code on your server.
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    application.run(host="127.0.0.1", port=5000, debug=debug_mode)