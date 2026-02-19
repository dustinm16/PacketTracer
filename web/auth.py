"""User authentication for the web UI.

Uses werkzeug's PBKDF2 password hashing and Flask session-based auth.
User accounts are stored in the PacketTracer SQLite database.
"""

import sqlite3
import time
import os
import secrets
from functools import wraps
from typing import Optional

from flask import (
    Blueprint, request, redirect, url_for, render_template,
    session, flash, current_app, g,
)
from werkzeug.security import generate_password_hash, check_password_hash


auth_bp = Blueprint("auth", __name__)

# Schema for the users table
USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS web_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at REAL NOT NULL,
    last_login REAL
);
"""


def init_users_table(db_path: str) -> None:
    """Create the web_users table if it doesn't exist."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(USERS_TABLE_SQL)
        conn.commit()


def get_user_db() -> sqlite3.Connection:
    """Get a database connection for user operations."""
    if "user_db" not in g:
        g.user_db = sqlite3.connect(current_app.config["DB_PATH"])
        g.user_db.row_factory = sqlite3.Row
    return g.user_db


def close_user_db(e=None):
    """Close the user database connection."""
    db = g.pop("user_db", None)
    if db is not None:
        db.close()


def user_count() -> int:
    """Count total users."""
    db = get_user_db()
    row = db.execute("SELECT COUNT(*) FROM web_users").fetchone()
    return row[0]


def create_user(username: str, password: str, role: str = "viewer") -> bool:
    """Create a new user. Returns True on success, False if username taken."""
    db = get_user_db()
    try:
        db.execute(
            "INSERT INTO web_users (username, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), role, time.time()),
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def verify_user(username: str, password: str) -> Optional[dict]:
    """Verify credentials. Returns user dict or None."""
    db = get_user_db()
    row = db.execute(
        "SELECT * FROM web_users WHERE username = ?", (username,)
    ).fetchone()
    if row and check_password_hash(row["password_hash"], password):
        db.execute(
            "UPDATE web_users SET last_login = ? WHERE id = ?",
            (time.time(), row["id"]),
        )
        db.commit()
        return dict(row)
    return None


def get_current_user() -> Optional[dict]:
    """Get the currently logged-in user from session."""
    user_id = session.get("user_id")
    if user_id is None:
        return None
    db = get_user_db()
    row = db.execute(
        "SELECT * FROM web_users WHERE id = ?", (user_id,)
    ).fetchone()
    return dict(row) if row else None


def login_required(f):
    """Decorator that requires authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator that requires admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login", next=request.url))
        user = get_current_user()
        if not user or user["role"] != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("main.dashboard"))
        return f(*args, **kwargs)
    return decorated


# --- Routes ---

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Login page."""
    # If no users exist, redirect to setup
    db = get_user_db()
    count = db.execute("SELECT COUNT(*) FROM web_users").fetchone()[0]
    if count == 0:
        return redirect(url_for("auth.setup"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = verify_user(username, password)
        if user:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            next_url = request.args.get("next", url_for("main.dashboard"))
            return redirect(next_url)
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@auth_bp.route("/setup", methods=["GET", "POST"])
def setup():
    """Initial admin account setup. Only accessible when no users exist."""
    db = get_user_db()
    count = db.execute("SELECT COUNT(*) FROM web_users").fetchone()[0]
    if count > 0:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            if create_user(username, password, role="admin"):
                user = verify_user(username, password)
                if user:
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                return redirect(url_for("main.dashboard"))
            flash("Could not create account.", "error")

    return render_template("setup.html")


@auth_bp.route("/logout")
def logout():
    """Log out the current user."""
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/users")
@admin_required
def manage_users():
    """User management (admin only)."""
    db = get_user_db()
    users = db.execute(
        "SELECT id, username, role, created_at, last_login FROM web_users ORDER BY created_at"
    ).fetchall()
    return render_template("users.html", users=[dict(u) for u in users])


@auth_bp.route("/users/add", methods=["POST"])
@admin_required
def add_user():
    """Add a new user (admin only)."""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")
    if role not in ("admin", "viewer"):
        role = "viewer"

    if len(username) < 3 or len(password) < 8:
        flash("Username (3+ chars) and password (8+ chars) required.", "error")
    elif create_user(username, password, role=role):
        flash(f"User '{username}' created.", "success")
    else:
        flash(f"Username '{username}' already exists.", "error")

    return redirect(url_for("auth.manage_users"))


@auth_bp.route("/users/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id: int):
    """Delete a user (admin only, cannot delete self)."""
    if user_id == session.get("user_id"):
        flash("Cannot delete your own account.", "error")
    else:
        db = get_user_db()
        db.execute("DELETE FROM web_users WHERE id = ?", (user_id,))
        db.commit()
        flash("User deleted.", "success")
    return redirect(url_for("auth.manage_users"))
