"""Authentication helpers: login, logout, password hashing."""

from flask import session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from database import models


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(hash: str, password: str) -> bool:
    return check_password_hash(hash, password)


def login_user(user_id: int):
    session["user_id"] = user_id


def logout_user():
    session.pop("user_id", None)


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = models.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    row = cur.fetchone()
    conn.close()
    return row


def require_login(func):
    """Decorator to protect routes requiring authentication."""

    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    return wrapper
