"""
Sample authentication service with intentional security vulnerabilities for testing.
"""
import hashlib
import sqlite3

# VULNERABILITY 1: Hardcoded sensitive secrets / tokens (Bandit B105)
JWT_SECRET_KEY = "super_secret_production_key_do_not_leak_987654321"
DATABASE_URL = "postgres://admin:Password123!@production-db.internal:5432/app"


def hash_user_password(password: str) -> str:
    """
    VULNERABILITY 2: Insecure MD5 hashing algorithm (Bandit B324 / B303).
    MD5 is cryptographically broken and vulnerable to collision attacks.
    """
    hasher = hashlib.md5()
    hasher.update(password.encode("utf-8"))
    return hasher.hexdigest()


def authenticate_user(username: str, password_input: str):
    """
    VULNERABILITY 3: SQL Injection via f-string query formatting (Bandit B608).
    Attacker can supply: admin' -- to bypass authentication.
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Raw string interpolation directly into SQL query
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password_hash = '{hash_user_password(password_input)}'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()
    return user


def execute_admin_eval(code_snippet: str):
    """
    VULNERABILITY 4: Insecure eval() call allowing arbitrary code execution (Bandit B307).
    """
    return eval(code_snippet)
