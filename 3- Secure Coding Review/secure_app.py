"""
Secure Banking Application (Fixed Version)
============================================
This is the remediated version of vulnerable_app.py with all 10 security
vulnerabilities fixed. Each fix is documented with comments.
"""

import sqlite3
import os
import hashlib
import hmac
import secrets
import html as html_module
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ============================================================
# FIX 1: Remove Hardcoded Database Password
# ============================================================
DB_PATH = os.environ.get("BANK_DB_PATH", "bank.db")

def get_db_connection():
    return sqlite3.connect(DB_PATH)

# ============================================================
# FIX 2: SQL Injection — Use Parameterized Queries
# ============================================================
def get_user_account(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM accounts WHERE username = ?"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    conn.close()
    return result

# ============================================================
# FIX 3: Command Injection — Use Safe API, Avoid shell=True
# ============================================================
import subprocess
import ipaddress

def ping_server(ip_address):
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return "Invalid IP address."

    result = subprocess.run(
        ["ping", "-n", "1", ip_address],
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout

# ============================================================
# FIX 4: Path Traversal — Validate and Sanitize File Paths
# ============================================================
def read_user_file(filename):
    base_dir = os.path.abspath("data")
    requested_path = os.path.abspath(os.path.join(base_dir, filename))

    if not requested_path.startswith(base_dir):
        return "Access denied."

    if filename.startswith("/") or filename.startswith("\\"):
        return "Access denied."

    try:
        with open(requested_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found."
    except IOError:
        return "Error reading file."

# ============================================================
# FIX 5: Cross-Site Scripting (XSS) — Escape HTML Output
# ============================================================
def display_profile(username):
    safe_username = html_module.escape(username)
    html = "<html><body>"
    html += "<h1>Welcome, " + safe_username + "</h1>"
    html += "</body></html>"
    return html

# ============================================================
# FIX 6: Weak Password Storage — Hash Passwords with Salt
# ============================================================
users_db = {}

def hash_password(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return salt + key

def verify_password(stored, password):
    salt = stored[:32]
    key = stored[32:]
    new_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return hmac.compare_digest(key, new_key)

def register_user(username, password):
    users_db[username] = hash_password(password)

def login_user(username, password):
    if username in users_db:
        return verify_password(users_db[username], password)
    return False

# ============================================================
# FIX 7: Insecure Use of eval() — Use Safe Alternatives
# ============================================================
import ast
import operator

_allowed_ops = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}

def _safe_eval(node):
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        val = _safe_eval(node.operand)
        return +val if isinstance(node.op, ast.UAdd) else -val
    if isinstance(node, ast.BinOp) and type(node.op) in _allowed_ops:
        return _allowed_ops[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    raise ValueError("Unsupported operation")

def calculate(expression):
    try:
        tree = ast.parse(expression, mode="eval")
        result = _safe_eval(tree)
        return result
    except (ValueError, SyntaxError, TypeError):
        return "Invalid expression."

# ============================================================
# FIX 8: Predictable Session Tokens — Use Cryptographically
#         Random Tokens
# ============================================================
sessions = {}

def create_session(username):
    token = secrets.token_hex(32)
    sessions[token] = username
    return token

# ============================================================
# FIX 9: Information Disclosure — Log Errors, Don't Expose
#         Stack Traces to Users
# ============================================================
def process_payment(amount, divisor):
    if divisor == 0:
        logging.warning("Attempted division by zero")
        print("Error: Cannot divide by zero.")
        return
    try:
        result = amount / divisor
        print("Payment processed: " + str(result))
    except Exception as e:
        logging.error("Payment processing error: %s", str(e))
        print("An unexpected error occurred. Please try again later.")

# ============================================================
# FIX 10: Dangerous Function — Use input() Correctly (Python 3)
#         Note: In Python 3, input() is safe (it doesn't eval).
#         But we still add validation.
# ============================================================
def get_user_input(prompt="Enter your choice: "):
    user_input = input(prompt).strip()
    valid_choices = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]
    if user_input not in valid_choices:
        return "1"
    return user_input

# ============================================================
# Main Menu (Secure)
# ============================================================
def main():
    print("Welcome to SecureBank (Secure Version)")
    print("1. Login")
    print("2. View Account")
    print("3. Ping Server")
    print("4. Read Profile File")
    print("5. Calculate")
    print("6. Process Payment")
    print("7. Register User")
    print("8. Login User")
    print("9. Exit")

    choice = get_user_input()

    if choice == "1":
        user = input("Username: ")
        result = get_user_account(user)
        print("Account: " + str(result))

    elif choice == "2":
        user = input("Username for profile: ")
        html = display_profile(user)
        print(html)

    elif choice == "3":
        ip = input("IP address to ping: ")
        print(ping_server(ip))

    elif choice == "4":
        file = input("Filename to read: ")
        print(read_user_file(file))

    elif choice == "5":
        expr = input("Expression: ")
        print("Result: " + str(calculate(expr)))

    elif choice == "6":
        amt = float(input("Amount: "))
        div = float(input("Divide by: "))
        process_payment(amt, div)

    elif choice == "7":
        u = input("New username: ")
        p = input("New password: ")
        register_user(u, p)
        print("User registered with hashed password!")

    elif choice == "8":
        u = input("Username: ")
        p = input("Password: ")
        if login_user(u, p):
            token = create_session(u)
            print("Login successful! Session: " + token)
        else:
            print("Login failed!")

    elif choice == "9":
        print("Goodbye.")

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
