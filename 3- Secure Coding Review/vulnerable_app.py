"""
Vulnerable Banking Application
===============================
WARNING: This code contains intentional security vulnerabilities for educational
purposes. DO NOT use this code in production.

Vulnerabilities present:
  1. Hardcoded Database Password
  2. SQL Injection
  3. Command Injection
  4. Path Traversal
  5. Cross-Site Scripting (XSS)
  6. Weak Password Storage (Plain Text)
  7. Insecure Use of eval()
  8. Predictable Session Tokens
  9. Information Disclosure via Stack Traces
  10. Use of Dangerous Function (input() in Python 2 style)
"""

import sqlite3
import os
import hashlib
import subprocess
import cgi

# ============================================================
# VULNERABILITY 1: Hardcoded Database Password
# ============================================================
DB_PASSWORD = "SuperSecret123!"  # Hardcoded credential

def get_db_connection():
    return sqlite3.connect("bank.db")

# ============================================================
# VULNERABILITY 2: SQL Injection
# ============================================================
def get_user_account(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM accounts WHERE username = '" + username + "'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

# ============================================================
# VULNERABILITY 3: Command Injection
# ============================================================
def ping_server(ip_address):
    result = subprocess.check_output("ping -n 1 " + ip_address, shell=True)
    return result.decode()

# ============================================================
# VULNERABILITY 4: Path Traversal
# ============================================================
def read_user_file(filename):
    with open("data/" + filename, "r") as f:
        return f.read()

# ============================================================
# VULNERABILITY 5: Cross-Site Scripting (XSS)
# ============================================================
def display_profile(username):
    html = "<html><body>"
    html += "<h1>Welcome, " + username + "</h1>"
    html += "</body></html>"
    return html

# ============================================================
# VULNERABILITY 6: Weak Password Storage (Plain Text)
# ============================================================
users_db = {}

def register_user(username, password):
    users_db[username] = password  # Stored in plain text

def login_user(username, password):
    if username in users_db and users_db[username] == password:
        return True
    return False

# ============================================================
# VULNERABILITY 7: Insecure Use of eval()
# ============================================================
def calculate(expression):
    return eval(expression)

# ============================================================
# VULNERABILITY 8: Predictable Session Tokens
# ============================================================
session_counter = 0

def create_session(username):
    global session_counter
    session_counter += 1
    token = str(session_counter) + "_" + username
    return token

# ============================================================
# VULNERABILITY 9: Information Disclosure via Stack Traces
# ============================================================
def unsafe_division(a, b):
    return a / b

def process_payment(amount, divisor):
    try:
        result = unsafe_division(amount, divisor)
        print("Payment processed: " + str(result))
    except Exception as e:
        print("Error: " + str(e))
        import traceback
        traceback.print_exc()

# ============================================================
# VULNERABILITY 10: Use of Dangerous Function (input)
# ============================================================
def get_user_input():
    user_input = input("Enter your choice: ")
    return user_input

# ============================================================
# Main Menu
# ============================================================
def main():
    print("Welcome to SecureBank")
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
        print("User registered!")

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
