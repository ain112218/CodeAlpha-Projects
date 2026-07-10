# Secure Coding Review

A beginner-friendly guide to performing a **secure code review** — finding and fixing security vulnerabilities in source code. This project includes a deliberately vulnerable sample application, a static analysis walkthrough, and a complete review report with remediation steps.

## What is a Secure Coding Review?

A secure code review is a manual or automated inspection of source code to find security weaknesses before they reach production. It helps catch:

- SQL Injection
- Cross-Site Scripting (XSS)
- Hardcoded secrets and credentials
- Command Injection
- Path Traversal
- Insecure data handling
- And many other vulnerabilities

## What's Inside

| File | Purpose |
|------|---------|
| `setup.bat` | One-time setup — checks Python, creates virtual environment, installs Bandit |
| `run.bat` | Interactive menu — run scans, view reports, browse source code |
| `vulnerable_app.py` | A sample banking app with **10 intentional security flaws** to audit |
| `secure_app.py` | The same app with **all vulnerabilities fixed** |
| `review_report.md` | The full **secure coding review report** — findings, risk ratings, and fixes |
| `requirements.txt` | Python dependencies (Bandit) |
| `README.md` | This file |

## How to Use

### 1. Run Setup (one time only)

Double-click **`setup.bat`**.

This will:
- Verify Python is installed
- Create an isolated virtual environment (`venv/`)
- Install Bandit (static analysis tool)

You only need to do this once.

### 2. Run the Review

Double-click **`run.bat`**.

This opens an interactive menu where you can:

| Option | What It Does |
|--------|-------------|
| **1** | Run Bandit on `vulnerable_app.py` — see what automated tools catch |
| **2** | Run Bandit on `secure_app.py` — confirm no issues remain |
| **3** | Open the full review report (`review_report.md` in Notepad) |
| **4** | Open the vulnerable source code for manual inspection |
| **5** | Open the fixed source code to compare fixes |

### 3. Manual Code Review

Open `vulnerable_app.py` and look for:

- Is user input trusted without validation?
- Are passwords or secrets visible in plain text?
- Could an attacker manipulate a file path or command?
- Are error messages leaking sensitive information?

Compare what you find with the Bandit results — some issues are **only visible to a human reviewer**.

## Vulnerability Summary

Here are the 10 vulnerabilities planted in `vulnerable_app.py`:

| # | Vulnerability | Risk Level |
|---|--------------|------------|
| 1 | Hardcoded Database Password | **Critical** |
| 2 | SQL Injection | **Critical** |
| 3 | Command Injection | **Critical** |
| 4 | Path Traversal | **High** |
| 5 | Cross-Site Scripting (XSS) | **High** |
| 6 | Weak Password Storage (Plain Text) | **High** |
| 7 | Insecure Use of `eval()` | **Critical** |
| 8 | Predictable Session Tokens | **Medium** |
| 9 | Information Disclosure via Stack Traces | **Medium** |
| 10 | Use of Dangerous Function (`input()` in Python 2 style) | **Low** |

## Static Analysis vs. Manual Review

| Method | What It Does | Catches |
|--------|-------------|---------|
| **Static Analyzer (Bandit)** | Automatically scans code for known dangerous patterns | Hardcoded passwords, SQL injection, `eval()`, command injection |
| **Manual Review** | A human reads the code line by line | Logic flaws, business logic issues, design problems, weak crypto |

> The most thorough reviews use **both** methods.

## Author

**Ain Azeem** — [azeem@warsawuni.edu.pl](mailto:azeem@warsawuni.edu.pl)

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
