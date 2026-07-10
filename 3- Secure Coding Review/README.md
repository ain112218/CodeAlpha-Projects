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
| `vulnerable_app.py` | A sample banking app with **10 intentional security flaws** to audit |
| `secure_app.py` | The same app with **all vulnerabilities fixed** |
| `review_report.md` | The full **secure coding review report** — findings, risk ratings, and fixes |
| `requirements.txt` | Python dependencies (install with `pip`) |
| `README.md` | This file — a step-by-step guide for beginners |

## How to Run a Secure Code Review — Step by Step

> No prior security experience? No problem. Follow the steps below.

### Step 1: Install Python

Download and install Python 3.8+ from [python.org](https://www.python.org/downloads/).  
During setup, check **"Add Python to PATH"**.

Verify it works:
```
python --version
```

### Step 2: Install Dependencies

Open a terminal (Command Prompt or PowerShell) in this folder and run:

```
pip install -r requirements.txt
```

This installs **Bandit** — a static analysis tool that automatically finds security issues in Python code.

### Step 3: Run a Static Analysis (Automated Scan)

Run Bandit on the vulnerable app to see what it catches automatically:

```
bandit -r vulnerable_app.py
```

Bandit will scan the code and print a report of security issues it detected.  
This is called **Static Application Security Testing (SAST)**.

### Step 4: Manual Code Review

Open `vulnerable_app.py` in any text editor (Notepad, VS Code, etc.).  
Read through the code and look for anything suspicious. Ask yourself:

- Is user input trusted without validation?
- Are passwords or secrets visible in plain text?
- Could an attacker manipulate a file path or command?
- Are error messages leaking sensitive information?

Compare what you find with the Bandit results — some issues are **only visible to a human reviewer**.

### Step 5: Review the Report

Open `review_report.md` to see the **complete findings document**.  
It lists every vulnerability found, explains why it's dangerous, and shows how to fix it.

### Step 6: Compare with the Secure Version

Open `secure_app.py` to see how all the issues were fixed.  
Each fix is commented so you can understand **why** the change was made.

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
