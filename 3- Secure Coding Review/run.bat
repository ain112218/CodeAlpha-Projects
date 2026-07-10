@echo off
cd /d "%~dp0"
title Secure Coding Review

REM === CHECK VIRTUAL ENVIRONMENT ===
if not exist venv\Scripts\activate.bat (
    echo [ERROR] Virtual environment not found.
    echo Please run setup.bat first to install dependencies.
    pause
    exit /b 1
)

call venv\Scripts\activate.bat

:menu
cls
echo ============================================
echo         Secure Coding Review
echo ============================================
echo.
echo  1. Run static analysis on vulnerable_app.py
echo  2. Run static analysis on secure_app.py
echo  3. View review report (review_report.md)
echo  4. View vulnerable_app.py source code
echo  5. View secure_app.py source code
echo  6. Exit
echo.
echo ============================================
set /p choice="Select an option (1-6): "

if "%choice%"=="1" goto scan_vulnerable
if "%choice%"=="2" goto scan_secure
if "%choice%"=="3" goto view_report
if "%choice%"=="4" goto view_vulnerable
if "%choice%"=="5" goto view_secure
if "%choice%"=="6" goto end

echo Invalid option. Please try again.
timeout /t 2 /nobreak >nul
goto menu

:scan_vulnerable
cls
echo ============================================
echo  Bandit Scan: vulnerable_app.py
echo ============================================
echo.
python -m bandit -r vulnerable_app.py
echo.
echo Press any key to return to menu...
pause >nul
goto menu

:scan_secure
cls
echo ============================================
echo  Bandit Scan: secure_app.py
echo ============================================
echo.
python -m bandit -r secure_app.py
echo.
echo Press any key to return to menu...
pause >nul
goto menu

:view_report
cls
echo ============================================
echo  Opening review_report.md
echo ============================================
echo.
if exist review_report.md (
    start notepad.exe review_report.md
) else (
    echo [ERROR] review_report.md not found.
)
echo Press any key to return to menu...
pause >nul
goto menu

:view_vulnerable
cls
echo ============================================
echo  Opening vulnerable_app.py
echo ============================================
echo.
if exist vulnerable_app.py (
    start notepad.exe vulnerable_app.py
) else (
    echo [ERROR] vulnerable_app.py not found.
)
echo Press any key to return to menu...
pause >nul
goto menu

:view_secure
cls
echo ============================================
echo  Opening secure_app.py
echo ============================================
echo.
if exist secure_app.py (
    start notepad.exe secure_app.py
) else (
    echo [ERROR] secure_app.py not found.
)
echo Press any key to return to menu...
pause >nul
goto menu

:end
exit /b 0
