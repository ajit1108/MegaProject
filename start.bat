@echo off
REM ============================================================
REM  start.bat — One-click launcher for the Sensitive Data
REM              Detection System on Windows
REM ============================================================

title SensitiveDataDetector Server

echo.
echo  ╔════════════════════════════════════════════════════╗
echo  ║   AI-Based Sensitive Data Detection System v1.0   ║
echo  ╚════════════════════════════════════════════════════╝
echo.

REM Check .env exists
if not exist ".env" (
    echo  [!] .env file not found.
    echo  [!] Copy .env.example to .env and configure your settings:
    echo       copy .env.example .env
    pause
    exit /b 1
)

REM Check venv exists
if not exist "venv\Scripts\activate.bat" (
    echo  [!] Virtual environment not found. Creating...
    python -m venv venv
    if errorlevel 1 (
        echo  [ERROR] Failed to create venv. Is Python 3.11+ installed?
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created.
)

REM Activate venv
call venv\Scripts\activate.bat

REM Install/upgrade dependencies quietly
echo  [*] Checking dependencies...
pip install -r requirements.txt -q
echo  [OK] Dependencies ready.

REM Ensure upload directory exists
if not exist "uploads" mkdir uploads

REM Start the server
echo.
echo  [*] Starting FastAPI server on http://127.0.0.1:8000
echo  [*] API Documentation:  http://127.0.0.1:8000/docs
echo  [*] Press Ctrl+C to stop
echo.

uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

pause
