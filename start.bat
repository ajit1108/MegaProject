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
echo  [*] Starting FastAPI server accessible locally and on network:
echo  [*] Local URL:    http://127.0.0.1:8000
echo  [*] Network URL:  http://0.0.0.0:8000 (Use your IP, e.g. http://192.168.1.11:8000)
echo  [*] Swagger Docs: http://127.0.0.1:8000/docs
echo  [*] Press Ctrl+C to stop
echo.

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

pause
