@echo off
REM MANS Bank - Windows Startup Script
REM Note: Set GROQ_API_KEY environment variable for AI threat analysis features

echo Starting MANS Bank Server...

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed!
    echo Please install Python 3.11 or higher from python.org
    pause
    exit /b 1
)

REM Install dependencies if needed
pip show flask >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install flask flask-cors werkzeug requests
)

echo.
echo Server starting at: http://localhost:5000
echo Login: admin@mans.bank / admin123
if not defined GROQ_API_KEY echo Note: Set GROQ_API_KEY env variable for AI features
echo.

REM Start the server
python server.py
