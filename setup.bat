@echo off
REM ============================================
REM Threat Detection Framework Setup Script
REM Windows Version
REM ============================================

echo.
echo Threat Detection Framework Setup
echo ====================================

REM Check Python version
echo Checking Python version...
python --version
if %errorlevel% neq 0 (
    echo Error: Python not installed or not in PATH
    pause
    exit /b 1
)

REM Create virtual environment
echo Creating virtual environment...
python -m venv venv
if %errorlevel% neq 0 (
    echo Error: Failed to create virtual environment
    pause
    exit /b 1
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
python -m pip install --upgrade pip
pip install -r backend\requirements.txt
if %errorlevel% neq 0 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)

REM Create directories
echo Creating directories...
mkdir logs 2>nul
mkdir data 2>nul
mkdir models 2>nul

REM Copy environment file
if not exist .env (
    echo Creating .env file from template...
    copy .env.example .env
    echo Warning: Please edit .env with your configuration
)

REM Initialize database
echo Initializing database...
python -c "^
from backend.app import app, db^
from backend.database.models import Threat, Alert, SystemMetrics, NetworkFlow, IncidentResponse^
^
with app.app_context():^
    db.create_all()^
    print('Database tables created')^
"

if %errorlevel% neq 0 (
    echo Error: Failed to initialize database
    pause
    exit /b 1
)

echo.
echo Setup complete!
echo.
echo Next steps:
echo 1. Edit .env file with your configuration
echo 2. Run: python backend\app.py
echo 3. Access dashboard at: http://localhost:5000
echo.
echo For production deployment, see README.md
echo.
pause
