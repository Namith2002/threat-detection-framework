@echo off
REM Batch file to run the Threat Detection Framework

echo Starting Cyber Threat Detection Framework...
echo Access the dashboard at http://localhost:5000

cd /d "%~dp0"
python run.py

pause
