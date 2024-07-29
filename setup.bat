@echo off

echo Setting up LockFly...

:: Check if Python 3 is installed
where python3 >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Python 3 could not be found. Please install Python 3 to continue.
    exit /b 1
)

:: Create and activate virtual environment
python3 -m venv venv
call venv\Scripts\activate

:: Install required dependencies
pip install -r requirements.txt

:: Run the application
python lockfly.py

