@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo USB-VAULT
echo ============================================================
echo.
echo Website example: gmail.com
echo Master password typing is hidden.
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
  echo Python is not installed or not in PATH.
  echo Install Python 3.10+ and try again.
  pause
  exit /b 1
)

echo Checking Python dependency...
python -m pip install -q -r ..\requirements.txt
if %errorlevel% neq 0 (
  echo Failed to install requirements.
  echo Try: python -m pip install -r ..\requirements.txt
  pause
  exit /b 1
)

echo.
echo USB-Vault ready. Starting interactive password generator...
python derive.py

echo.
echo Done.
pause
