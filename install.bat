@echo off
REM PacketVision Pro - One-Click Installer for Windows
REM Run this as Administrator

echo.
echo   ========================================
echo     PacketVision Pro - Windows Installer
echo   ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo Download from: https://www.python.org/downloads/
    echo During install, check "Add Python to PATH"
    pause
    exit /b 1
)

echo [OK] Python found

REM Check pip
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip not found. Reinstall Python with "Add pip" checked.
    pause
    exit /b 1
)

REM Check Npcap
echo [...] Checking for Npcap...
sc query npcap >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Npcap not found! Packet capture requires Npcap.
    echo Download from: https://npcap.com/#download
    echo Check "Install in WinPcap API-compatible mode"
    echo.
    set /p INSTALL_NPCAP="Open Npcap download page? (y/n): "
    if /i "%INSTALL_NPCAP%"=="y" start https://npcap.com/#download
)

REM Create virtual environment
echo [...] Setting up virtual environment...
python -m venv venv
call venv\Scripts\activate.bat

REM Install packages
echo [...] Installing Python packages...
python -m pip install --upgrade pip -q
python -m pip install -r requirements.txt -q

echo.
echo   ========================================
echo   Installation complete!
echo   ========================================
echo.
echo   To run:
echo     venv\Scripts\activate
echo     python main.py
echo.
echo   Or double-click: run.bat
echo.
echo   NOTE: Run terminal as Administrator for packet capture.
echo.
pause
