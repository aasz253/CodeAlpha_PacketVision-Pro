@echo off
REM PacketVision Pro - Quick Launch Script for Windows
REM Right-click this file and "Run as Administrator"

cd /d "%~dp0"

if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

echo Starting PacketVision Pro...
echo (Run this as Administrator for packet capture)
python main.py %*
pause
