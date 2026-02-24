@echo off
title LiKinho Server
echo Starting LiKinho KeyAuth Server...
cd /d "%~dp0"

WHERE node >nul 2>nul
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js not found in PATH!
    echo Please install Node.js from https://nodejs.org/
    echo or add it to your PATH.
    pause
    exit
)

node server.js
pause
