@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

if not exist "%~dp0clipferry.exe" (
    echo [ERROR] clipferry.exe is missing from this folder.
    pause
    exit /b 2
)

if not exist "%~dp0stage4-dual-pc.ps1" (
    echo [ERROR] stage4-dual-pc.ps1 is missing from this folder.
    pause
    exit /b 2
)

if not exist "%~dp0stage4-dual-pc-menu.ps1" (
    echo [ERROR] stage4-dual-pc-menu.ps1 is missing from this folder.
    pause
    exit /b 2
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0stage4-dual-pc-menu.ps1" %*
set "clipferry_exit=%ERRORLEVEL%"

if not "%clipferry_exit%"=="0" (
    echo.
    echo [ERROR] Interactive test wizard exited with code %clipferry_exit%.
    pause
)

exit /b %clipferry_exit%
