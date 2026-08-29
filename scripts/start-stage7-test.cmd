@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

if not exist "%~dp0clipferry.exe" (
    echo [ERROR] 当前文件夹缺少 clipferry.exe。
    pause
    exit /b 2
)

if not exist "%~dp0stage5-dual-pc-menu.ps1" (
    echo [ERROR] 当前文件夹缺少 stage5-dual-pc-menu.ps1。
    pause
    exit /b 2
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0stage5-dual-pc-menu.ps1" -Stage7 %*
set "clipferry_exit=%ERRORLEVEL%"

if not "%clipferry_exit%"=="0" (
    echo.
    echo [ERROR] 阶段 7 交互验收程序退出码：%clipferry_exit%。
    pause
)

exit /b %clipferry_exit%
