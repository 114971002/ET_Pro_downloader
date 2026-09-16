@echo off
chcp 65001 >nul
echo [*] 設定 ET Pro 每日自動下載排程 (Windows Task Scheduler)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_scheduled_task.ps1"
pause
