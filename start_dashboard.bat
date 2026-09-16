@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ==================================================================
echo   ET Pro 自動下載器 - 網頁管理控制台啟動程式
echo ==================================================================
echo.
echo [*] 正在檢查 Python 環境...

where python.exe >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] 系統 PATH 中找不到 python.exe，嘗試搜尋常見安裝路徑...
    if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
        set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
        set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    ) else (
        echo [X] 錯誤: 找不到 Python 執行檔，請確認已安裝 Python 並加入 PATH。
        pause
        exit /b 1
    )
) else (
    set "PYTHON_EXE=python"
)

echo [+] 使用 Python: %PYTHON_EXE%
echo [*] 正在啟動 Web 服務 (http://127.0.0.1:8000)...
echo [*] 即將為您開啟瀏覽器...
echo.

start "" "http://127.0.0.1:8000"

"%PYTHON_EXE%" src\web_server_entry.py --host 127.0.0.1 --port 8000
pause
