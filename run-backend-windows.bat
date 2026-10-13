@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creating Python environment...
    py -3 -m venv .venv
    if errorlevel 1 goto failed
)

echo Installing backend requirements...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed

echo Starting NovaPanel API at http://127.0.0.1:8000
".venv\Scripts\python.exe" -m uvicorn app.main:app --reload
goto end

:failed
echo.
echo NovaPanel backend could not start. Check the error above.
pause

:end
endlocal
