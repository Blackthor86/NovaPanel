@echo off
setlocal
cd /d "%~dp0frontend"

if not exist "node_modules" (
    echo Installing frontend packages...
    call npm.cmd install
    if errorlevel 1 goto failed
)

echo Starting NovaPanel dashboard...
call npm.cmd run dev
goto end

:failed
echo.
echo NovaPanel dashboard could not start. Check the error above.
pause

:end
endlocal
