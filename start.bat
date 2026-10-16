@echo off
setlocal EnableExtensions

rem SafeHands quick launcher. All paths are resolved relative to this file.
cd /d "%~dp0"

where node >nul 2>&1
if errorlevel 1 (
  echo SafeHands needs Node.js 22.14.0 or newer in the Node 22 line.
  echo Install Node.js from https://nodejs.org/ and run start.bat again.
  pause
  exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
  echo npm was not found. Reinstall Node.js with npm enabled, then try again.
  pause
  exit /b 1
)

if not exist "node_modules\vite\package.json" (
  echo First run: installing locked dependencies...
  call npm ci
  if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
  )
)

echo Starting SafeHands at http://localhost:5173/
start "SafeHands dev server" /min cmd /k "cd /d ""%~dp0"" && npm run dev"
timeout /t 3 /nobreak >nul
start "" "http://localhost:5173/"

echo SafeHands is running. Close the SafeHands dev server window to stop it.
endlocal
