@echo off
setlocal EnableExtensions
rem dsh-passwords one-click installer (Windows bootstrap; real logic in scripts\install.mjs)
rem
rem Usage (either):
rem   1) Double-click this file (recommended): auto-installs missing deps,
rem      downloads the project, finishes the install, and keeps the window open
rem      showing the SETUP_KEY.
rem   2) Already cloned: run install.bat inside the project directory
rem      (skips dependency install and download).
rem
rem Checks Node.js 22.19+ or 24+ / git / dsh and installs what is missing (winget / npm),
rem then hands off to scripts\install.mjs which finishes the install (pnpm is
rem auto-installed there as well).
rem
rem NOTE: keep this file ASCII-only. cmd parses .bat with the OEM code page;
rem non-ASCII bytes get garbled regardless of chcp, breaking the prompts.

call :main
set "EXIT_CODE=%errorlevel%"
echo.
echo [dsh-passwords] Press any key to exit...
pause >nul
exit /b %EXIT_CODE%

:main
set "SCRIPT_DIR=%~dp0"

rem -- 0. Already in a cloned project directory: run the installer directly --
if exist "%SCRIPT_DIR%scripts\install.mjs" goto run

rem -- 1. Node.js (auto-install via winget if missing; version < 22 aborts) --
where node >nul 2>nul
if not errorlevel 1 goto node_ok
echo [dsh-passwords] Node.js not found, installing...
where winget >nul 2>nul
if errorlevel 1 goto node_manual
winget install OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
if errorlevel 1 goto node_manual
rem winget usually does not refresh PATH for this session; add it and re-check
set "PATH=%LOCALAPPDATA%\Programs\nodejs;%PATH%"
where node >nul 2>nul
if errorlevel 1 (
  echo [dsh-passwords] Node.js installed but not visible in this terminal.
  echo [dsh-passwords] Open a new terminal and run this installer again.
  exit /b 1
)

:node_ok
for /f "tokens=1-3 delims=v." %%a in ('node -v') do (
  set "NODE_MAJOR=%%a"
  set "NODE_MINOR=%%b"
  set "NODE_PATCH=%%c"
)
if not defined NODE_MAJOR (
  echo [dsh-passwords] Could not read the Node.js version. Check your installation.
  exit /b 1
)
if not defined NODE_MINOR set "NODE_MINOR=0"
if not defined NODE_PATCH set "NODE_PATCH=0"
if %NODE_MAJOR% LSS 22 (
  echo [dsh-passwords] Node.js is unsupported (v%NODE_MAJOR%.%NODE_MINOR%.%NODE_PATCH%), 22.19+ or 24+ required. Upgrade and retry.
  exit /b 1
)
if %NODE_MAJOR% EQU 23 (
  echo [dsh-passwords] Node.js is unsupported (v%NODE_MAJOR%.%NODE_MINOR%.%NODE_PATCH%), 22.19+ or 24+ required. Upgrade and retry.
  exit /b 1
)
if %NODE_MAJOR% EQU 22 if %NODE_MINOR% LSS 19 (
  echo [dsh-passwords] Node.js is unsupported (v%NODE_MAJOR%.%NODE_MINOR%.%NODE_PATCH%), 22.19+ or 24+ required. Upgrade and retry.
  exit /b 1
)
echo [dsh-passwords] Node.js v%NODE_MAJOR%.%NODE_MINOR%.%NODE_PATCH% OK
goto git_check

:node_manual
echo [dsh-passwords] Could not install Node.js automatically.
echo [dsh-passwords] Install Node.js 22.19+ or 24+ manually (https://nodejs.org/) and run this installer again.
exit /b 1

:git_check
rem -- 2. git (auto-install via winget if missing) --
where git >nul 2>nul
if not errorlevel 1 goto git_ok
echo [dsh-passwords] git not found, installing...
where winget >nul 2>nul
if errorlevel 1 goto git_manual
winget install Git.Git --accept-source-agreements --accept-package-agreements
if errorlevel 1 goto git_manual
set "PATH=%ProgramFiles%\Git\cmd;%PATH%"
where git >nul 2>nul
if errorlevel 1 (
  echo [dsh-passwords] git installed but not visible in this terminal.
  echo [dsh-passwords] Open a new terminal and run this installer again.
  exit /b 1
)

:git_ok
echo [dsh-passwords] git OK
goto dsh_check

:git_manual
echo [dsh-passwords] Could not install git automatically.
echo [dsh-passwords] Install it manually (https://git-scm.com/download/win) and retry.
exit /b 1

:dsh_check
rem -- 3. dsh (DeepSeek Harness, auto-install if missing) --
where dsh >nul 2>nul
if not errorlevel 1 goto dsh_ok
echo [dsh-passwords] dsh (DeepSeek Harness) not found, installing...
rem dsh needs native builds; newer npm blocks install scripts, allow them first
call npm config set allow-scripts=@deepseek-ai/dsh-subprocess-local,koffi,node-pty,@google/genai,protobufjs --location=user
call npm install -g @deepseek-ai/dsh@0.1.2-rc.1
if errorlevel 1 goto dsh_manual
where dsh >nul 2>nul
if errorlevel 1 (
  echo [dsh-passwords] dsh installed but not visible in this terminal.
  echo [dsh-passwords] Open a new terminal and run this installer again.
  exit /b 1
)

:dsh_ok
echo [dsh-passwords] dsh OK
goto prepare_dest

:dsh_manual
echo [dsh-passwords] dsh auto-install failed. Run it manually:
echo [dsh-passwords]   npm install -g @deepseek-ai/dsh@0.1.2-rc.1
echo [dsh-passwords] then verify with: DEEPSEEK_API_KEY=sk-your-key dsh web
echo [dsh-passwords] and run this installer again.
exit /b 1

:prepare_dest
rem -- 4. Install directory (DSH_PASSWORDS_DIR overrides the default) --
set "DEST=%USERPROFILE%\dsh-passwords"
if defined DSH_PASSWORDS_DIR set "DEST=%DSH_PASSWORDS_DIR%"
if exist "%DEST%" (
  echo [dsh-passwords] Target directory already exists: %DEST%
  echo [dsh-passwords] To reinstall, delete it first (back up .env and data\ inside).
  exit /b 1
)

rem -- 5. Download the project and run the install --
echo [dsh-passwords] Downloading project to %DEST% ...
git clone --depth 1 https://github.com/slywalker2006/dsh-passwords.git "%DEST%"
if errorlevel 1 (
  echo [dsh-passwords] Project download failed. Check your network and retry.
  exit /b 1
)
cd /d "%DEST%"
set "SCRIPT_DIR=%CD%\"

:run
rem Real install logic: deps / build / SETUP_KEY / plugin registration / patch
echo [dsh-passwords] Installing: deps -^> build -^> SETUP_KEY -^> register plugin -^> apply patch...
node "%SCRIPT_DIR%scripts\install.mjs"
if errorlevel 1 exit /b %errorlevel%

echo.
echo [dsh-passwords] Install finished!
echo [dsh-passwords] SETUP_KEY is shown in the output above and saved to:
echo [dsh-passwords]   %SCRIPT_DIR%setup-key.txt (auto-deleted after first-time setup)
echo [dsh-passwords] Next: start dsh (dsh web) -^> open https://server-IP.sslip.io
echo [dsh-passwords]       -^> enter SETUP_KEY to create the owner account.
exit /b 0