@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Run from an elevated cmd.exe on the Exchange Edge server.
rem Optional argument: local SFTP log reader account (default: edge_log_reader).
set "READER_ACCOUNT=%~1"
if not defined READER_ACCOUNT set "READER_ACCOUNT=edge_log_reader"
set "TASK_NAME=ExchangeEdgeDashboard-QueueSnapshot"
set "INSTALL_DIR=%ProgramData%\ExchangeEdgeDashboardCollector"
set "SOURCE_SCRIPT=%~dp0Collect-QueueSnapshot.ps1"
set "TARGET_SCRIPT=%INSTALL_DIR%\Collect-QueueSnapshot.ps1"
set "RUNNER=%INSTALL_DIR%\Run-QueueCollector.cmd"
set "POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "LOG_ROOT=%ProgramFiles%\Microsoft\Exchange Server\V15\TransportRoles\Logs"
if defined EDGE_LOG_ROOT set "LOG_ROOT=%EDGE_LOG_ROOT%"
set "OUTPUT_DIR=%LOG_ROOT%\Dashboard"
set "OUTPUT_FILE=%OUTPUT_DIR%\queue-snapshot.json"

fltmc >nul 2>&1
if errorlevel 1 (
    echo ERROR: Run this installer as Administrator.
    exit /b 1
)
if not exist "%SOURCE_SCRIPT%" (
    echo ERROR: Collect-QueueSnapshot.ps1 must be next to this BAT file.
    exit /b 1
)
if not exist "%LOG_ROOT%\" (
    echo ERROR: Exchange log directory not found: "%LOG_ROOT%"
    echo Set EDGE_LOG_ROOT before running if Exchange uses another log directory.
    exit /b 1
)
schtasks.exe /query /tn "%TASK_NAME%" >nul 2>&1
if not errorlevel 1 (
    echo ERROR: Task already exists. No files or task were changed.
    echo Inspect or remove that exact task before reinstalling.
    exit /b 1
)

if not exist "%INSTALL_DIR%\" mkdir "%INSTALL_DIR%"
if errorlevel 1 exit /b 1
if not exist "%OUTPUT_DIR%\" mkdir "%OUTPUT_DIR%"
if errorlevel 1 exit /b 1
copy /y "%SOURCE_SCRIPT%" "%TARGET_SCRIPT%" >nul
if errorlevel 1 exit /b 1

rem Grant the existing SFTP reader access to snapshots, not to task controls.
icacls "%OUTPUT_DIR%" /grant "%READER_ACCOUNT%:(OI)(CI)RX" >nul
if errorlevel 1 (
    echo ERROR: Could not grant the reader access to "%OUTPUT_DIR%".
    exit /b 1
)
if exist "%OUTPUT_FILE%" (
    icacls "%OUTPUT_FILE%" /grant "%READER_ACCOUNT%:R" >nul
    if errorlevel 1 exit /b 1
)

rem Prove local Exchange cmdlets work before a recurring task is installed.
echo Testing a single read-only collection...
"%POWERSHELL%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%TARGET_SCRIPT%" -OutputPath "%OUTPUT_FILE%" -Once
if errorlevel 1 (
    echo ERROR: The collector failed. No scheduled task was created.
    echo Check status and error in "%OUTPUT_FILE%".
    exit /b 1
)

> "%RUNNER%" echo @echo off
>> "%RUNNER%" echo "%POWERSHELL%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%TARGET_SCRIPT%" -OutputPath "%OUTPUT_FILE%" -IntervalSeconds 30 -MaxMessages 200 ^> "%INSTALL_DIR%\collector-last-run.log" 2^>^&1
if errorlevel 1 exit /b 1

echo Creating task as %USERDOMAIN%\%USERNAME%.
echo Windows will ask for this administrator account's password.
echo Do not type a password into the command line or share it.
schtasks.exe /create /tn "%TASK_NAME%" /sc minute /mo 1 /tr "%RUNNER%" /ru "%USERDOMAIN%\%USERNAME%" /rp * /rl highest
if errorlevel 1 (
    echo ERROR: Task registration failed. Existing snapshot and script were kept.
    exit /b 1
)
schtasks.exe /run /tn "%TASK_NAME%"
if errorlevel 1 exit /b 1
echo Task started. Check LastTaskResult and the snapshot timestamp after one minute.
echo Script: "%TARGET_SCRIPT%"
echo Snapshot: "%OUTPUT_FILE%"
exit /b 0
