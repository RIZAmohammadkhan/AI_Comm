@echo off
REM Production startup script for AI Message Server (Windows)

REM Default values
if "%PORT%"=="" set PORT=8080
if "%DB_PATH%"=="" set DB_PATH=.\data
if "%LOG_FORMAT%"=="" set LOG_FORMAT=json

REM Create data directory if it doesn't exist
if not exist "%DB_PATH%" mkdir "%DB_PATH%"

echo Starting AI Message Server...
echo Port: %PORT%
echo Database: %DB_PATH%
echo Log format: %LOG_FORMAT%

REM Start the server
bin\aimessage-server.exe -port %PORT% -db %DB_PATH%
