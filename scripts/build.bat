@echo off
REM AI Message - Build Script for Windows

echo Building AI Message...

REM Create bin directory
if not exist bin mkdir bin

REM Build server
echo Building server...
go build -o bin\aimessage-server.exe .\cmd\aimessage-server
if %errorlevel% equ 0 (
    echo ✅ Server built successfully
) else (
    echo ❌ Server build failed
    exit /b 1
)

REM Build client
echo Building client...
go build -o bin\aimessage.exe .\cmd\aimessage
if %errorlevel% equ 0 (
    echo ✅ Client built successfully
) else (
    echo ❌ Client build failed
    exit /b 1
)

echo.
echo 🎉 Build complete!
echo Server: .\bin\aimessage-server.exe
echo Client: .\bin\aimessage.exe
