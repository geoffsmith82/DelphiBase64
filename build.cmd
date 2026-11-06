@echo off
rem Builds both libraries for Win32 and Win64. Each can also be built on its
rem own with Base64\build.cmd or Hash\build.cmd.
setlocal
cd /d "%~dp0"

echo ##### Base64
call Base64\build.cmd
if errorlevel 1 exit /b 1

echo.
echo ##### Hash
call Hash\build.cmd
if errorlevel 1 exit /b 1
