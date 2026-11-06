@echo off
rem Builds the base64 test/benchmark projects for Win32 and Win64.
rem Output: Win32\Release and Win64\Release next to this script.
setlocal
call "C:\Program Files (x86)\Embarcadero\Studio\37.0\bin\rsvars.bat" >nul
cd /d "%~dp0"

if not exist Win32\Release mkdir Win32\Release
if not exist Win64\Release mkdir Win64\Release

pushd Tests
echo === Win32: tests and benchmark
dcc32 -B -Q -E"..\Win32\Release" -NU"..\Win32\Release" PolyFillTest32.dpr
if errorlevel 1 goto :err
echo === Win64: tests and benchmark
dcc64 -B -Q -E"..\Win64\Release" -NU"..\Win64\Release" PolyFillTest64.dpr
if errorlevel 1 goto :err
popd

echo.
echo BUILD OK
goto :eof

:err
popd
echo.
echo BUILD FAILED
exit /b 1
