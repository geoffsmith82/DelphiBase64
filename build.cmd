@echo off
call "C:\Program Files (x86)\Embarcadero\Studio\37.0\bin\rsvars.bat" >nul
cd /d "C:\Programming\assemblytest\PolyFill"

echo === Building Win32 ===
dcc32 -B -E"Win32\Release" -NU"Win32\Release" PolyFillTest32.dpr
if errorlevel 1 goto :err

echo === Building Win64 ===
dcc64 -B -E"Win64\Release" -NU"Win64\Release" PolyFillTest64.dpr
if errorlevel 1 goto :err

echo.
echo BUILD OK
goto :eof

:err
echo.
echo BUILD FAILED
exit /b 1
