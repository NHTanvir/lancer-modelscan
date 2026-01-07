@echo off
REM Windows release build for lancer-modelscan.
REM Output: dist$PKG-windows-x86_64\bin$PKG.exe

echo === Building lancer-modelscan (release) for Windows x86_64 ===
cargo build --release
if errorlevel 1 exit /b 1

echo === Packaging ===
set DIST=dist$PKG-windows-x86_64
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"
mkdir "%DIST%\bin"

copy target\release$PKG.exe "%DIST%\bin\" >/dev/null
copy LICENSE "%DIST%\" >/dev/null 2>/dev/null
copy README.md "%DIST%\" >/dev/null 2>/dev/null

echo === Done. Binary: %DIST%\bin ===
dir "%DIST%\bin"
exit /b 0
