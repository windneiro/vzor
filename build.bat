@echo off
setlocal

set TARGET=%~1
if "%TARGET%"=="" set TARGET=native
set MODE=%~2
if "%MODE%"=="" set MODE=ReleaseFast

if /I "%TARGET%"=="native" goto build_native
if /I "%TARGET%"=="windows" goto build_windows
if /I "%TARGET%"=="linux" goto build_linux
if /I "%TARGET%"=="linux-arm64" goto build_linux_arm64
if /I "%TARGET%"=="all" goto build_all
goto usage

:build_native
echo Building native target with optimize=%MODE%
zig build -Doptimize=%MODE%
set ARTIFACTS=zig-out\bin\vzor.exe and/or zig-out\bin\vzor
goto end

:build_windows
echo Building Windows x86_64 with optimize=%MODE%
zig build -Dtarget=x86_64-windows -Doptimize=%MODE%
set ARTIFACTS=zig-out\bin\vzor.exe
goto end

:build_linux
echo Building Linux x86_64 with optimize=%MODE%
zig build -Dtarget=x86_64-linux -Doptimize=%MODE%
set ARTIFACTS=zig-out\bin\vzor
goto end

:build_linux_arm64
echo Building Linux aarch64 with optimize=%MODE%
zig build -Dtarget=aarch64-linux -Doptimize=%MODE%
set ARTIFACTS=zig-out\bin\vzor
goto end

:build_all
echo Building all configured targets with optimize=%MODE%
zig build build-all -Doptimize=%MODE%
set ARTIFACTS=zig-out\bin\vzor.exe, zig-out\bin\vzor, zig-out\bin\vzor-x86_64-windows.exe, zig-out\bin\vzor-x86_64-linux, zig-out\bin\vzor-aarch64-linux
goto end

:usage
echo Usage: build.bat [native^|windows^|linux^|linux-arm64^|all] [Debug^|ReleaseSafe^|ReleaseFast^|ReleaseSmall]
exit /b 1

:end
if errorlevel 1 (
  echo Build failed.
  exit /b %errorlevel%
)
echo Build completed.
echo Artifacts: %ARTIFACTS%
endlocal
