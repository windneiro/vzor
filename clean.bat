@echo off
setlocal

if exist .zig-cache (
  echo Removing .zig-cache
  rmdir /s /q .zig-cache
)

if exist zig-out (
  echo Removing zig-out
  rmdir /s /q zig-out
)

if exist audit-scan.json del /f /q audit-scan.json
if exist audit.log del /f /q audit.log
if exist report.html del /f /q report.html

echo Clean completed.
endlocal
