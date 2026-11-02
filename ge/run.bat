@echo off
cd /d "%~dp0"
echo Starting MediaHub GE (Development Mode)...
go run -tags "desktop,dev" .
pause

