@echo off
cd /d "%~dp0"
echo Building MediaHub GE (Production Release)...
go build -tags "desktop,production" -ldflags="-w -s -H windowsgui" -o ge.exe .
echo Build completed: ge.exe
pause

