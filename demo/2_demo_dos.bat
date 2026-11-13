@echo off
chcp 65001 >nul
title NIDS demo 2 - DoS (tai ket noi 60 giay)
cd /d "%~dp0.."
wsl -d Ubuntu -u root -- bash scripts/demo_lab.sh k3-dos-muc2
echo.
pause
