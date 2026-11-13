@echo off
chcp 65001 >nul
title NIDS demo 1 - quet cong (Nmap)
cd /d "%~dp0.."
wsl -d Ubuntu -u root -- bash scripts/demo_lab.sh k2-quet-nhanh
echo.
pause
