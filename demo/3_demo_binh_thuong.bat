@echo off
chcp 65001 >nul
title NIDS demo 3 - traffic binh thuong (doi chung)
cd /d "%~dp0.."
wsl -d Ubuntu -u root -- bash scripts/demo_lab.sh k1-binh-thuong
echo.
pause
