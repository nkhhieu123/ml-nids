@echo off
chcp 65001 >nul
title NIDS demo - kiem tra moi truong
cd /d "%~dp0.."
echo === Kiem tra moi truong demo (khoang 20 giay) ===
wsl -d Ubuntu -u root -- bash scripts/demo_kiem_tra.sh
echo.
pause
