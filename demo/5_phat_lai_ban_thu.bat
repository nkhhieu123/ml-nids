@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
title NIDS demo 5 - phat lai ban thu lab
cd /d "%~dp0.."
echo Chon ban thu de phat lai qua cam bien realtime (nhanh gap 10 lan):
echo   1. Binh thuong          2. Quet cong           3. DoS
echo   4. DDoS nam nguon       5. Botnet 5 bot tap trung   6. Botnet 5 bot ngang hang
set /p c="Nhap so (1-6): "
set k=
if "%c%"=="1" set k=binh-thuong
if "%c%"=="2" set k=quet
if "%c%"=="3" set k=dos
if "%c%"=="4" set k=ddos
if "%c%"=="5" set k=bot5-tap-trung
if "%c%"=="6" set k=bot5-p2p
if "%k%"=="" (echo Lua chon khong hop le.& pause & exit /b 1)
python scripts\phat_lai_demo.py %k%
echo.
pause
