@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
title NIDS demo 4 - ket qua da luu
cd /d "%~dp0.."
python scripts\demo_ket_qua.py
start "" "docs\hinh\thuc_nghiem\lab\lab_do_tre.png"
start "" "docs\hinh\thuc_nghiem\lab\lab_bao_gia.png"
echo.
pause
