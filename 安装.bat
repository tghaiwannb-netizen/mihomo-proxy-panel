@echo off
chcp 65001 >nul
title 安装 ACIS 代理
cd /d "%~dp0"
echo 正在创建桌面快捷方式...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0make-shortcuts.ps1"
echo.
echo 安装完成。桌面上有「代理控制台」「启动代理」「停止代理」。
echo 现在打开控制台，请用墨清账户登录。
echo.
start "" "%~dp0panel\start-panel.bat"
timeout /t 5 >nul
