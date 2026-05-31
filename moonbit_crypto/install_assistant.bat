@echo off
title MoonBit 安装助手
mode con cols=100 lines=30
color 0A

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                  MoonBit SDK 智能安装助手                      ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

REM 检查 Python（我们已经有 Python 了）
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Python 已安装
    echo.
)

REM 检查 MoonBit 是否已经安装
moon --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] MoonBit 已安装！
    moon --version
    echo.
    goto :run_tests
)

echo [提示] MoonBit SDK 未检测到
echo.
echo 请选择安装方式：
echo.
echo [1] 使用官方一键安装（推荐）
echo [2] 手动下载并安装
echo [3] 使用 Python 替代方案（无需安装 MoonBit）
echo [4] 退出
echo.
set /p choice="请选择 (1-4): "

if "%choice%"=="1" goto :auto_install
if "%choice%"=="2" goto :manual_install
if "%choice%"=="3" goto :python_only
if "%choice%"=="4" goto :eof

goto :eof

:auto_install
echo.
echo ═══════════════════════════════════════════════════════════
echo 方式1: 官方一键安装
echo ═══════════════════════════════════════════════════════════
echo.
echo 请按照以下步骤操作：
echo.
echo 1. 打开 PowerShell（管理员模式）
echo 2. 运行以下命令：
echo.
echo    irm https://moonbitlang.cn/install.sh ^| iex
echo.
echo 3. 安装完成后，重启此终端
echo 4. 再次运行此脚本
echo.
echo ═══════════════════════════════════════════════════════════
echo.
pause
goto :eof

:manual_install
echo.
echo ═══════════════════════════════════════════════════════════
echo 方式2: 手动下载安装
echo ═══════════════════════════════════════════════════════════
echo.
echo 请按照以下步骤操作：
echo.
echo 1. 打开浏览器，访问：
echo.
echo    https://github.com/moonbitlang/moonbit/releases
echo.
echo 2. 下载最新的 Windows 版本：
echo.
echo    moonbit-x86_64-pc-windows-msvc.zip
echo.
echo 3. 解压到：C:\MoonBit
echo.
echo 4. 添加到系统 PATH：
echo.
echo    C:\MoonBit\bin
echo.
echo 5. 重启此终端
echo 6. 再次运行此脚本
echo.
echo ═══════════════════════════════════════════════════════════
echo.
echo 或者，您可以直接使用 Python 替代方案（选择 [3]）
echo.
pause
goto :eof

:python_only
echo.
echo ═══════════════════════════════════════════════════════════
echo 方式3: Python 替代方案
echo ═══════════════════════════════════════════════════════════
echo.
echo [OK] 我们已经有完整的 Python 实现了！
echo.
echo 无需安装 MoonBit 即可：
echo.
echo   - 运行性能测试
echo   - 使用加密库
echo   - 对比分析结果
echo.
echo 正在运行 Python 性能测试...
echo.
cd ..
python moonbit_crypto\python_benchmark.py
if %errorlevel% equ 0 (
    echo.
    echo [OK] Python 测试完成！
    echo.
    echo 查看测试报告：
    echo   moonbit_crypto\TEST_REPORT.md
    echo   moonbit_crypto\PERFORMANCE_ANALYSIS.md
    echo.
)
goto :eof

:run_tests
echo.
echo ═══════════════════════════════════════════════════════════
echo 运行 MoonBit 加密库测试
echo ═══════════════════════════════════════════════════════════
echo.

if not exist "moonbit_crypto\moon.mod.json" (
    echo [错误] 找不到 MoonBit 项目
    echo 请确保在项目根目录运行此脚本
    pause
    exit /b 1
)

cd moonbit_crypto

echo [1/3] 构建项目...
moon build
if %errorlevel% neq 0 (
    echo [警告] 构建可能有问题，但继续尝试...
)

echo.
echo [2/3] 检查文件...
if exist "sha256.mbt" (
    echo [OK] SHA-256 代码
)
if exist "hmac.mbt" (
    echo [OK] HMAC 代码
)
if exist "benchmark.mbt" (
    echo [OK] 基准测试
)

echo.
echo [3/3] 选择测试类型：
echo.
echo [1] 运行 MoonBit 基准测试
echo [2] 运行 Python 对比测试
echo [3] 查看文档
echo [4] 退出
echo.
set /p test_choice="请选择 (1-4): "

if "%test_choice%"=="1" (
    echo.
    echo 运行 MoonBit 基准测试...
    moon run benchmark
) else if "%test_choice%"=="2" (
    echo.
    echo 运行 Python 对比测试...
    cd ..
    python moonbit_crypto\python_benchmark.py
) else if "%test_choice%"=="3" (
    echo.
    echo 打开文档...
    notepad moonbit_crypto\README.md
    notepad moonbit_crypto\TEST_REPORT.md
)

echo.
echo ═══════════════════════════════════════════════════════════
echo 测试完成！
echo ═══════════════════════════════════════════════════════════
echo.
echo 相关文档：
echo   - moonbit_crypto\README.md
echo   - moonbit_crypto\COMPLETE_GUIDE.md
echo   - moonbit_crypto\TEST_REPORT.md
echo.
pause

:eof
