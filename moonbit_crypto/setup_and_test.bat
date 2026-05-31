@echo off
REM MoonBit 快速安装脚本
echo ==========================================
echo MoonBit SDK 安装脚本
echo ==========================================
echo.

REM 检查是否已安装
moon --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] MoonBit 已安装
    moon --version
    goto :build
)

echo [1/4] 正在下载 MoonBit SDK...
echo.

REM 尝试下载 MoonBit
set DOWNLOAD_URL=https://github.com/moonbitlang/moonbit/releases/download/nightly-2026.05/moonbit-x86_64-pc-windows-msvc.zip
set INSTALL_DIR=%USERPROFILE%\.moonbit

REM 创建安装目录
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%INSTALL_DIR%\bin" mkdir "%INSTALL_DIR%\bin"

echo 下载地址: %DOWNLOAD_URL%
echo 安装目录: %INSTALL_DIR%
echo.

REM 提示用户手动下载
echo ==========================================
echo 手动安装步骤:
echo ==========================================
echo.
echo 1. 打开浏览器访问:
echo    https://github.com/moonbitlang/moonbit/releases
echo.
echo 2. 下载最新版本 (Windows):
echo    moonbit-x86_64-pc-windows-msvc.zip
echo.
echo 3. 解压到: %INSTALL_DIR%
echo.
echo 4. 将 %INSTALL_DIR%\bin 添加到系统 PATH
echo.
echo 5. 重启此终端，运行:
echo    moon --version
echo.
echo ==========================================
echo.

REM 尝试使用 curl 下载
echo 尝试自动下载...
curl -L -o "%INSTALL_DIR%\moonbit.zip" "%DOWNLOAD_URL%" 2>nul
if %errorlevel% equ 0 (
    echo [OK] 下载完成，正在解压...
    powershell -Command "Expand-Archive -Path '%INSTALL_DIR%\moonbit.zip' -DestinationPath '%INSTALL_DIR%' -Force"
    echo [OK] 解压完成
) else (
    echo [警告] 自动下载失败，请手动下载
)

echo.
:build
REM 尝试构建项目
echo [2/4] 检查 MoonBit 项目...
if exist "moonbit_crypto\moon.mod.json" (
    echo [OK] 找到项目配置
    cd moonbit_crypto
) else (
    echo [错误] 找不到 MoonBit 项目
    echo 请确保在项目根目录运行此脚本
    pause
    exit /b 1
)

echo.
echo [3/4] 构建 MoonBit 项目...
moon build
if %errorlevel% neq 0 (
    echo [警告] 构建失败，可能需要先安装 MoonBit
)

echo.
echo [4/4] 运行基准测试...
echo.
echo 选择测试选项:
echo   1. 运行 MoonBit 基准测试 (需要 MoonBit)
echo   2. 运行 Python 基准测试 (无需 MoonBit)
echo   3. 两者都运行
echo.
set /p choice="请选择 (1-3): "

if "%choice%"=="1" (
    echo 运行 MoonBit 测试...
    moon run benchmark
) else if "%choice%"=="2" (
    echo 运行 Python 测试...
    cd ..
    python moonbit_crypto\python_benchmark.py
) else if "%choice%"=="3" (
    echo 运行 MoonBit 测试...
    moon run benchmark
    echo.
    echo ========== Python 测试 ==========
    cd ..
    python moonbit_crypto\python_benchmark.py
)

echo.
echo ==========================================
echo 安装和测试完成！
echo ==========================================
echo.
echo 相关文档:
echo   - moonbit_crypto\INSTALL_GUIDE.md
echo   - moonbit_crypto\README.md
echo   - moonbit_crypto\TEST_REPORT.md
echo.
pause
