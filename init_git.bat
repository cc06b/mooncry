@echo off
REM Git 初始化脚本 - Windows
echo ==========================================
echo 金融级 C/S 架构系统 - Git 初始化
echo ==========================================
echo.

cd /d "%~dp0"

echo 正在检查 Git...
git --version
if %errorlevel% neq 0 (
    echo.
    echo [错误] 找不到 Git！
    echo.
    echo 请先安装 Git: https://git-scm.com/download/win
    echo 安装后需要重启终端。
    pause
    exit /b 1
)

echo.
echo Git 已找到！
echo.

echo 正在初始化仓库...
git init
if %errorlevel% neq 0 (
    echo [错误] 初始化失败！
    pause
    exit /b 1
)

echo.
echo [成功] Git 仓库已初始化！
echo.

echo 检查当前状态...
git status

echo.
echo 正在添加文件到暂存区...
git add .
if %errorlevel% neq 0 (
    echo [错误] 添加文件失败！
    pause
    exit /b 1
)

echo.
echo [成功] 文件已添加！
echo.

echo 正在创建首次提交...
git commit -m "Initial commit: Financial C/S Architecture System"
if %errorlevel% neq 0 (
    echo.
    echo [提示] 需要配置 Git 用户信息
    echo.
    echo 请运行以下命令配置您的信息：
    echo   git config --global user.name "Your Name"
    echo   git config --global user.email "your@email.com"
    echo.
    echo 然后再次运行此脚本。
    pause
    exit /b 1
)

echo.
echo ==========================================
echo 恭喜！Git 仓库初始化完成！
echo ==========================================
echo.
echo 查看历史记录: git log --oneline
echo 查看状态: git status
echo.
pause
