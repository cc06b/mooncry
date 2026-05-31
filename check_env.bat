@echo off
REM 快速检查Python环境并准备压力测试
echo ==========================================
echo 压力测试环境检查
echo ==========================================
echo.

REM 检查Python
echo [1/4] 检查Python安装...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [错误] 未检测到Python！
    echo.
    echo 请先安装Python:
    echo 1. 访问 https://www.python.org/downloads/
    echo 2. 下载并安装Python 3.8+
    echo 3. 务必勾选 "Add Python to PATH"
    echo 4. 重启此终端
    echo.
    echo 或者查看 QUICK_START.md 获取详细说明
    echo.
    pause
    exit /b 1
)

echo [OK] Python已安装
python --version
echo.

REM 检查pip
echo [2/4] 检查pip...
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [警告] pip未正确安装，尝试修复...
    python -m ensurepip --default-pip
)

echo [OK] pip可用
pip --version
echo.

REM 安装依赖
echo [3/4] 安装项目依赖...
pip install -r requirements.txt -q
if %errorlevel% neq 0 (
    echo [警告] 部分依赖安装失败，但继续...
) else (
    echo [OK] 依赖安装完成
)
echo.

REM 检查测试文件
echo [4/4] 检查测试文件...
if not exist "examples\stress_test_server.py" (
    echo [错误] 找不到测试文件！
    echo 请确保在项目根目录运行此脚本
    pause
    exit /b 1
)
echo [OK] 测试文件就绪
echo.

echo ==========================================
echo 环境检查完成！
echo ==========================================
echo.
echo 下一步操作:
echo.
echo 1. 打开第一个终端，运行:
echo    cd examples
echo    python stress_test_server.py
echo.
echo 2. 打开第二个终端，运行:
echo    cd examples
echo    python stress_test_client.py --clients 100 --requests 10
echo.
echo 或者运行自动化测试:
echo    python auto_stress_test.py
echo.
echo 详细说明请查看: QUICK_START.md
echo.
pause
