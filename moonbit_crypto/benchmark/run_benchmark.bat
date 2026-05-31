@echo off
REM SHA-256 性能基准测试 - C vs MoonBit

echo ======================================================================
echo           SHA-256 性能基准测试 (C vs MoonBit)
echo ======================================================================
echo.

REM 创建输出目录
if not exist "benchmark" mkdir benchmark

REM 编译 C 版本
echo [1/3] 编译 C 版本...
gcc -O3 -march=native -o benchmark\sha256_c.exe benchmark\sha256_c.c -lrt
if %errorlevel% neq 0 (
    echo 编译失败！
    pause
    exit /b 1
)

REM 运行 C 版本
echo.
echo [2/3] 运行 C 版本基准测试...
echo.
benchmark\sha256_c.exe

REM 运行 MoonBit 版本
echo.
echo [3/3] 运行 MoonBit 版本基准测试...
echo.
cd C:\Users\leo\Documents\GitHub\solo\moonbit_crypto
C:\Users\leo\.moon\bin\moon.exe run benchmark\sha256_moonbit.mbt

echo.
echo ======================================================================
echo                     性能对比完成
echo ======================================================================
echo.
echo 性能差距分析:
echo - 如果 MoonBit 版本性能接近 C (<2x 差距): 优化效果优秀
echo - 如果差距在 2-5x: 有进一步优化空间
echo - 如果差距 >5x: 需要深度优化或 SIMD 支持
echo.
pause
