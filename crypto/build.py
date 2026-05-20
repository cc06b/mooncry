#!/usr/bin/env python3
"""
Financial Crypto Library Build Script
金融加密库构建脚本
"""

import os
import sys
import subprocess
import platform
import shutil

def run_command(cmd, cwd=None):
    """运行命令并返回结果"""
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        return False

def build():
    """构建加密库"""
    crypto_dir = os.path.dirname(os.path.abspath(__file__))
    build_dir = os.path.join(crypto_dir, 'build')
    
    # 清理旧的构建目录
    if os.path.exists(build_dir):
        print(f"Cleaning existing build directory: {build_dir}")
        shutil.rmtree(build_dir)
    
    # 创建构建目录
    os.makedirs(build_dir, exist_ok=True)
    
    print(f"Building financial crypto library in: {build_dir}")
    
    # CMake配置
    cmake_cmd = ['cmake', '..']
    if platform.system() == 'Windows':
        cmake_cmd.extend(['-G', 'Visual Studio 17 2022', '-A', 'x64'])
    
    if not run_command(cmake_cmd, cwd=build_dir):
        return False
    
    # 编译
    build_cmd = ['cmake', '--build', '.', '--config', 'Release']
    if not run_command(build_cmd, cwd=build_dir):
        return False
    
    # 复制库文件到lib目录
    lib_dir = os.path.join(crypto_dir, 'lib')
    os.makedirs(lib_dir, exist_ok=True)
    
    lib_files = []
    if platform.system() == 'Windows':
        lib_path = os.path.join(build_dir, 'lib', 'Release', 'financial_crypto.dll')
        if os.path.exists(lib_path):
            shutil.copy(lib_path, lib_dir)
            lib_files.append(lib_path)
    elif platform.system() == 'Darwin':
        lib_path = os.path.join(build_dir, 'lib', 'libfinancial_crypto.dylib')
        if os.path.exists(lib_path):
            shutil.copy(lib_path, lib_dir)
            lib_files.append(lib_path)
    else:
        lib_path = os.path.join(build_dir, 'lib', 'libfinancial_crypto.so')
        if os.path.exists(lib_path):
            shutil.copy(lib_path, lib_dir)
            lib_files.append(lib_path)
    
    if lib_files:
        print(f"\nBuild successful! Library files copied to: {lib_dir}")
        for f in lib_files:
            print(f"  - {os.path.basename(f)}")
        return True
    else:
        print("\nBuild completed but no library files found!")
        return False

if __name__ == '__main__':
    success = build()
    sys.exit(0 if success else 1)
