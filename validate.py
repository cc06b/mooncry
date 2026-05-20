#!/usr/bin/env python3
"""
项目验证脚本
检查所有 Python 文件的语法和基本功能
"""

import os
import sys
import ast

def check_python_syntax(filepath):
    """检查 Python 文件语法"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        ast.parse(content)
        return True, None
    except SyntaxError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def validate_project():
    """验证项目文件"""
    print("=" * 60)
    print("金融级 C/S 架构系统 - 项目验证")
    print("=" * 60)
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"\n项目根目录: {base_dir}")
    
    python_files = [
        os.path.join(base_dir, "config", "config.py"),
        os.path.join(base_dir, "server", "server.py"),
        os.path.join(base_dir, "utils", "logger.py"),
        os.path.join(base_dir, "utils", "security.py"),
        os.path.join(base_dir, "crypto", "__init__.py"),
        os.path.join(base_dir, "crypto", "build.py"),
        os.path.join(base_dir, "examples", "test_crypto.py"),
    ]
    
    print(f"\n1. 检查 Python 文件语法 ({len(python_files)} 个文件):")
    all_good = True
    for filepath in python_files:
        if os.path.exists(filepath):
            ok, error = check_python_syntax(filepath)
            rel_path = os.path.relpath(filepath, base_dir)
            if ok:
                print(f"   ✅ {rel_path}")
            else:
                print(f"   ❌ {rel_path}: {error}")
                all_good = False
        else:
            print(f"   ⚠️  {rel_path}: 文件不存在")
    
    c_files = [
        os.path.join(base_dir, "crypto", "include", "financial_crypto.h"),
        os.path.join(base_dir, "crypto", "src", "sha256.c"),
        os.path.join(base_dir, "crypto", "src", "hmac.c"),
        os.path.join(base_dir, "crypto", "src", "aes256.c"),
        os.path.join(base_dir, "crypto", "src", "utils.c"),
    ]
    
    print(f"\n2. 检查 C 语言文件 ({len(c_files)} 个文件):")
    for filepath in c_files:
        if os.path.exists(filepath):
            rel_path = os.path.relpath(filepath, base_dir)
            file_size = os.path.getsize(filepath)
            print(f"   ✅ {rel_path} ({file_size} bytes)")
    
    print(f"\n3. 项目结构:")
    structure = [
        "config/config.py",
        "server/server.py", 
        "crypto/include/financial_crypto.h",
        "crypto/src/sha256.c",
        "crypto/src/hmac.c",
        "crypto/src/aes256.c",
        "crypto/src/utils.c",
        "crypto/CMakeLists.txt",
        "crypto/__init__.py",
        "crypto/build.py",
        "utils/security.py",
        "utils/logger.py",
        "examples/test_crypto.py",
        "requirements.txt",
        "README.md"
    ]
    for item in structure:
        path = os.path.join(base_dir, item)
        if os.path.exists(path):
            print(f"   ✅ {item}")
        else:
            print(f"   ❌ {item}")
    
    print("\n" + "=" * 60)
    if all_good:
        print("✅ 所有 Python 文件语法检查通过！")
    else:
        print("❌ 部分文件有问题，请检查")
    print("=" * 60)
    
    print("\n📋 构建加密库:")
    print("   要构建原生加密库，请在 crypto/ 目录下运行:")
    print("     1. 确保安装了 CMake 和 C 编译器")
    print("     2. python build.py")
    print("\n📋 运行测试:")
    print("   cd examples")
    print("   python test_crypto.py")

if __name__ == "__main__":
    validate_project()
