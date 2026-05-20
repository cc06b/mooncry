#!/usr/bin/env python3
"""
项目测试脚本
用于验证代码语法和基本结构
"""

import os
import sys
import ast
import re
from pathlib import Path


class CodeAnalyzer:
    """代码分析器"""
    
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.issues = []
        self.warnings = []
        
    def check_python_syntax(self, filepath):
        """检查Python文件语法"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            ast.parse(content)
            return True, None
        except SyntaxError as e:
            return False, f"语法错误 (行 {e.lineno}): {e.msg}"
        except Exception as e:
            return False, f"错误: {str(e)}"
    
    def check_imports(self, filepath):
        """检查导入语句"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            imports = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
            
            return imports
        except:
            return []
    
    def check_docstrings(self, filepath):
        """检查文档字符串"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            has_module_doc = ast.get_docstring(tree) is not None
            
            classes_with_doc = 0
            functions_with_doc = 0
            total_classes = 0
            total_functions = 0
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    total_classes += 1
                    if ast.get_docstring(node):
                        classes_with_doc += 1
                elif isinstance(node, ast.FunctionDef):
                    total_functions += 1
                    if ast.get_docstring(node):
                        functions_with_doc += 1
            
            return {
                'has_module_doc': has_module_doc,
                'classes_with_doc': f"{classes_with_doc}/{total_classes}",
                'functions_with_doc': f"{functions_with_doc}/{total_functions}"
            }
        except:
            return None
    
    def analyze_file(self, filepath):
        """分析单个文件"""
        print(f"\n分析文件: {filepath.relative_to(self.project_root)}")
        print("-" * 60)
        
        ok, error = self.check_python_syntax(filepath)
        if ok:
            print("✅ 语法检查通过")
        else:
            print(f"❌ 语法检查失败: {error}")
            self.issues.append(f"{filepath.name}: {error}")
            return
        
        imports = self.check_imports(filepath)
        print(f"📦 导入模块 ({len(imports)}): {', '.join(imports[:5])}")
        if len(imports) > 5:
            print(f"   ... 还有 {len(imports) - 5} 个导入")
        
        docs = self.check_docstrings(filepath)
        if docs:
            print(f"📝 文档字符串:")
            print(f"   - 模块文档: {'✅ 有' if docs['has_module_doc'] else '⚠️  无'}")
            print(f"   - 类文档: {docs['classes_with_doc']} 有文档")
            print(f"   - 函数文档: {docs['functions_with_doc']} 有文档")
    
    def check_c_file_structure(self, filepath):
        """检查C文件结构"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            print(f"\n分析C文件: {filepath.relative_to(self.project_root)}")
            print("-" * 60)
            
            if filepath.suffix == '.h':
                if re.search(r'#ifndef\s+\w+', content):
                    print("✅ 有头文件保护")
                else:
                    print("⚠️  无头文件保护")
            
            functions = re.findall(r'(?:\w+\s+)+\s*(\w+)\s*\([^)]*\)\s*\{', content)
            print(f"🔧 函数数量: {len(functions)}")
            
            single_comments = len(re.findall(r'//.*', content))
            multi_comments = len(re.findall(r'/\*.*?\*/', content, re.DOTALL))
            print(f"💬 注释: 单行 {single_comments}, 多行 {multi_comments}")
            
            return True
        except Exception as e:
            print(f"❌ C文件分析失败: {e}")
            return False
    
    def run(self):
        """运行分析"""
        print("=" * 60)
        print("金融级 C/S 架构系统 - 代码分析")
        print("=" * 60)
        print(f"\n项目目录: {self.project_root}")
        
        python_files = list(self.project_root.glob('**/*.py'))
        print(f"\n找到 {len(python_files)} 个Python文件")
        
        for py_file in sorted(python_files):
            if '__pycache__' not in str(py_file):
                self.analyze_file(py_file)
        
        c_files = list(self.project_root.glob('crypto/**/*.c')) + \
                  list(self.project_root.glob('crypto/**/*.h'))
        print(f"\n\n找到 {len(c_files)} 个C/C++文件")
        
        for c_file in sorted(c_files):
            self.check_c_file_structure(c_file)
        
        print("\n\n" + "=" * 60)
        print("项目结构检查")
        print("=" * 60)
        
        required_dirs = [
            'config',
            'server',
            'crypto/include',
            'crypto/src',
            'utils',
            'examples'
        ]
        
        required_files = [
            'config/config.py',
            'server/server.py',
            'crypto/__init__.py',
            'crypto/CMakeLists.txt',
            'crypto/src/sha256.c',
            'crypto/src/hmac.c',
            'crypto/src/aes256.c',
            'crypto/src/utils.c',
            'crypto/include/financial_crypto.h',
            'utils/security.py',
            'utils/logger.py',
            'examples/test_crypto.py',
            'requirements.txt',
            'README.md'
        ]
        
        print("\n📁 目录结构:")
        for dir_path in required_dirs:
            full_path = self.project_root / dir_path
            if full_path.exists():
                print(f"   ✅ {dir_path}")
            else:
                print(f"   ❌ {dir_path} (缺失)")
                self.issues.append(f"缺失目录: {dir_path}")
        
        print("\n📄 必需文件:")
        for file_path in required_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                size = full_path.stat().st_size
                print(f"   ✅ {file_path} ({size} bytes)")
            else:
                print(f"   ❌ {file_path} (缺失)")
                self.issues.append(f"缺失文件: {file_path}")
        
        print("\n\n" + "=" * 60)
        print("分析总结")
        print("=" * 60)
        
        if not self.issues:
            print("✅ 所有检查通过！项目结构完整，代码质量良好。")
        else:
            print(f"⚠️  发现 {len(self.issues)} 个问题:")
            for issue in self.issues:
                print(f"   - {issue}")
        
        print("\n下一步:")
        print("1. 安装Python依赖: pip install -r requirements.txt")
        print("2. 运行测试: python examples/test_crypto.py")
        print("3. (可选) 构建原生库: cd crypto && python build.py")
        
        return len(self.issues) == 0


def main():
    """主函数"""
    script_dir = Path(__file__).parent
    project_root = script_dir
    
    analyzer = CodeAnalyzer(project_root)
    success = analyzer.run()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
