#!/bin/bash
# 项目快速验证脚本

echo "=========================================="
echo "金融级 C/S 架构系统 - 快速验证"
echo "=========================================="
echo ""

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 计数
TOTAL=0
PASSED=0
FAILED=0

# 检查函数
check_file() {
    TOTAL=$((TOTAL + 1))
    if [ -f "$1" ]; then
        echo -e "${GREEN}✅${NC} $1"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}❌${NC} $1 (缺失)"
        FAILED=$((FAILED + 1))
    fi
}

check_dir() {
    TOTAL=$((TOTAL + 1))
    if [ -d "$1" ]; then
        echo -e "${GREEN}✅${NC} $1/"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}❌${NC} $1/ (缺失)"
        FAILED=$((FAILED + 1))
    fi
}

# 1. 检查目录结构
echo "1. 检查目录结构"
echo "------------------------------------------"
check_dir "$PROJECT_ROOT/config"
check_dir "$PROJECT_ROOT/server"
check_dir "$PROJECT_ROOT/crypto/include"
check_dir "$PROJECT_ROOT/crypto/src"
check_dir "$PROJECT_ROOT/utils"
check_dir "$PROJECT_ROOT/examples"
echo ""

# 2. 检查核心文件
echo "2. 检查核心文件"
echo "------------------------------------------"
check_file "$PROJECT_ROOT/config/config.py"
check_file "$PROJECT_ROOT/server/server.py"
check_file "$PROJECT_ROOT/crypto/__init__.py"
check_file "$PROJECT_ROOT/crypto/CMakeLists.txt"
check_file "$PROJECT_ROOT/utils/security.py"
check_file "$PROJECT_ROOT/utils/logger.py"
check_file "$PROJECT_ROOT/examples/test_crypto.py"
check_file "$PROJECT_ROOT/requirements.txt"
check_file "$PROJECT_ROOT/README.md"
echo ""

# 3. 检查C源码文件
echo "3. 检查C源码文件"
echo "------------------------------------------"
check_file "$PROJECT_ROOT/crypto/include/financial_crypto.h"
check_file "$PROJECT_ROOT/crypto/src/sha256.c"
check_file "$PROJECT_ROOT/crypto/src/hmac.c"
check_file "$PROJECT_ROOT/crypto/src/aes256.c"
check_file "$PROJECT_ROOT/crypto/src/utils.c"
echo ""

# 4. 检查C代码语法（简单检查）
echo "4. 检查C代码结构"
echo "------------------------------------------"
TOTAL=$((TOTAL + 1))
if grep -q "#ifndef FINANCIAL_CRYPTO_H" "$PROJECT_ROOT/crypto/include/financial_crypto.h" 2>/dev/null; then
    echo -e "${GREEN}✅${NC} financial_crypto.h 有头文件保护"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌${NC} financial_crypto.h 缺少头文件保护"
    FAILED=$((FAILED + 1))
fi

TOTAL=$((TOTAL + 1))
if grep -q "typedef enum" "$PROJECT_ROOT/crypto/include/financial_crypto.h" 2>/dev/null; then
    echo -e "${GREEN}✅${NC} 定义了 CryptoResult 枚举"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌${NC} 缺少 CryptoResult 枚举定义"
    FAILED=$((FAILED + 1))
fi

TOTAL=$((TOTAL + 1))
if grep -q "sha256_hash" "$PROJECT_ROOT/crypto/include/financial_crypto.h" 2>/dev/null; then
    echo -e "${GREEN}✅${NC} 定义了 sha256_hash 函数"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌${NC} 缺少 sha256_hash 函数声明"
    FAILED=$((FAILED + 1))
fi

TOTAL=$((TOTAL + 1))
if grep -q "hmac_sha256" "$PROJECT_ROOT/crypto/include/financial_crypto.h" 2>/dev/null; then
    echo -e "${GREEN}✅${NC} 定义了 hmac_sha256 函数"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌${NC} 缺少 hmac_sha256 函数声明"
    FAILED=$((FAILED + 1))
fi

TOTAL=$((TOTAL + 1))
if grep -q "aes_256_cbc_encrypt" "$PROJECT_ROOT/crypto/include/financial_crypto.h" 2>/dev/null; then
    echo -e "${GREEN}✅${NC} 定义了 aes_256_cbc_encrypt 函数"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌${NC} 缺少 aes_256_cbc_encrypt 函数声明"
    FAILED=$((FAILED + 1))
fi

TOTAL=$((TOTAL + 1))
if grep -q "generate_random_bytes" "$PROJECT_ROOT/crypto/include/financial_crypto.h" 2>/dev/null; then
    echo -e "${GREEN}✅${NC} 定义了 generate_random_bytes 函数"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌${NC} 缺少 generate_random_bytes 函数声明"
    FAILED=$((FAILED + 1))
fi
echo ""

# 5. 统计文件行数
echo "5. 代码规模统计"
echo "------------------------------------------"
echo "Python 文件："
for pyfile in $(find "$PROJECT_ROOT" -name "*.py" -not -path "*/__pycache__/*" 2>/dev/null); do
    lines=$(wc -l < "$pyfile" 2>/dev/null || echo "0")
    echo "  $pyfile: $lines 行"
done

echo ""
echo "C 源文件："
for cfile in $(find "$PROJECT_ROOT/crypto/src" -name "*.c" 2>/dev/null); do
    lines=$(wc -l < "$cfile" 2>/dev/null || echo "0")
    echo "  $cfile: $lines 行"
done
echo ""

# 6. 总结
echo "=========================================="
echo "验证总结"
echo "=========================================="
echo "总计检查: $TOTAL"
echo -e "通过: ${GREEN}$PASSED${NC}"
echo -e "失败: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ 所有检查通过！${NC}"
    echo ""
    echo "下一步："
    echo "1. 安装Python依赖：pip install -r requirements.txt"
    echo "2. 运行测试：python examples/test_crypto.py"
    echo "3. (可选) 构建C库：cd crypto && python build.py"
    exit 0
else
    echo -e "${RED}❌ 存在问题，请检查！${NC}"
    exit 1
fi
