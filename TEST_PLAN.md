# 金融级 C/S 架构系统 - 测试计划

## 测试环境要求

### 必需环境
- Python 3.8 或更高版本
- pip 包管理器
- CMake 3.10 或更高版本（用于编译C加密库）

### 可选环境
- C编译器：GCC (Linux/macOS), MSVC (Windows), Clang
- Git

## 测试步骤

### 第一阶段：环境检查

#### 1. 检查Python安装
```bash
python --version
# 或
python3 --version
```

#### 2. 检查pip
```bash
pip --version
```

#### 3. 检查CMake（可选）
```bash
cmake --version
```

### 第二阶段：安装依赖

#### 1. 安装Python依赖
```bash
cd 项目根目录
pip install -r requirements.txt
```

预期输出：
```
Installing collected packages: aiofiles, cryptography, pyjwt, python-multipart, python-dotenv
Successfully installed aiofiles-23.2.1 cryptography-41.0.7 pyjwt-2.8.0 python-multipart-0.0.6 python-dotenv-1.0.0
```

### 第三阶段：代码语法检查

#### 1. 验证所有Python文件语法
```bash
cd 项目根目录
python -m py_compile config/config.py
python -m py_compile server/server.py
python -m py_compile utils/security.py
python -m py_compile utils/logger.py
python -m py_compile crypto/__init__.py
python -m py_compile crypto/build.py
python -m py_compile examples/test_crypto.py
```

预期：所有文件编译成功，无语法错误

#### 2. 验证C代码头文件
```bash
cd crypto
gcc -fsyntax-only -I include include/financial_crypto.h
```

### 第四阶段：构建测试（可选）

如果安装了CMake和C编译器：

#### 1. 构建原生加密库
```bash
cd crypto
python build.py
```

预期输出：
```
Building financial crypto library in: ...
-- Configuring done
-- Generating done
-- Build files have been written to: ...
[100%] Built target financial_crypto
Build successful! Library files copied to: ...lib
  - financial_crypto.dll (Windows) 或
  - libfinancial_crypto.so (Linux) 或
  - libfinancial_crypto.dylib (macOS)
```

#### 2. 验证库文件生成
```bash
# Windows
dir crypto\lib\financial_crypto.dll

# Linux/macOS
ls -lh crypto/lib/libfinancial_crypto.*
```

### 第五阶段：功能测试

#### 1. 运行加密模块测试（不依赖原生库）
```bash
cd examples
python test_crypto.py
```

**预期输出应包含：**

```
============================================================
Financial Crypto Library Test
============================================================

使用原生库: False

1. 测试 SHA-256 哈希
   输入: b'Hello, World! 金融级加密测试'
   哈希结果 (hex): [32字节十六进制字符串]
   ✅ SHA-256 测试通过

2. 测试 HMAC-SHA256
   密钥: b'test-secret-key-123456'
   HMAC结果 (hex): [32字节十六进制字符串]
   ✅ HMAC-SHA256 测试通过

3. 测试随机数生成
   生成16字节随机数: [16字节十六进制字符串]
   ✅ 随机数生成测试通过

4. 测试 AES-256-CBC 加密/解密
   密钥: [32字节十六进制字符串]
   IV: [16字节十六进制字符串]
   明文: b'\xe8\xbf\x99\xe6\x98\xaf\xe4\xb8\x80\xe6\xae\xb5...'
   密文长度: XX bytes
   解密结果: b'\xe8\xbf\x99\xe6\x98\xaf\xe4\xb8\x80\xe6\xae\xb5...'
   解密成功: True
   ✅ AES-256-CBC 测试通过

5. 测试 Base64 加密/解密
   Base64密文: [Base64编码字符串]
   Base64解密结果: 这是一段敏感文本，需要加密传输。
   ✅ Base64加密测试通过

============================================================
所有测试通过！🎉
============================================================

============================================================
Security Manager Test
============================================================

1. 测试哈希功能
   数据: 测试数据
   哈希值: [64字节十六进制字符串]
   ✅ 哈希功能测试通过

2. 测试 HMAC
   验证通过: True
   ✅ HMAC测试通过

3. 测试加密/解密
   原文: 这是一个秘密消息
   密文: [加密字符串]
   解密: 这是一个秘密消息
   成功: True
   ✅ 加密/解密测试通过

4. 测试 Nonce 生成和验证
   生成 Nonce: [64字节十六进制字符串]
   验证通过: True
   二次验证: False (预期: False)
   ✅ Nonce测试通过

============================================================
安全模块测试通过！🎉
============================================================
```

#### 2. 测试原生加密库（如果已编译）
```bash
# 设置环境变量显示使用原生库
python test_crypto.py
```

**预期输出第一行：**
```
使用原生库: True
```

### 第六阶段：服务器测试

#### 1. 准备TLS证书（开发环境）
```bash
mkdir -p certs
cd certs

# 生成私钥
openssl genrsa -out server.key 2048

# 生成证书
openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/CN=localhost"

cd ..
```

#### 2. 配置环境变量
```bash
# Windows PowerShell
$env:TLS_CERT_PATH = "certs\server.crt"
$env:TLS_KEY_PATH = "certs\server.key"
$env:JWT_SECRET_KEY = "your-secure-secret-key-change-in-production"

# Linux/macOS
export TLS_CERT_PATH="certs/server.crt"
export TLS_KEY_PATH="certs/server.key"
export JWT_SECRET_KEY="your-secure-secret-key-change-in-production"
```

#### 3. 启动服务器（测试连接）
```bash
cd server
python server.py
```

**预期输出：**
```
INFO - 金融服务器启动在 ('0.0.0.0', 8443)
```

注意：由于没有实现客户端，服务器无法完整测试连接。可以检查服务器是否正常启动并监听端口。

## 测试检查清单

### 必须通过的测试
- [ ] 所有Python文件语法检查通过
- [ ] 加密模块导入成功
- [ ] SHA-256哈希功能正常
- [ ] HMAC-SHA256功能正常
- [ ] AES-256-CBC加密/解密正常
- [ ] 随机数生成正常
- [ ] Base64加密/解密正常
- [ ] SecurityManager所有功能正常
- [ ] JWT生成和验证正常
- [ ] Nonce生成和验证正常

### 可选测试（需要额外环境）
- [ ] CMake构建系统正常（需要CMake）
- [ ] C加密库编译成功（需要C编译器）
- [ ] 原生加密库加载正常（需要编译后的库文件）
- [ ] TLS服务器启动正常（需要证书）
- [ ] 并发连接测试（需要完整客户端）

## 性能基准测试

### 测试SHA-256性能
```python
import time
from crypto import sha256

data = b"test data" * 1000
iterations = 10000

start = time.time()
for _ in range(iterations):
    sha256(data)
end = time.time()

print(f"SHA-256: {iterations} 次迭代耗时 {end - start:.3f} 秒")
print(f"平均每次: {(end - start) / iterations * 1000:.3f} 毫秒")
```

### 对比测试（原生 vs Python）
```python
import time
from crypto import use_native, sha256

data = b"test data" * 1000
iterations = 10000

start = time.time()
for _ in range(iterations):
    sha256(data)
end = time.time()

print(f"使用原生库: {use_native}")
print(f"耗时: {end - start:.3f} 秒")
```

## 故障排除

### 问题1：Python未安装
解决方案：从 https://www.python.org/downloads/ 下载并安装Python 3.8+

### 问题2：依赖安装失败
解决方案：
```bash
# 使用国内镜像
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### 问题3：CMake找不到编译器
解决方案：
```bash
# Windows: 安装Visual Studio Build Tools
# Linux: sudo apt-get install build-essential
# macOS: xcode-select --install
```

### 问题4：无法加载原生加密库
解决方案： 
1. 确保已成功构建库文件
2. 检查库文件是否在正确位置（crypto/lib/）
3. 检查PATH环境变量

### 问题5：TLS证书错误
解决方案：
1. 使用上述命令生成自签名证书
2. 或者从证书颁发机构获取正式证书
3. 确保证书路径配置正确

## 测试报告模板

```
测试日期: [日期]
测试人员: [姓名]
测试环境: [操作系统、Python版本等]

### 测试结果汇总
✅ 通过: [数量]
❌ 失败: [数量]
⚠️  跳过: [数量]

### 详细测试结果
[列出每个测试项的结果]

### 性能测试结果
[列出性能测试数据]

### 问题记录
[记录发现的问题和解决方案]

### 结论
[总体评估]
```

## 联系支持

如果在测试过程中遇到问题：
1. 检查本文档的故障排除部分
2. 查看项目的README.md
3. 检查日志文件 logs/app.log
4. 提交Issue到项目仓库
