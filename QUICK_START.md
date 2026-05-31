# 压力测试快速启动指南

## ⚠️ 当前状态

当前环境未检测到Python安装。请按照以下步骤操作：

---

## 🚀 方法1：快速安装Python（推荐）

### 步骤1：下载Python
访问官网下载：https://www.python.org/downloads/

选择 **Python 3.8 或更高版本**

### 步骤2：安装Python
运行安装程序，**务必勾选**：
- ☑️ "Add Python to PATH"
- ☑️ "Install pip"

### 步骤3：验证安装
打开**新的**命令提示符（或PowerShell），运行：

```bash
python --version
```

应该看到类似：`Python 3.x.x`

---

## 🚀 方法2：使用已安装的Python

如果您已经安装了Python但无法运行，可能需要：

1. **重启终端**（使PATH生效）
2. **或者使用完整路径**，例如：
   ```bash
   C:\Python39\python.exe --version
   ```

---

## 📦 安装依赖

无论使用哪种方法，安装完Python后都需要：

```bash
cd c:\Users\leo\Documents\GitHub\solo
pip install -r requirements.txt
```

---

## 🎯 开始压力测试

### 步骤1：启动服务器
打开**第一个**终端窗口，运行：

```bash
cd c:\Users\leo\Documents\GitHub\solo
cd examples
python stress_test_server.py
```

应该看到：
```
[Server] 压测服务器启动在 0.0.0.0:8443
[Server] 监听中...
```

### 步骤2：运行压力测试
打开**第二个**终端窗口，运行：

```bash
cd c:\Users\leo\Documents\GitHub\solo
cd examples
python auto_stress_test.py
```

或者运行单次测试（更快）：

```bash
cd c:\Users\leo\Documents\GitHub\solo
cd examples
python stress_test_client.py --clients 100 --requests 10
```

---

## 📊 测试配置

### 快速测试（5分钟）
```bash
python stress_test_client.py --clients 100 --requests 20
```

### 完整测试（15分钟）
```bash
python auto_stress_test.py
```

### 极限测试
```bash
python stress_test_client.py --clients 1000 --requests 5
```

---

## 🎉 测试完成

测试完成后会显示：

- ✅ 总请求数
- ✅ 成功/失败数
- ✅ QPS（每秒请求数）
- ✅ 延迟统计（P50, P95, P99）
- ✅ 性能评估

---

## 📝 预期结果

### 方案A（Python备用方案）
- **QPS**: 300-500
- **最大并发**: 1,200-1,500
- **P99延迟**: < 50ms

### 方案B（原生C库）
- **QPS**: 2,500-5,000
- **最大并发**: 5,000-8,000
- **P99延迟**: < 10ms

---

## ❓ 常见问题

### 问题1：python命令找不到
**解决**：重启终端，或重新安装Python并勾选"Add to PATH"

### 问题2：pip安装失败
**解决**：
```bash
python -m pip install --upgrade pip
```

### 问题3：端口被占用
**解决**：修改端口
```bash
python stress_test_server.py --port 8444
python stress_test_client.py --port 8444
```

### 问题4：模块导入错误
**解决**：
```bash
pip install -r requirements.txt
```

---

## 📞 需要帮助？

查看详细文档：
- [STRESS_TEST_REPORT.md](file:///c:/Users/leo/Documents/GitHub/solo/STRESS_TEST_REPORT.md) - 压测报告
- [PERFORMANCE_ANALYSIS.md](file:///c:/Users/leo/Documents/GitHub/solo/PERFORMANCE_ANALYSIS.md) - 性能分析
