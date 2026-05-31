# MoonBit 安装指南

## 🔍 当前状态

**MoonBit SDK 未安装** - 需要手动安装

---

## 🚀 安装步骤

### 方式1: 使用安装脚本（推荐）

#### Windows PowerShell

```powershell
# 以管理员身份运行 PowerShell
irm https://moonbitlang.cn/install.sh | iex
```

或者手动下载：
```powershell
# 下载 MoonBit 安装包
Invoke-WebRequest -Uri "https://github.com/moonbitlang/moonbit/releases/latest/download/moonbit-x86_64-pc-windows-msvc.zip" -OutFile "moonbit.zip"

# 解压到指定目录
Expand-Archive -Path "moonbit.zip" -DestinationPath "C:\MoonBit"

# 添加到 PATH
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\MoonBit", "User")

# 刷新 PATH
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","User") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","Machine")

# 验证安装
moon --version
```

#### Linux / macOS

```bash
# 一键安装
curl -fsSL https://moonbitlang.cn/install.sh | bash

# 或者使用 brew (macOS)
brew install moonbitlang/tap/moon

# 验证安装
moon --version
```

---

### 方式2: 手动下载

1. 访问 GitHub Releases:
   ```
   https://github.com/moonbitlang/moonbit/releases
   ```

2. 下载对应系统的版本:
   - **Windows**: `moonbit-x86_64-pc-windows-msvc.zip`
   - **Linux**: `moonbit-x86_64-unknown-linux-musl.tar.gz`
   - **macOS (Intel)**: `moonbit-x86_64-apple-darwin.tar.gz`
   - **macOS (Apple Silicon)**: `moonbit-aarch64-apple-darwin.tar.gz`

3. 解压到任意目录（如 `C:\MoonBit` 或 `~/.moonbit`）

4. 添加到系统 PATH

---

## ✅ 验证安装

安装完成后，运行：

```bash
moon --version
```

应该看到类似输出：
```
Moonbit 0.1.x (build date: 2026-05-21)
```

---

## 📦 项目构建

### 1. 进入项目目录

```bash
cd c:\Users\leo\Documents\GitHub\solo\moonbit_crypto
```

### 2. 构建项目

```bash
moon build
```

### 3. 运行测试

```bash
moon test
```

### 4. 运行基准测试

```bash
moon run benchmark
```

---

## 🐛 常见问题

### 问题1: 命令找不到

**Windows:**
```powershell
# 检查是否在 PATH 中
$env:PATH -split ';'

# 手动添加到 PATH（如果缺失）
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\MoonBit", "User")
```

**Linux/macOS:**
```bash
# 检查 ~/.bashrc 或 ~/.zshrc
echo $PATH

# 手动添加
export PATH="$HOME/.moonbit/bin:$PATH"
```

### 问题2: 权限错误

**Linux/macOS:**
```bash
chmod +x moon
```

### 问题3: 依赖缺失

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential
```

**macOS:**
```bash
xcode-select --install
```

---

## 🎯 测试验证

安装完成后，运行以下测试：

```bash
# 1. 查看版本
moon --version

# 2. 构建项目
cd moonbit_crypto
moon build

# 3. 运行基准测试
moon run benchmark

# 4. 应该看到性能数据
```

---

## 📚 学习资源

- 官方文档: https://moonbitlang.cn/docs/
- 在线 IDE: https://moonbitlang.cn/ide/
- 示例代码: https://moonbitlang.cn/examples/

---

## 🚀 下一步

安装完成后，我可以帮您：
1. 构建 MoonBit 加密库
2. 运行性能测试
3. 对比 Python/C 实现
4. 继续优化性能

---

*如有问题，请参考 MoonBit 官方文档或提交 Issue*
