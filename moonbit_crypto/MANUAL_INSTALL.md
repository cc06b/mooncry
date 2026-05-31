# MoonBit 安装指南（手动方式）

## ⚠️ 自动安装失败

由于沙盒权限限制，无法自动安装。请按以下手动步骤操作：

---

## 🚀 Windows 安装（3种方式）

### 方式1: PowerShell 命令（推荐）

1. **打开 PowerShell（右键 → 以管理员身份运行）**

2. **运行安装命令：**
```powershell
irm https://cli.moonbitlang.cn/install/powershell.ps1 | iex
```

3. **如果遇到权限错误，尝试：**
```powershell
# 先删除旧目录（如果存在）
Remove-Item -Recurse -Force "$env:USERPROFILE\.moon" -ErrorAction SilentlyContinue

# 再重新安装
irm https://cli.moonbitlang.cn/install/powershell.ps1 | iex
```

---

### 方式2: VS Code 插件（最简单）

1. 安装 VS Code: https://code.visualstudio.com/

2. 安装 MoonBit 插件：
   - 打开 VS Code
   - 按 `Ctrl+Shift+X` 打开扩展
   - 搜索 "MoonBit"
   - 安装 "MoonBit" 插件

3. 按 `Ctrl+Shift+P`，输入：
   ```
   MoonBit:install latest moonbit toolchain
   ```

4. 选择 "Yes" 等待安装完成

5. 重启 VS Code

6. 在终端验证：
   ```bash
   moon --version
   ```

---

### 方式3: 手动下载

1. 访问下载页面：
   ```
   https://cli.moonbitlang.cn/binaries/latest/
   ```

2. 下载 Windows 版本：
   - `moonbit-windows-x86_64.zip`

3. 解压到指定目录：
   ```powershell
   # 创建目录
   New-Item -ItemType Directory -Path "$env:USERPROFILE\.moon\bin" -Force

   # 解压
   Expand-Archive -Path "Downloads\moonbit-windows-x86_64.zip" -DestinationPath "$env:USERPROFILE\.moon\bin"
   ```

4. 添加到 PATH：
   ```powershell
   # 临时添加（当前终端）
   $env:PATH = "$env:USERPROFILE\.moon\bin;$env:PATH"

   # 永久添加
   [Environment]::SetEnvironmentVariable("PATH", "$env:USERPROFILE\.moon\bin;$env:PATH", "User")
   ```

5. 验证安装：
   ```bash
   moon --version
   ```

---

## 🔧 安装后验证

### 1. 检查版本
```bash
moon --version
```

应该看到类似：
```
Moonbit 0.1.x
```

### 2. 检查帮助
```bash
moon help
```

### 3. 创建测试项目
```bash
moon new test_project
cd test_project
moon run main
```

---

## 📁 项目位置

MoonBit 项目应该放在：
```
c:\Users\leo\Documents\GitHub\solo\moonbit_crypto\
```

我们的项目文件：
- `moon.mod.json` - 项目配置
- `sha256.mbt` - SHA-256 实现
- `hmac.mbt` - HMAC 实现
- `benchmark.mbt` - 性能测试

---

## 🧪 运行 MoonBit 测试

安装完成后：

1. 进入项目目录：
   ```bash
   cd c:\Users\leo\Documents\GitHub\solo\moonbit_crypto
   ```

2. 构建项目：
   ```bash
   moon build
   ```

3. 运行基准测试：
   ```bash
   moon run benchmark
   ```

4. 查看性能数据！

---

## 🐛 常见问题

### Q1: 提示找不到 moon 命令

**解决：**
```powershell
# 检查是否安装成功
Get-ChildItem "$env:USERPROFILE\.moon" -Recurse

# 手动添加到 PATH
$env:PATH = "$env:USERPROFILE\.moon\bin;$env:PATH"
```

### Q2: 权限拒绝

**解决：**
```powershell
# 以管理员身份运行 PowerShell
# 或使用 VS Code 插件方式安装
```

### Q3: 安装失败

**解决：**
```powershell
# 清理后重试
Remove-Item -Recurse -Force "$env:USERPROFILE\.moon" -ErrorAction SilentlyContinue
irm https://cli.moonbitlang.cn/install/powershell.ps1 | iex
```

---

## 📚 相关资源

- 官方安装指南：https://www.moonbitlang.cn/download/
- 官方文档：https://docs.moonbitlang.cn/
- 在线体验：https://tour.moonbitlang.com/

---

## 🎯 下一步

1. 安装 MoonBit
2. 运行 `moon run benchmark`
3. 对比 Python vs MoonBit 性能

---

*如有问题，请查看官方文档或联系 MoonBit 社区*
