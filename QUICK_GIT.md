# 快速初始化 Git

## 方式 1：使用批处理脚本（推荐，最简单）

双击运行：
```
init_git.bat
```

## 方式 2：使用 PowerShell 脚本

右键点击 `init_git.ps1`，选择"使用 PowerShell 运行"

或者在 PowerShell 中：
```powershell
cd c:\Users\leo\Documents\GitHub\solo
.\init_git.ps1
```

## 方式 3：手动运行命令

### 步骤 1：打开 Git Bash 或 PowerShell
在项目目录 `c:\Users\leo\Documents\GitHub\solo` 中右键选择
"Git Bash Here" 或在 PowerShell 中 cd 到该目录

### 步骤 2：初始化仓库
```bash
# 配置用户信息（如果还没配置的话）
git config --global user.name "您的名字"
git config --global user.email "您的邮箱"

# 初始化
git init
git add .
git commit -m "Initial commit: Financial C/S Architecture System"
```

---

## 验证是否成功

运行：
```bash
git log --oneline
```

应该看到：
```
a1b2c3d (HEAD -> main) Initial commit: Financial C/S Architecture System
```

---

## 如果需要配置用户信息

首次提交可能需要配置：
```bash
git config --global user.name "您的名字"
git config --global user.email "您的邮箱"
```

然后再重新提交。
