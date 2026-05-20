# Git 版本控制设置指南

## 1. 安装 Git

### Windows
从官方网站下载并安装 Git：
https://git-scm.com/download/win

安装时建议选择：
- "Git from the command line and also from 3rd-party software"
- "Checkout Windows-style, commit Unix-style line endings"

### macOS
使用 Homebrew 安装：
```bash
brew install git
```

或者从官网下载：https://git-scm.com/download/mac

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install git
```

### 验证安装
安装完成后，在终端运行：
```bash
git --version
```

应该会显示类似：`git version 2.xx.x`

---

## 2. 初始化 Git 仓库

在项目目录 `c:\Users\leo\Documents\GitHub\solo` 中执行以下操作：

### 步骤 1：配置用户信息
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### 步骤 2：初始化仓库
```bash
cd c:\Users\leo\Documents\GitHub\solo
git init
```

### 步骤 3：查看状态
```bash
git status
```

### 步骤 4：添加文件到暂存区
```bash
git add .
```

### 步骤 5：首次提交
```bash
git commit -m "Initial commit: Financial C/S Architecture System"
```

---

## 3. 已创建的 .gitignore 文件

我已经为您创建了 `.gitignore` 文件，它会忽略以下内容：

✅ **已配置的忽略项：**
- Python 缓存文件 (__pycache__, *.pyc)
- C/C++ 编译产物 (build/, lib/, *.o, *.so, *.dll)
- IDE 配置文件 (.vscode/, .idea/)
- 日志文件 (*.log, logs/)
- 环境变量文件 (.env)
- TLS 证书 (certs/, *.key, *.crt) - **重要！不要提交证书！**
- 操作系统临时文件

---

## 4. Git 常用命令

### 查看修改
```bash
git status          # 查看工作区状态
git diff            # 查看未暂存的修改
git diff --staged   # 查看已暂存的修改
```

### 提交变更
```bash
git add .                   # 添加所有修改
git add <文件名>            # 添加指定文件
git commit -m "提交信息"    # 提交修改
```

### 查看历史
```bash
git log                     # 查看提交历史
git log --oneline          # 简洁的历史记录
```

### 分支操作
```bash
git branch                 # 查看分支
git branch <分支名>        # 创建分支
git checkout <分支名>      # 切换分支
git checkout -b <分支名>   # 创建并切换分支
git merge <分支名>         # 合并分支
```

### 远程仓库（可选）
如果需要同步到 GitHub 等远程仓库：

```bash
# 添加远程仓库
git remote add origin https://github.com/your-username/your-repo.git

# 推送到远程
git push -u origin main

# 拉取远程更新
git pull origin main
```

---

## 5. 推荐的 Git 工作流

### 开发新功能
```bash
# 1. 从 main 分支创建新分支
git checkout main
git pull origin main
git checkout -b feature/my-new-feature

# 2. 开发和提交
git add .
git commit -m "Add new feature"

# 3. 推送到远程
git push origin feature/my-new-feature

# 4. 创建 Pull Request（在 GitHub 上）
```

### 修复 Bug
```bash
git checkout main
git pull origin main
git checkout -b fix/bug-description

# ... 修复 bug ...

git add .
git commit -m "Fix bug: description"
git push origin fix/bug-description
```

---

## 6. 安全注意事项

⚠️ **永远不要提交以下文件：**
- `.env` 文件（包含密钥和配置）
- TLS 证书和私钥 (certs/)
- 包含密码或密钥的配置文件
- 用户的个人信息

✅ **推荐做法：**
- 使用 `.env.example` 提供配置模板
- 在 README 中说明如何配置环境变量
- 确保所有敏感信息已被正确忽略

---

## 7. 快速开始脚本

### Windows (PowerShell)
```powershell
# 设置用户信息
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# 初始化仓库
cd c:\Users\leo\Documents\GitHub\solo
git init
git add .
git commit -m "Initial commit: Financial C/S Architecture System"

Write-Host "Git 仓库初始化完成！" -ForegroundColor Green
```

### macOS/Linux (Bash)
```bash
# 设置用户信息
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# 初始化仓库
cd ~/Documents/GitHub/solo
git init
git add .
git commit -m "Initial commit: Financial C/S Architecture System"

echo "Git 仓库初始化完成！"
```

---

## 8. 下一步

初始化 Git 仓库后，您可以：

1. **连接到远程仓库**（如 GitHub）
2. **创建开发分支**进行功能开发
3. **使用 Pull Request** 进行代码审查
4. **使用标签**标记发布版本

---

有任何问题，请参考 Git 官方文档：
https://git-scm.com/doc
