# Git 初始化脚本 - PowerShell
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "金融级 C/S 架构系统 - Git 初始化" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "正在检查 Git..." -ForegroundColor Yellow
try {
    $gitVersion = git --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Git not found"
    }
    Write-Host "$gitVersion" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "[错误] 找不到 Git！" -ForegroundColor Red
    Write-Host ""
    Write-Host "请先安装 Git: https://git-scm.com/download/win" -ForegroundColor Yellow
    Write-Host "安装后需要重启终端。" -ForegroundColor Yellow
    Read-Host "按回车键退出"
    exit 1
}

Write-Host ""
Write-Host "[成功] Git 已找到！" -ForegroundColor Green
Write-Host ""

Write-Host "正在初始化仓库..." -ForegroundColor Yellow
git init
if ($LASTEXITCODE -ne 0) {
    Write-Host "[错误] 初始化失败！" -ForegroundColor Red
    Read-Host "按回车键退出"
    exit 1
}

Write-Host ""
Write-Host "[成功] Git 仓库已初始化！" -ForegroundColor Green
Write-Host ""

Write-Host "检查当前状态..." -ForegroundColor Yellow
git status

Write-Host ""
Write-Host "正在添加文件到暂存区..." -ForegroundColor Yellow
git add .
if ($LASTEXITCODE -ne 0) {
    Write-Host "[错误] 添加文件失败！" -ForegroundColor Red
    Read-Host "按回车键退出"
    exit 1
}

Write-Host ""
Write-Host "[成功] 文件已添加！" -ForegroundColor Green
Write-Host ""

Write-Host "正在创建首次提交..." -ForegroundColor Yellow
git commit -m "Initial commit: Financial C/S Architecture System"
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[提示] 需要配置 Git 用户信息" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "请运行以下命令配置您的信息：" -ForegroundColor Cyan
    Write-Host "  git config --global user.name `"Your Name`"" -ForegroundColor White
    Write-Host "  git config --global user.email `"your@email.com`"" -ForegroundColor White
    Write-Host ""
    Write-Host "然后再次运行此脚本。" -ForegroundColor Yellow
    Read-Host "按回车键退出"
    exit 1
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "恭喜！Git 仓库初始化完成！" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "查看历史记录: git log --oneline" -ForegroundColor White
Write-Host "查看状态: git status" -ForegroundColor White
Write-Host ""
Read-Host "按回车键退出"
