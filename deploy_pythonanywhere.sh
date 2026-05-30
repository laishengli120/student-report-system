#!/bin/bash
# ============================================================
#  班主任小助手 —— PythonAnywhere 一键部署脚本
#  支持两种方式：1) GitHub 拉取  2) 本地上传
#  在 PythonAnywhere 的 Bash 终端中运行即可
# ============================================================
set -e

# ---- 颜色 ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
err()   { echo -e "${RED}[ERR]${NC}   $1"; }

echo ""
echo "============================================"
echo "  班主任小助手 - PythonAnywhere 部署脚本"
echo "============================================"
echo ""

# ============================================================
# 步骤 1：检测环境
# ============================================================
info "正在检测 PythonAnywhere 环境……"

if ! command -v python3 &>/dev/null; then
    err "未找到 python3，请确认你在 PythonAnywhere 的 Bash 终端中运行此脚本。"
    exit 1
fi

PA_USERNAME="${PA_USERNAME:-}"
if [ -z "$PA_USERNAME" ]; then
    PA_USERNAME=$(whoami)
    echo -ne "PythonAnywhere 用户名 [${PA_USERNAME}]: "
    read -r input
    [ -n "$input" ] && PA_USERNAME="$input"
fi

if [ ! -d "/home/$PA_USERNAME" ]; then
    err "用户目录 /home/${PA_USERNAME} 不存在，请检查用户名是否正确。"
    exit 1
fi

ok "环境检测通过，用户: ${PA_USERNAME}"

# ============================================================
# 步骤 2：选择代码获取方式
# ============================================================
PROJECT_DIR="/home/${PA_USERNAME}/student-report-system"
VENV_DIR="/home/${PA_USERNAME}/.virtualenvs/student-report-env"
WSGI_FILE="/var/www/${PA_USERNAME}_pythonanywhere_com_wsgi.py"

echo ""
echo "----------------------------------------"
echo "  请选择项目代码的获取方式："
echo "----------------------------------------"
echo "  1) 从 GitHub 仓库拉取（需要有 GitHub 账号和仓库地址）"
echo "  2) 从本地上传（已在 Files 页面将项目文件上传到 PythonAnywhere）"
echo ""
echo -ne "请输入 1 或 2 [1]: "
read -r DEPLOY_MODE
DEPLOY_MODE="${DEPLOY_MODE:-1}"

# ============================================================
# 步骤 3：获取代码
# ============================================================
if [ "$DEPLOY_MODE" = "2" ]; then
    # ---- 方式 2：本地上传 ----
    echo ""
    cat << UPLOAD_HELP
${YELLOW}使用「本地上传」方式，请先完成以下操作：${NC}

  ${GREEN}1.${NC} 在 PythonAnywhere 顶部导航点击 "Files" 标签。
  ${GREEN}2.${NC} 将项目文件夹压缩为 .tar.gz 或 .zip 文件，通过 Files 页面上传。
       （进入项目文件夹，全选所有 .py / .html / .css / .js / .txt / .md 等文件，
        注意不要包含 .venv 和 __pycache__ 文件夹，打包上传即可。）
  ${GREEN}3.${NC} 上传后，在 Bash 终端中解压，例如：
       ${CYAN}tar -xzf student-report-system.tar.gz${NC}
       或
       ${CYAN}unzip student-report-system.zip -d student-report-system${NC}
  ${GREEN}4.${NC} 解压完成后，记下项目文件夹所在的路径。

UPLOAD_HELP

    echo -ne "请输入解压后的项目文件夹路径（例如 /home/${PA_USERNAME}/student-report-system）: "
    read -r SOURCE_DIR

    if [ -z "$SOURCE_DIR" ]; then
        err "路径不能为空。"
        exit 1
    fi

    if [ ! -d "$SOURCE_DIR" ]; then
        err "目录 ${SOURCE_DIR} 不存在，请检查路径是否正确。"
        exit 1
    fi

    # 检查关键文件是否存在
    if [ ! -f "$SOURCE_DIR/app.py" ]; then
        err "目录 ${SOURCE_DIR} 中未找到 app.py，请确认该目录是项目的根目录。"
        exit 1
    fi

    # 如果源目录和目标目录不同，则复制文件
    if [ "$SOURCE_DIR" != "$PROJECT_DIR" ]; then
        info "正在将项目文件复制到 ${PROJECT_DIR}……"
        if [ -d "$PROJECT_DIR" ]; then
            warn "目标目录已存在，备份旧目录……"
            mv "$PROJECT_DIR" "${PROJECT_DIR}_backup_$(date +%Y%m%d%H%M%S)"
        fi
        cp -r "$SOURCE_DIR" "$PROJECT_DIR"
        ok "项目文件已复制到 ${PROJECT_DIR}"
    else
        ok "项目目录已就绪: ${PROJECT_DIR}"
    fi

else
    # ---- 方式 1：GitHub 拉取（默认） ----
    GIT_REPO="${GIT_REPO:-}"
    if [ -z "$GIT_REPO" ]; then
        echo ""
        echo -ne "请输入 Git 仓库地址（例如 https://github.com/user/repo.git）: "
        read -r GIT_REPO
    fi

    if [ -z "$GIT_REPO" ]; then
        err "Git 仓库地址不能为空。"
        exit 1
    fi

    if [ -d "$PROJECT_DIR/.git" ]; then
        info "项目目录已存在，正在执行 git pull……"
        cd "$PROJECT_DIR"
        git pull origin main 2>/dev/null || git pull origin master 2>/dev/null || warn "git pull 失败，请手动检查"
        info "代码已更新"
    else
        if [ -d "$PROJECT_DIR" ]; then
            warn "目录 ${PROJECT_DIR} 已存在但非 git 仓库，备份后重新克隆……"
            mv "$PROJECT_DIR" "${PROJECT_DIR}_backup_$(date +%Y%m%d%H%M%S)"
        fi
        info "正在克隆仓库……"
        git clone "$GIT_REPO" "$PROJECT_DIR"
        info "代码克隆完成"
    fi
fi

cd "$PROJECT_DIR"

# 确认 app.py 存在
if [ ! -f "$PROJECT_DIR/app.py" ]; then
    err "项目目录 ${PROJECT_DIR} 中未找到 app.py，部署无法继续。"
    exit 1
fi

# ============================================================
# 步骤 4：创建虚拟环境并安装依赖
# ============================================================
info "正在创建虚拟环境……"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    ok "虚拟环境已创建: ${VENV_DIR}"
else
    ok "虚拟环境已存在，跳过创建"
fi

info "正在安装 Python 依赖……"
source "${VENV_DIR}/bin/activate"
pip install --upgrade pip -q
pip install -r "${PROJECT_DIR}/requirements.txt" -q
ok "依赖安装完成"

# ============================================================
# 步骤 5：创建必要目录
# ============================================================
info "正在创建必要目录……"
mkdir -p "${PROJECT_DIR}/instance"
mkdir -p "${PROJECT_DIR}/uploads"
ok "目录就绪（instance、uploads）"

# ============================================================
# 步骤 6：生成 WSGI 文件内容
# ============================================================
info "正在生成 WSGI 配置文件……"

WSGI_CONTENT=$(cat << WSGI_EOF
import sys
import os

project_home = '${PROJECT_DIR}'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

os.makedirs(os.path.join(project_home, 'instance'), exist_ok=True)

from app import app as application
WSGI_EOF
)

# 保存到家目录，后续手动配置
WSGI_LOCAL="${HOME}/wsgi_config.txt"
echo "$WSGI_CONTENT" > "$WSGI_LOCAL"
ok "WSGI 内容已保存到: ${WSGI_LOCAL}"

# 也尝试直接写入（部分付费账号可能有权限）
if [ -w /var/www/ ] || [ -w "$WSGI_FILE" ] 2>/dev/null; then
    echo "$WSGI_CONTENT" > "$WSGI_FILE" 2>/dev/null && ok "已直接写入: ${WSGI_FILE}" || true
fi

# ============================================================
# 步骤 7：输出后续配置说明
# ============================================================
echo ""
echo "============================================"
echo "  脚本执行完毕！请继续以下手动步骤："
echo "============================================"
echo ""

cat << GUIDE
${GREEN}1. 创建 Web App${NC}
   打开 PythonAnywhere 仪表盘 → "Web" 标签 → "Add a new web app"。
   选择 "Manual configuration"（不要选 Flask 自动配置），Python 版本选 3.10 或以上。

${GREEN}2. 配置 WSGI 文件${NC}
   创建 Web App 后，在 Web 页面中找到 "Code" 区域，点击链接打开 WSGI 配置文件编辑器。
   清空文件原有内容，将以下文件的内容粘贴进去：
   ${CYAN}${WSGI_LOCAL}${NC}
   （在 Bash 中执行 ${CYAN}cat ${WSGI_LOCAL}${NC} 可查看内容，全选复制后粘贴即可）
   粘贴完成后点击编辑器右上角的 "Save" 按钮保存。

${GREEN}3. 关联虚拟环境${NC}
   回到 Web 页面，在 "Virtualenv" 栏填入:
   ${CYAN}${VENV_DIR}${NC}

${GREEN}4. 配置静态文件映射${NC}
   在 "Static files" 区域添加一条记录：
   ${CYAN}URL: /static/     Directory: ${PROJECT_DIR}/static/${NC}

${GREEN}5. 重新加载应用${NC}
   点击 Web 页面顶部的绿色 "Reload" 按钮使配置生效。

${GREEN}6. 访问系统${NC}
   - 家长端：${CYAN}https://${PA_USERNAME}.pythonanywhere.com/parent${NC}
   - 教师端：${CYAN}https://${PA_USERNAME}.pythonanywhere.com/admin/login${NC}
   - 默认账号：admin / admin123

${GREEN}7. 后续更新代码${NC}
   代码有更新时，重新运行本脚本或手动更新文件后，
   在 Web 页面点击绿色 "Reload" 按钮即可（无需重启服务器）。
GUIDE

echo ""
warn "重要：首次登录后请立即修改默认管理员密码！"
warn "建议在管理后台配置 AI 接口密钥后再使用评语生成功能。"
echo ""
ok "部署完成！"
