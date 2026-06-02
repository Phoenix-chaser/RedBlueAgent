#!/bin/bash
# =============================================================================
# PentestAgent - Kali Linux 一键安装脚本
# 使用: bash setup_kali.sh
# =============================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
step()    { echo -e "\n${BLUE}[>]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     PentestAgent - Kali Linux 安装脚本           ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# 检查是否为 Kali
if grep -qi "kali" /etc/os-release 2>/dev/null; then
    info "检测到 Kali Linux"
else
    warn "未检测到 Kali Linux，将尝试继续（Ubuntu/Debian 也兼容）"
fi

# =============================================================================
# 1. 系统工具（Kali 已预装大部分，apt 会跳过已安装的包）
# =============================================================================
step "检查/安装系统工具..."
sudo apt-get update -qq

TOOLS_TO_CHECK=(nmap nikto sqlmap dirsearch curl git)
MISSING=()
for tool in "${TOOLS_TO_CHECK[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING+=("$tool")
    else
        info "$tool 已安装"
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    warn "安装缺少的工具: ${MISSING[*]}"
    sudo apt-get install -y "${MISSING[@]}"
fi

# Metasploit 单独检查（Kali 预装，Ubuntu 需要手动装）
if command -v msfconsole &>/dev/null; then
    info "metasploit 已安装"
else
    warn "未找到 metasploit（可选）。Kali 上安装: sudo apt install metasploit-framework"
fi

# =============================================================================
# 2. Python 依赖
# =============================================================================
step "安装 Python 依赖..."

# Kali 可能需要 --break-system-packages 或使用 venv
PYTHON_VERSION=$(python3 --version 2>&1)
info "Python: $PYTHON_VERSION"

# 检查是否需要 venv（Python 3.11+ 在 Kali 上可能需要）
if python3 -m pip install --dry-run rich 2>&1 | grep -q "externally-managed"; then
    warn "系统 Python 受保护，使用虚拟环境..."

    if [ ! -d "venv" ]; then
        python3 -m venv venv
        info "虚拟环境已创建: ./venv"
    fi

    source venv/bin/activate
    PIP_CMD="pip"
    echo ""
    echo "  ⚠️  每次使用项目前需要激活虚拟环境:"
    echo "  source venv/bin/activate"
    echo ""
else
    PIP_CMD="pip3"
fi

# 重定向 pip 临时目录到磁盘（避免 tmpfs 满导致 No space left on device）
export TMPDIR="$HOME/tmp_pip"
mkdir -p "$TMPDIR"

$PIP_CMD install --upgrade pip -q
$PIP_CMD install --no-cache-dir -r requirements.txt

# 清理临时目录
rm -rf "$TMPDIR"

info "Python 依赖安装完成"

# =============================================================================
# 3. 配置 .env 文件
# =============================================================================
step "配置环境变量..."

if [ ! -f ".env" ]; then
    cp .env.example .env
    warn ".env 已创建，请编辑并填入 API Key:"
    echo ""
    echo "  nano .env"
    echo ""
    echo "  国产模型推荐 (选一个):"
    echo "    DEEPSEEK_API_KEY=sk-...   (https://platform.deepseek.com)"
    echo "    MOONSHOT_API_KEY=sk-...   (https://platform.moonshot.cn)"
    echo "    ZHIPU_API_KEY=...         (https://open.bigmodel.cn)"
else
    info ".env 已存在"
fi

# =============================================================================
# 4. 创建数据目录
# =============================================================================
step "创建数据目录..."
mkdir -p data/sessions data/reports data/knowledge_base/vector_store \
         data/knowledge_base/cve_entries data/knowledge_base/exploit_techniques
info "数据目录就绪"

# =============================================================================
# 5. 靶场（可选，需要 Docker）
# =============================================================================
step "检查 Docker（靶场用）..."
if command -v docker &>/dev/null; then
    info "Docker 已安装"
    if [ -f "docker/docker-compose.yml" ]; then
        echo ""
        echo "  启动内置靶场:"
        echo "  cd docker && docker compose up -d target"
        echo "  靶场地址: http://localhost:8080"
    fi
else
    warn "未安装 Docker（可选，用于启动靶场）"
    echo "  安装: sudo apt install docker.io docker-compose-v2"
    echo "  启用: sudo systemctl enable --now docker"
    echo "  加入组: sudo usermod -aG docker \$USER"
fi

# =============================================================================
# 完成
# =============================================================================
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║              安装完成！                          ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  1. 编辑 .env 填入 API Key                       ║"
echo "║     启动venv   source venv/bin/activate         ║"
echo "║  2. 验证环境:                                    ║"
echo "║     python3 scripts/validate_environment.py      ║"
echo "║  3. 对靶场测试:                                  ║"
echo "║     python3 scripts/run_agent.py \\               ║"
echo "║       --target 172.20.0.10                       ║"
echo "║  4. 指定国产模型:                                ║"
echo "║     python3 scripts/run_agent.py \\               ║"
echo "║       --target 172.20.0.10 --provider deepseek   ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
