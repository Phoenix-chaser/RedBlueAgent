# PentestAgent

LLM 驱动的自动化渗透测试 Agent。基于 ReAct(Reason → Act → Observe)范式,按 PTES 方法论自主完成信息收集、漏洞扫描、漏洞分析与利用,并生成测试报告。支持 DeepSeek / Kimi / 智谱 GLM / Claude / OpenAI 多家大模型。

> ⚠️ **仅限授权测试**。只能对你拥有或已获得书面授权的目标使用。未授权的渗透测试在多数司法管辖区属违法行为。

---

## 功能概览

- **多工具编排**:nmap、dirsearch、nikto、sqlmap、metasploit,统一调度
- **工具解释器层**:LLM 给出的松散参数自动归一化成合法命令行,工具输出自动解析成结构化数据(每个工具独立实现)
- **分阶段推进**:目标确认 → 信息收集 → 漏洞扫描 → 漏洞分析 → 漏洞利用 → 后渗透 → 报告生成
- **安全边界**:作用域校验、危险操作人工审批、全程审计日志
- **RAG 知识库**(可选):结合 CVE / exploit 知识增强决策
- **国产模型友好**:DeepSeek、Kimi、智谱开箱即用

---

## 环境要求

- **Kali Linux**(推荐)或 Ubuntu / Debian
- Python 3.10+
- 已安装的安全工具:nmap、nikto、sqlmap、dirsearch(Kali 预装),metasploit 可选
- 任一家大模型的 API Key

---

## 快速开始(一键脚本)

项目自带 [`setup_kali.sh`](setup_kali.sh),会自动完成:检查/安装安全工具 → 创建 Python 虚拟环境 → 安装依赖 → 生成 `.env` 模板 → 创建数据目录。

```bash
# 1. 克隆项目
git clone https://github.com/Phoenix-chaser/Pentestagent.git
cd Pentestagent

# 2. 运行一键安装脚本
bash setup_kali.sh
```

脚本做了什么:

| 步骤 | 内容 |
|------|------|
| 1 | 检查并安装 `nmap` `nikto` `sqlmap` `dirsearch` `curl` `git`(已装则跳过) |
| 2 | 检测 metasploit(可选) |
| 3 | 系统 Python 受保护时自动建 `venv` 虚拟环境,安装 `requirements.txt` |
| 4 | 从 `.env.example` 复制出 `.env` |
| 5 | 创建 `data/sessions` `data/reports` `data/knowledge_base` 等目录 |
| 6 | 检测 Docker(可选,用于内置靶场) |

### 填入 API Key

脚本生成 `.env` 后,编辑它并填入**任意一个**模型的 Key:

```bash
nano .env
```

```ini
# 三选一(国产模型,国内访问快)
DEEPSEEK_API_KEY=sk-xxxxxxxx        # https://platform.deepseek.com
MOONSHOT_API_KEY=sk-xxxxxxxx        # https://platform.moonshot.cn
ZHIPU_API_KEY=xxxxxxxx              # https://open.bigmodel.cn

LLM_PROVIDER=deepseek               # 与上面的 Key 对应
LLM_MODEL=deepseek-chat
```

> 国内网络建议保留 `.env` 末尾的 `HF_ENDPOINT=https://hf-mirror.com`,避免 RAG 嵌入模型下载失败。

### 验证环境

```bash
source venv/bin/activate                      # 如果脚本创建了 venv
python3 scripts/validate_environment.py
```

会逐项检查工具、依赖、API Key、数据目录是否就绪。

---

## 运行

对目标发起一次完整渗透测试:

```bash
source venv/bin/activate
python3 scripts/run_agent.py --target 192.168.1.100
```

指定模型提供商与具体模型:

```bash
# DeepSeek
python3 scripts/run_agent.py --target 192.168.1.100 --provider deepseek --model deepseek-chat

# Kimi 超长上下文
python3 scripts/run_agent.py --target 192.168.1.100 --provider moonshot --model moonshot-v1-128k

# 智谱 GLM 轻量版
python3 scripts/run_agent.py --target 192.168.1.100 --provider zhipu --model glm-4-flash
```

限定测试作用域(可多次指定):

```bash
python3 scripts/run_agent.py --target 192.168.1.100 \
    --scope 192.168.1.100 --scope 192.168.1.0/24
```

查看所有支持的模型及其配置状态:

```bash
python3 scripts/run_agent.py --list-providers
```

### 常用命令行参数

| 参数 | 说明 |
|------|------|
| `--target` | 目标 IP 或主机名(必填) |
| `--scope` | 允许测试的 IP/CIDR,可多次指定,默认仅 target |
| `--provider` | `anthropic` / `deepseek` / `moonshot` / `zhipu` / `openai` |
| `--model` | 模型名,留空用提供商默认 |
| `--no-interactive` | 关闭交互审批(危险操作自动拒绝) |
| `--config` | 指定 config.yaml 路径(默认当前目录) |
| `--list-providers` | 列出所有支持的模型 |

测试报告生成在 `data/reports/<session_id>/`。

---

## 内置靶场(可选,需 Docker)

```bash
cd docker
docker compose up -d target
# 靶场地址 http://localhost:8080
python3 ../scripts/run_agent.py --target 127.0.0.1 --scope 127.0.0.1
```

---

## 项目结构

```
agent/                  ReAct 主循环、LLM 工厂、提示词
modules/
  tool_invocation/      工具调用核心
    params/             输入解释器:LLM 参数 → 命令行(每个工具独立)
    parsers/            输出解释器:工具输出 → 结构化数据(每个工具独立)
    tools/              各工具薄封装
    invoker.py          按工具名分发
    executor.py         安全的子进程执行(无 shell=True)
  context_management/   状态管理、分层摘要、RAG 知识库
  task_planning/        阶段管理、攻击树
  report_generation/    报告生成
security/               作用域校验、危险操作审批、审计日志
scripts/                运行、环境校验、知识库构建入口
tests/unit/             单元测试(工具解释器 + 输出解析器)
```

工具解释器分为对称的两层,每个工具各自实现:
- **输入**([`params/`](modules/tool_invocation/params/)):把 LLM 给出的松散参数(URL 当 target、布尔写成字符串、端口写成列表等)归一化成合法命令行,非法参数返回可读错误回喂给 LLM。
- **输出**([`parsers/`](modules/tool_invocation/parsers/)):把 nmap XML、dirsearch/nikto JSON、sqlmap/metasploit 文本解析成结构化数据。

---

## 运行测试

```bash
source venv/bin/activate
python3 -m pytest tests/unit -q
```

---

## 安全与免责声明

本工具仅用于**已获授权**的安全测试与教育研究。危险操作(漏洞利用、`--os-shell` 等)默认需人工审批,全程记录审计日志。使用者需自行确保对目标拥有合法授权,任何未授权使用造成的后果由使用者承担。

