# PentestAgent 自动渗透测试系统 — 原理解析

> 这个项目的核心是**设计一个 AI Agent 系统**，渗透测试是它的应用场景。
> 重点在于：怎么让 AI 可靠地、安全地、自主地完成一个多步骤任务。

---

## 1. 这个系统是什么

**PentestAgent = AI 大脑 + 渗透测试工具。**

你给它一个目标 IP，它像真正的渗透测试工程师一样工作：侦察 → 扫描 → 利用漏洞 → 写报告。

传统工具（nmap、sqlmap）只是"手脚"——你告诉它做什么它就做什么。PentestAgent 有"大脑"——用大语言模型（LLM）**自主决策**下一步该做什么。

---

## 2. 核心原理：ReAct 循环

### 一句话概括

```
思考 → 行动 → 观察 → 再思考 → 再行动 → ... 直到完成
```

### 为什么用 ReAct？

渗透测试天然是**探索-推理-行动**的循环——你不可能事先规划好所有步骤，每一步的结果都影响下一步的策略。

**举个例子：**

```
第1步：用 nmap 扫描 → 发现端口 5000 运行 Flask
第2步：推理 → Flask 登录页面可能有 SQL 注入
第3步：用 sqlmap 测试 → 发现注入成功！
第4步：推理 → 有了注入，能不能拿到数据库里的密码？
第5步：用 sqlmap --dbs → 拿到了 admin 密码
...
```

每一步的发现都决定了下一步做什么。这就是 ReAct 的核心——**边做边想，边想边做**。

---

## 3. 项目的三个核心问题

这个项目本质上在解决三个 Agent 工程问题：

| 问题 | 解决方案 |
|------|---------|
| 怎么让 AI 做出正确决策？ | Prompt 工程 |
| 怎么防止 AI 乱来？ | 状态机 + 自动推理 |
| 怎么防止 AI 闯祸？ | 安全护栏 |

下面按我实际做的工作来讲。

---

## 4. 我做了什么

### 4.1 设计 ReAct 循环引擎

**做了什么：** 实现了一个最多 200 轮的 Think-Act-Observe 循环。

**每轮做三件事：**

1. **Think**：把当前所有信息打包成 Prompt 发给 LLM，让它决定下一步
2. **Act**：解析 LLM 回答，经过安全检查后执行对应工具
3. **Observe**：把工具结果合并到全局状态，检查是否该进入下一阶段

**实际发给 LLM 的消息长这样：**

```
┌─ System Message ─────────────────────────────────────────┐
│ "你是一个渗透测试专家，自主决策，找到所有漏洞..."          │
│ 工具列表、输出格式要求、行为准则                          │
└──────────────────────────────────────────────────────────┘

┌─ Human Message ──────────────────────────────────────────┐
│ === 当前状态 ===                                          │
│ 目标：192.168.1.100                                      │
│ 阶段：漏洞扫描                                           │
│ 已发现：端口5000/Werkzeug，/login，/admin，/.env          │
│ 已发现漏洞：Development Server Exposed (HIGH)            │
│                                                          │
│ === 阶段指导 ===                                          │
│ 目标：扫描所有Web服务的漏洞                               │
│ 建议：运行nikto、运行dirsearch...                         │
│                                                          │
│ === 最近操作 ===                                          │
│ [第3轮] nmap service scan → 发现端口5000                  │
│ [第4轮] dirsearch → 发现15个路径                          │
│                                                          │
│ 请用 <thought><action> 格式回答。                         │
└──────────────────────────────────────────────────────────┘
```

**LLM 回答：**

```xml
<thought>
已经发现了多个Web路径，/login可能存在SQL注入。
应该用sqlmap测试登录表单。
</thought>
<action>
{"type": "tool", "tool": "sqlmap",
 "params": {"url": "http://192.168.1.100:5000/login",
            "data": "username=admin&password=test"}}
</action>
```

**核心循环伪代码：**

```
for 每一轮 in range(200):
    if 当前阶段卡住超过30轮: 强制推进

    # THINK
    消息 = 构建Prompt(状态快照 + 阶段指导 + 历史记录)
    思考, 行动 = 调用LLM并解析(消息)

    # ACT
    if 行动是"完成": break
    if 安全检查通过(行动):
        结果 = 执行工具(行动)
    else:
        结果 = "被安全系统拦截"

    # OBSERVE
    更新状态(思考, 行动, 结果)
    检查阶段推进()
    每10轮压缩一次历史()
```

---

### 4.2 设计 Prompt 提示词体系（最核心的工作）

Prompt 决定了 LLM 的决策质量。这是我花时间最多的部分。

**角色定义——告诉 LLM 它是谁：**

```
You are an expert penetration tester operating as an autonomous AI agent.
Your job is to systematically test the security of a target system and find ALL vulnerabilities.
```

三个关键词的设计意图：
- **"expert"**：让 LLM 主动探索，而不是被动等指令
- **"autonomous"**：告诉它自己做决策，不要停下来问人
- **"ALL"**：心理锚点，防止找到几个漏洞就满足

**四条行为准则——用心理学引导 LLM：**

```
1. BE THOROUGH: The target has 22 known vulnerabilities.
2. BE SYSTEMATIC: Do not skip steps.
3. BE SPECIFIC: When you find /login, analyze what vulnerability it might have.
4. BE PERSISTENT: If one approach fails, try another.
```

设计意图：
- "22"是具体数字——比"很多"更能激励彻底搜索
- "Do not skip"——防止 LLM 聪明过头跳步
- "try another"——防止一次失败就放弃（LLM 的"习得性无助"）

**输出格式——XML 包裹 JSON：**

```xml
<thought>自由推理...</thought>
<action>{"type":"tool","tool":"nmap","params":{...}}</action>
```

为什么这样设计：
- XML 标签用正则提取更可靠，JSON 出错不影响 thought 提取
- `<thought>` 给自由推理空间，`<action>` 要求严格结构化
- LLM 在标签内的格式遵从度显著更高

**阶段指导——每个阶段注入不同建议：**

```
CURRENT STAGE: Vulnerability Scanning
1. Run nikto against each web port
2. Run dirsearch against each web port
5. Do NOT skip dirsearch — it discovers most of the attack surface
```

**格式提醒放在消息末尾**——利用近因效应，LLM 对最后看到的内容遵从度最高。

**自适应提示——根据状态动态补充：**
- 发现的路径太少 → 追加"考虑用更多扩展名运行 dirsearch"
- 高危漏洞太少 → 追加"考虑检查更多路径的注入漏洞"

**容错处理——LLM 不完美：**
- 工具名放错字段 → 自动修正
- JSON 解析失败但含"finish" → 识别为完成信号
- 无 thought 标签 → 取前 500 字符兜底

---

### 4.3 设计七阶段状态机（约束 LLM 不乱来）

**为什么需要：** LLM 不可靠——可能跳步、卡住、或过早结束。

**我的方案：** 用有限状态机做确定性控制。

```
目标确认 → 信息收集 → 漏洞扫描 → 漏洞分析 → 漏洞利用 → 后渗透 → 报告
```

**每个转换都有前置条件：**

| 转换 | 条件 | 例子 |
|------|------|------|
| 目标确认 → 信息收集 | 有存活主机 | nmap 发现目标存活 |
| 信息收集 → 漏洞扫描 | 有开放端口 | nmap 发现端口 5000 |
| 漏洞扫描 → 漏洞分析 | 有路径或漏洞 | dirsearch 发现 /login |
| 漏洞利用 → 后渗透 | 有利用尝试 | sqlmap 测试了注入 |

**关键分工：**
- 状态机决定"什么时候"进入下一阶段
- LLM 决定"在当前阶段做什么"

类比：状态机是红绿灯，LLM 是驾驶员。你不会让驾驶员自己决定什么时候变灯。

**防卡死：** 单阶段超过 30 轮强制推进。

---

### 4.4 实现自动推理引擎（减轻 LLM 负担）

**做了什么：** 工具只报告"事实"，我写了规则引擎自动把事实升级为"安全知识"。

**例子：**

```
nmap 报告：端口5000运行Werkzeug httpd 2.0.3
  → 系统自动创建漏洞："Development Server Exposed"（HIGH）
  → 原因：Werkzeug是开发服务器，无速率限制，可能有调试模式

dirsearch 报告：/.env 返回 HTTP 200
  → 系统自动创建漏洞："Environment File Exposed"（HIGH）
  → 原因：.env文件通常包含数据库密码、API密钥

dirsearch 报告：/.git 返回 HTTP 200
  → 系统自动创建漏洞："Git Repository Exposed"（CRITICAL）
  → 原因：可以下载完整源代码和提交历史
```

内置了 **14 种危险服务**（telnet、redis、mongodb...）和 **15 种敏感路径**（/.env、/.git、/admin...）的规则。

**为什么这样做：** 这些是确定性知识——发现 Werkzeug 就一定是漏洞，不需要消耗 LLM 算力来判断。把确定性的事交给代码，把需要推理的事交给 LLM。

---

### 4.5 实现安全护栏（防止 AI 闯祸）

**为什么需要：** 这是一个自主执行 shell 命令的 AI 系统。没有安全边界就不能用于真实场景。

**三层防护：**

| 层 | 做什么 | 例子 |
|----|--------|------|
| 范围验证 | 每次执行前检查目标是否在授权范围内 | LLM想扫描8.8.8.8 → 拦截 |
| 危险操作审批 | 高风险操作暂停等人工确认 | metasploit exploit → 需要审批 |
| 审计日志 | 所有操作记录到文件 | 时间戳+工具+参数+结果 |

**命令注入防护：**

```python
# 安全：命令作为列表传递，分号不会被shell解释
subprocess.run(["nmap", "-sV", "192.168.1.100"])

# 危险：如果LLM参数中含 "; rm -rf /"，shell会执行！
subprocess.run("nmap -sV 192.168.1.100", shell=True)
```

我选择不使用 `shell=True`，从根本上杜绝命令注入风险。

---

### 4.6 实现上下文压缩（解决记忆有限问题）

**问题：** LLM 上下文窗口有限（DeepSeek ~65K tokens），200 轮交互会溢出。

**我的方案：分层记忆**

```
长期记忆（压缩摘要）：[第1-50轮的摘要] [第51-100轮的摘要]
短期记忆（完整记录）：[第101轮] [第102轮] ... [第120轮]
```

- 保留最近 20 轮完整记录（LLM 需要知道刚才做了什么）
- 更早的轮次用 LLM 压缩成摘要（保留关键发现，省略细节）
- 每 10 轮检查，token 超过 130K 时触发压缩

**压缩时的 Prompt：**
```
"Summarize the following actions, preserving ALL of:
 discovered services and versions, vulnerabilities found,
 failed attack paths, and key findings."
```

---

### 4.7 其他支撑工作

| 工作 | 做了什么 |
|------|---------|
| 多 LLM 支持 | 统一工厂适配 DeepSeek/Claude/Kimi/GLM/OpenAI，改 base_url 即可切换 |
| 漏洞去重 | 标题+组件前缀匹配，避免多工具重复记录同一漏洞 |
| 攻击树 | UCB1 算法平衡"深耕已知路径"和"探索新路径" |
| RAG 知识库 | ChromaDB 向量检索，补充 LLM 不知道的最新 CVE |
| 报告生成 | LLM 生成双语摘要+修复建议，输出 Markdown+JSON |
| 测试靶机 | Docker 搭建 22 个漏洞的 Flask 靶机验证系统能力 |
| 单元测试 | pytest 测试解析器、去重、状态机、攻击树 |
| 部署脚本 | Kali Linux 一键环境配置 |

---

## 5. 一次完整的运行流程

```
启动：python scripts/run_agent.py --target 192.168.1.100 --provider deepseek
  │
  ├─ 初始化：连接LLM → 创建安全组件 → 注册工具 → 组装循环引擎
  │
  ├─ 第1轮（目标确认）
  │   Think: LLM收到"目标192.168.1.100，阶段：目标确认"
  │   Act:   执行 nmap -sn 192.168.1.100
  │   Observe: 目标存活 → 满足条件 → 自动进入信息收集
  │
  ├─ 第2轮（信息收集）
  │   Think: LLM看到"主机存活但没有端口信息"
  │   Act:   执行 nmap -sV -sC -T4 192.168.1.100
  │   Observe: 发现端口5000/Werkzeug → 自动推理创建漏洞 → 进入漏洞扫描
  │
  ├─ 第3轮（漏洞扫描）
  │   Think: LLM看到"有Web端口，阶段指导说要运行nikto"
  │   Act:   执行 nikto -h 192.168.1.100 -p 5000
  │   Observe: 发现多个漏洞模式
  │
  ├─ 第4轮（漏洞扫描）
  │   Think: LLM决定枚举目录
  │   Act:   执行 dirsearch -u http://192.168.1.100:5000
  │   Observe: 发现 /login /admin /.env /.git
  │            → 自动推理创建3个漏洞 → 满足条件 → 进入漏洞分析
  │
  ├─ 第5轮（漏洞分析→利用）
  │   Think: "发现/login，可能有SQL注入，影响最大，先测试"
  │   Act:   执行 sqlmap -u ".../login" --data "username=admin&password=test"
  │   Observe: 发现SQL注入 → 创建CRITICAL漏洞
  │
  ├─ 第6-10轮（继续利用+后渗透）
  │   继续测试 XSS、文件上传、SSRF 等
  │
  ├─ LLM输出 {"type": "finish"}
  │
  └─ 生成报告：report.md（双语）+ report.json（结构化数据）
```

---

## 6. 核心设计原则

| 原则 | 为什么 |
|------|--------|
| Prompt 是灵魂 | 角色+准则+格式约束 = LLM 做出高质量可解析的决策 |
| 状态机约束 LLM | LLM 不可靠，确定性机制兜底 |
| 确定性知识不走 LLM | 规则引擎处理确定性推理，LLM 只做需要推理的事 |
| 安全边界不可少 | AI 执行命令必须有范围验证+审批+审计 |
| 分层记忆 | 上下文有限，压缩旧信息但保留关键发现 |
| 容错设计 | LLM 输出不完美，系统需要优雅兜底 |
| temperature=0.1 | 要稳定决策，不要创意 |

---

## 附录：源文件索引

| 文件 | 作用 |
|------|------|
| `agent/core.py` | 总指挥，组装所有组件 |
| `agent/react_loop.py` | ReAct 循环引擎 |
| `agent/prompts/system_prompt.py` | 系统提示词 |
| `agent/prompts/stage_prompts.py` | 阶段指导提示词 |
| `agent/llm_factory.py` | LLM 提供商工厂 |
| `modules/context_management/context_manager.py` | 状态合并 + 自动推理 |
| `modules/context_management/state_schema.py` | 全局状态数据模型 |
| `modules/context_management/summarizer.py` | 上下文压缩 |
| `modules/context_management/rag/knowledge_base.py` | RAG 向量检索 |
| `modules/task_planning/stage_manager.py` | 七阶段状态机 |
| `modules/task_planning/attack_tree.py` | UCB1 攻击树 |
| `modules/tool_invocation/invoker.py` | 工具路由 |
| `modules/tool_invocation/tools/*.py` | 5个工具实现 |
| `modules/tool_invocation/parsers/*.py` | 5个输出解析器 |
| `security/boundary.py` | 安全边界控制器 |
| `modules/report_generation/generator.py` | 报告生成 |
