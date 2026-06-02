# PentestAgent 模块与代码详解

> 从一个简单例子出发，跟着数据流走一遍系统，逐个讲解每个模块的作用。

---

## 从一个例子开始

假设你运行：

```bash
python scripts/run_agent.py --target 192.168.1.100 --provider deepseek
```

系统会自主完成渗透测试。我们跟着这个过程，看每个模块在什么时候、做什么事。

---

## 第一步：启动（agent/core.py）

`PentestAgent` 是总指挥，负责把所有模块组装到一起。

**它做了什么：**

```
1. 读取 config.yaml 配置文件
2. 创建 LLM 客户端（连接 DeepSeek）
3. 创建安全组件（范围验证 + 审批 + 审计）
4. 创建工具调用器（注册 5 个工具）
5. 创建状态管理器 + 压缩器 + 阶段管理器
6. 把以上所有组件组装成 ReAct 循环引擎
7. 初始化 PentestState（目标=192.168.1.100）
8. 启动循环
```

**关键代码片段：**

```python
# core.py 第 61-66 行：创建 LLM
self.llm = create_llm(
    provider=provider,      # "deepseek"
    model=model,            # "deepseek-chat"
    max_tokens=max_tokens,  # 8192
    temperature=temperature,# 0.1（低随机性）
)

# core.py 第 107-117 行：组装循环引擎
self.react_loop = ReActLoop(
    llm=self.llm,
    invoker=self.invoker,
    context_mgr=self.context_mgr,
    summarizer=self.summarizer,
    stage_manager=self.stage_manager,
    security=self.security,
    rag_kb=self.rag_kb,
    max_iterations=200,
    max_stage_iterations=30,
)
```

---

## 第二步：LLM 工厂（agent/llm_factory.py）

**作用：** 根据 provider 名字创建对应的 LLM 客户端。

**为什么需要：** 不同模型的 API 地址不同，但接口格式相同（都兼容 OpenAI 格式）。

```python
# 支持的模型
PROVIDER_CONFIGS = {
    "deepseek":  {"base_url": "https://api.deepseek.com/v1",      "default_model": "deepseek-chat"},
    "moonshot":  {"base_url": "https://api.moonshot.cn/v1",        "default_model": "moonshot-v1-32k"},
    "zhipu":     {"base_url": "https://open.bigmodel.cn/api/paas/v4", "default_model": "glm-4"},
    "anthropic": {"base_url": None,                                 "default_model": "claude-sonnet-4-6"},
    "openai":    {"base_url": None,                                 "default_model": "gpt-4o"},
}
```

**核心逻辑：** Anthropic 用专用库，其他都用 OpenAI 兼容接口（只改 base_url）。

---

## 第三步：进入循环（agent/react_loop.py）

这是整个系统的**心脏**。每一轮做三件事：

```
Think：构建 Prompt → 调用 LLM → 解析回答
Act：  安全检查 → 执行工具
Observe：合并结果 → 阶段推进 → 压缩检查
```

### Think：构建 Prompt

`_build_messages()` 方法把 6 个部分拼成一条消息发给 LLM：

```python
# react_loop.py 第 148-193 行
def _build_messages(self, state):
    parts = []
    
    # ① 压缩历史（之前发生了什么）
    if state.summary_chunks:
        parts.append("## Compressed History\n" + "\n".join(state.summary_chunks[-3:]))
    
    # ② 状态快照（现在知道什么）
    parts.append(self.context_mgr.build_state_snapshot(state))
    
    # ③ 阶段指导（这个阶段该做什么）
    parts.append(get_stage_prompt(state.current_stage.value))
    
    # ④ RAG 知识（相关 CVE 信息）
    if self.rag_kb:
        rag_context = self._get_rag_context(state)
        if rag_context:
            parts.append(f"## Relevant Security Knowledge\n{rag_context}")
    
    # ⑤ 最近 10 轮记录（刚才做了什么）
    if state.llm_turns:
        ...
    
    # ⑥ 格式提醒（按格式回答）
    parts.append(TOOL_FORMAT_REMINDER)
    
    human_content = "\n\n---\n\n".join(parts)
    return [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=human_content)]
```

### Think：解析 LLM 回答

LLM 回答类似：
```xml
<thought>需要确认目标是否存活。</thought>
<action>{"type":"tool","tool":"nmap","params":{"scan_type":"host_discovery"}}</action>
```

`_parse_llm_response()` 用正则提取：

```python
# react_loop.py 第 218-253 行
def _parse_llm_response(self, content):
    # 提取 <thought>
    thought_match = re.search(r"<thought>(.*?)</thought>", content, re.DOTALL)
    
    # 提取 <action> 中的 JSON
    action_match = re.search(r"<action>(.*?)</action>", content, re.DOTALL)
    action_dict = json.loads(action_match.group(1))
    
    # 容错：LLM 把工具名放在 type 字段
    if action_type not in {"tool", "finish", "wait"}:
        action_dict.setdefault("tool", action_type)
        action_type = "tool"
    
    return thought, ActionDecision(type=action_type, tool=..., params=...)
```

### Act：安全检查 + 执行工具

```python
# react_loop.py 第 112-128 行
if action.type == "tool" and action.tool:
    # 先过安全检查
    if not self.security.validate(action, state):
        observation = ToolResult(success=False, error_message="BLOCKED")
    else:
        # 通过后执行工具
        observation = self.invoker.invoke(action)
```

### Observe：更新状态 + 阶段推进

```python
# react_loop.py 第 135-141 行
state = self.context_mgr.update(state, thought, action, observation)
state = self.stage_manager.maybe_advance(state)

# 每 10 轮压缩一次
if iteration % 10 == 9:
    state = self.summarizer.summarize_if_needed(state)
```

---

## 第四步：System Prompt（agent/prompts/system_prompt.py）

**作用：** 定义 LLM 的角色、工具列表、输出格式、行为准则。

**关键设计：**

```
角色："expert penetration tester" + "autonomous" + "find ALL"
准则：BE THOROUGH（22个漏洞）/ SYSTEMATIC / SPECIFIC / PERSISTENT
格式：<thought>...</thought> <action>{JSON}</action>
规则：不越界、不跳步、不重复失败命令
```

这个 Prompt 在整个会话中**固定不变**，作为 System Message 发送。

---

## 第五步：阶段指导（agent/prompts/stage_prompts.py）

**作用：** 每个阶段注入不同的建议，引导 LLM 做正确的事。

```python
# 7 套阶段指导，根据当前阶段选择注入
STAGE_GUIDANCE = {
    "target_confirmation": "运行 nmap host_discovery 确认存活...",
    "information_gathering": "运行 nmap service 扫描所有端口...",
    "vulnerability_scanning": "运行 nikto + dirsearch，Do NOT skip dirsearch...",
    "vulnerability_analysis": "分析路径，推理可能的漏洞类型...",
    "vulnerability_exploitation": "用 sqlmap 测试注入，用 metasploit 利用...",
    "post_exploitation": "记录所有发现，准备报告...",
    "report_generation": "输出 finish...",
}
```

---

## 第六步：安全检查（security/）

### boundary.py — 安全边界控制器（总调度）

```python
def validate(self, action, state):
    # 第一层：范围验证
    target = action.params.get("target", "") or state.target
    if not self.scope_validator.is_in_scope(target, state.scope):
        self.audit_logger.log_violation("SCOPE_VIOLATION", action)
        return False
    
    # 第二层：危险操作检测
    if self.approval_gate.is_dangerous(action):
        approved = self.approval_gate.request_approval(action)
        return approved
    
    # 通过
    self.audit_logger.log_allowed(action)
    return True
```

### scope_validator.py — 范围验证

```python
def is_in_scope(self, target, scope):
    host = self._extract_host(target)  # 从 URL 提取主机名
    for scope_entry in scope:
        if host == scope_entry:           return True  # 精确匹配
        if scope_entry.startswith("*"):                # 通配符
            if host.endswith(scope_entry[1:]): return True
        if "/" in scope_entry:                          # CIDR
            if ip_address(host) in ip_network(scope_entry): return True
    return False
```

### approval_gate.py — 危险操作审批

```python
ALWAYS_REQUIRE_APPROVAL = [
    (r"metasploit", r"exploit/"),       # Metasploit exploit 模块
    (r"sqlmap", r"--os-shell"),         # sqlmap 获取 shell
    (r"sqlmap", r"--file-write"),       # sqlmap 写文件
    (r"nmap", r"--script.*(exploit|brute|dos)"),  # nmap 危险脚本
]

def request_approval(self, action):
    if self.interactive:
        answer = input("Approve? [y/N]: ")
        return answer in ("y", "yes")
    return False  # 非交互模式默认拒绝
```

### audit_logger.py — 审计日志

所有操作记录到 JSONL 文件：
```json
{"timestamp": "2025-01-15T10:30:05", "event": "ALLOWED", "tool": "nmap", "params": {...}}
{"timestamp": "2025-01-15T10:35:30", "event": "VIOLATION", "type": "SCOPE_VIOLATION", "tool": "nmap"}
```

---

## 第七步：工具执行（modules/tool_invocation/）

### invoker.py — 工具路由器

```python
class ToolInvoker:
    def __init__(self):
        self.tools = {
            "nmap": NmapTool(),
            "nikto": NiktoTool(),
            "dirsearch": DirsearchTool(),
            "sqlmap": SqlmapTool(),
            "metasploit": MetasploitTool(),
        }
    
    def invoke(self, action):
        tool = self.tools.get(action.tool)
        return tool.run(action.params)
```

### tools/base_tool.py — 统一接口

```python
class BaseTool:
    name: str
    timeout: int = 120
    parser = None
    
    def run(self, params):
        cmd = self.build_command(params)           # 子类实现：参数→命令
        raw = SubprocessExecutor.run(cmd, self.timeout)  # 执行
        parsed = self.parser.parse(raw.stdout, raw.stderr) if self.parser else {}
        return ToolResult(tool=self.name, command=" ".join(cmd), parsed=parsed, ...)
    
    def build_command(self, params) -> list[str]:
        raise NotImplementedError
```

### tools/nmap_tool.py — Nmap 命令构建

LLM 说 `{"scan_type": "service"}`，代码翻译成具体参数：

```python
def build_command(self, params):
    cmd = ["nmap", "-oX", "-"]  # 始终输出 XML
    
    scan_type = params.get("scan_type", "service")
    if scan_type == "quick":           cmd += ["-T4", "-F"]
    elif scan_type == "service":       cmd += ["-sV", "-sC", "-T4"]
    elif scan_type == "full":          cmd += ["-sV", "-sC", "-p-", "-T4"]
    elif scan_type == "host_discovery": cmd += ["-sn"]
    
    # 脚本白名单：防止 LLM 幻觉出不存在的脚本
    if scripts := params.get("scripts"):
        valid = [s for s in scripts.split(",") if s in VALID_SCRIPTS]
        if valid:
            cmd += [f"--script={','.join(valid)}"]
    
    cmd.append(target)
    return cmd
```

### executor.py — 子进程执行器

```python
class SubprocessExecutor:
    @staticmethod
    def run(cmd, timeout=120):
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            # 注意：没有 shell=True！防止命令注入
        )
        return RawOutput(stdout=result.stdout, stderr=result.stderr, returncode=result.returncode)
```

---

## 第八步：结果合并 + 自动推理（modules/context_management/context_manager.py）

工具执行完后，`ContextManager` 负责把结果合并到全局状态。

### update() — 记录一轮交互

```python
def update(self, state, thought, action, observation):
    state.total_iterations += 1
    
    # 记录这一轮的交互
    turn = LLMTurn(iteration=..., thought=thought, action_tool=..., observation=...)
    state.llm_turns.append(turn)
    
    # 如果工具有结构化结果，合并到状态
    if isinstance(observation, ToolResult) and observation.parsed:
        self._merge_tool_result(state, observation)
    
    return state
```

### _merge_nmap() — 合并 nmap 结果 + 自动推理

```python
def _merge_nmap(self, state, parsed):
    # 14 种危险服务规则
    DANGEROUS_SERVICES = {
        "telnet":  (HIGH,     "Telnet Service Exposed",  "未加密远程访问..."),
        "redis":   (CRITICAL, "Redis Service Exposed",   "通常无认证，可RCE..."),
        "mongodb": (CRITICAL, "MongoDB Exposed",         "可能无认证访问..."),
        ...  # 共 14 种
    }
    
    # 13 种开发服务器规则
    DEV_SIGNATURES = {
        "werkzeug": (HIGH, "Development Server Exposed", "无速率限制，可能有调试模式..."),
        "django":   (HIGH, "Development Server Exposed", "Django 开发服务器..."),
        ...  # 共 13 种
    }
    
    for host_data in parsed["hosts"]:
        for port_data in host_data["ports"]:
            # 记录端口和服务
            state.hosts[ip].services.append(ServiceInfo(...))
            
            # 自动推理：危险服务
            if svc_name in DANGEROUS_SERVICES:
                state.add_vulnerability(Vulnerability(title=..., severity=...))
            
            # 自动推理：开发服务器
            for sig in DEV_SIGNATURES:
                if sig in version.lower():
                    state.add_vulnerability(Vulnerability(title=..., severity=...))
```

### _merge_dirsearch() — 合并 dirsearch 结果 + 敏感路径推理

```python
def _merge_dirsearch(self, state, parsed):
    # 15 种敏感路径规则
    SENSITIVE_PATHS = {
        "/.env":    (HIGH,     "Environment File Exposed",  "可能含数据库密码..."),
        "/.git":    (CRITICAL, "Git Repository Exposed",    "可下载完整源代码..."),
        "/admin":   (MEDIUM,   "Admin Panel Accessible",    "验证是否有认证..."),
        "/backup":  (HIGH,     "Backup Directory Exposed",  "可能含源代码..."),
        ...  # 共 15 种
    }
    
    for item in parsed["paths"]:
        path = item["path"]
        state.web_paths.append(path)
        
        # 自动推理：敏感路径
        for keyword, (sev, title, desc) in SENSITIVE_PATHS.items():
            if keyword in path.lower():
                state.add_vulnerability(Vulnerability(title=title, severity=sev, ...))
```

### 漏洞去重（state_schema.py 第 162 行）

```python
def add_vulnerability(self, vuln):
    for existing in self.vulnerabilities:
        # 标题相同？
        if existing.title.lower() != vuln.title.lower():
            continue
        # 组件前缀匹配？
        norm_old = existing.affected_component.lower().rstrip("/")
        norm_new = vuln.affected_component.lower().rstrip("/")
        if norm_old == norm_new or norm_old.startswith(norm_new) or norm_new.startswith(norm_old):
            return  # 去重，不添加
    
    self.vulnerabilities.append(vuln)  # 没有重复，添加
```

---

## 第九步：阶段推进（modules/task_planning/stage_manager.py）

每轮 Observe 后检查是否该进入下一阶段：

```python
# 6 个前置条件函数
def _can_advance_to_info_gathering(state):
    return any(h.is_alive for h in state.hosts)  # 有存活主机

def _can_advance_to_vuln_scanning(state):
    return any(h.services for h in state.hosts)  # 有开放端口

def _can_advance_to_vuln_analysis(state):
    return bool(state.web_paths) or bool(state.vulnerabilities)  # 有路径或漏洞

# 自动推进
def maybe_advance(self, state):
    current = state.current_stage
    next_stage, condition = STAGE_TRANSITIONS[current]
    if condition(state):
        state.current_stage = next_stage
    return state

# 强制推进（防卡死）
def force_advance(self, state):
    next_stage, _ = STAGE_TRANSITIONS[state.current_stage]
    state.current_stage = next_stage
    return state
```

---

## 第十步：上下文压缩（modules/context_management/summarizer.py）

当历史太长时，压缩旧轮次：

```python
class HierarchicalSummarizer:
    def summarize_if_needed(self, state, token_budget=130_000):
        estimated = self.estimate_tokens(state)
        if estimated < token_budget:
            return state  # 还没到阈值
        
        # 保留最近 20 轮，压缩更早的
        turns_to_compress = state.llm_turns[:-20]
        chunk_summary = self._compress_turns(turns_to_compress)
        
        state.summary_chunks.append(chunk_summary)
        state.llm_turns = state.llm_turns[-20:]
        return state
    
    def _compress_turns(self, turns):
        # 用 LLM 压缩自己说过的话
        prompt = (
            "Summarize the following actions, preserving ALL of: "
            "discovered services, vulnerabilities, failed paths, key findings."
        )
        response = self.llm.invoke([HumanMessage(content=prompt + turns_text)])
        return response.content
```

---

## 第十一步：报告生成（modules/report_generation/generator.py）

循环结束后，生成最终报告：

```python
class ReportGenerator:
    def generate(self, state, session_dir):
        # 1. 计算指标
        metrics = self._compute_metrics(state)
        
        # 2. 用 LLM 生成双语摘要
        prompt = f"""Write both English and Chinese versions of:
        1. Executive summary (3-5 sentences)
        2. Remediation recommendations
        Target: {state.target}
        Vulnerabilities: {metrics.total_vulns_found}
        Critical: {metrics.critical_count}, High: {metrics.high_count}..."""
        
        summary = self.llm.invoke([HumanMessage(content=prompt)])
        
        # 3. 输出 Markdown + JSON
        self._write_markdown_report(state, metrics, summary, session_dir)
        self._write_json_report(state, metrics, session_dir)
```

---

## 全局状态（modules/context_management/state_schema.py）

所有模块共享的数据结构：

```python
class PentestState(BaseModel):
    # 基本信息
    session_id: str
    target: str                    # "192.168.1.100"
    scope: list[str]               # ["192.168.1.100"]
    current_stage: PentestStage    # 当前阶段
    
    # 发现的数据
    hosts: list[HostInfo]          # 主机+端口+服务
    web_paths: list[str]           # /login, /admin, /.env ...
    vulnerabilities: list[Vulnerability]  # 漏洞列表
    credentials: list[dict]        # 获取的凭证
    
    # 过程追踪
    llm_turns: list[LLMTurn]       # 每轮交互记录
    summary_chunks: list[str]      # 压缩后的历史
    
    # 统计
    total_iterations: int
    stages_completed: list[str]
```

---

## 数据流总结

```
用户输入 --target 192.168.1.100
    ↓
core.py 组装所有模块，初始化 PentestState
    ↓
react_loop.py 开始循环（最多 200 轮）
    ↓
┌─────────────────────────────────────────────────────────┐
│ THINK                                                   │
│   _build_messages() 拼接 6 部分 Prompt                   │
│   调用 LLM API                                          │
│   _parse_llm_response() 提取 thought + action           │
├─────────────────────────────────────────────────────────┤
│ ACT                                                     │
│   security/boundary.py 安全检查                          │
│   invoker.py 路由到对应工具                              │
│   nmap_tool.py build_command() 翻译参数为命令            │
│   executor.py subprocess.run() 执行                     │
│   nmap_parser.py 解析 XML 输出                          │
├─────────────────────────────────────────────────────────┤
│ OBSERVE                                                 │
│   context_manager.py update() 记录交互                   │
│   context_manager.py _merge_nmap() 合并结果+自动推理     │
│   state_schema.py add_vulnerability() 去重              │
│   stage_manager.py maybe_advance() 检查阶段推进          │
│   summarizer.py summarize_if_needed() 压缩检查          │
└─────────────────────────────────────────────────────────┘
    ↓ （循环直到 LLM 输出 finish 或达到 200 轮）
    ↓
generator.py 生成双语报告 → report.md + report.json
```

---

## 文件索引

| 文件 | 作用 | 在流程中的位置 |
|------|------|--------------|
| `agent/core.py` | 总指挥，组装模块 | 第一步 |
| `agent/llm_factory.py` | 创建 LLM 客户端 | 第二步 |
| `agent/react_loop.py` | ReAct 循环引擎 | 第三步 |
| `agent/prompts/system_prompt.py` | 系统提示词 | 第四步 |
| `agent/prompts/stage_prompts.py` | 阶段指导 | 第五步 |
| `security/boundary.py` | 安全边界控制器 | 第六步 |
| `security/scope_validator.py` | 范围验证 | 第六步 |
| `security/approval_gate.py` | 危险操作审批 | 第六步 |
| `security/audit_logger.py` | 审计日志 | 第六步 |
| `modules/tool_invocation/invoker.py` | 工具路由 | 第七步 |
| `modules/tool_invocation/tools/base_tool.py` | 工具统一接口 | 第七步 |
| `modules/tool_invocation/tools/nmap_tool.py` | Nmap 命令构建 | 第七步 |
| `modules/tool_invocation/executor.py` | 子进程执行 | 第七步 |
| `modules/context_management/context_manager.py` | 状态合并+自动推理 | 第八步 |
| `modules/context_management/state_schema.py` | 全局状态+去重 | 第八步 |
| `modules/task_planning/stage_manager.py` | 阶段状态机 | 第九步 |
| `modules/context_management/summarizer.py` | 上下文压缩 | 第十步 |
| `modules/report_generation/generator.py` | 报告生成 | 第十一步 |
