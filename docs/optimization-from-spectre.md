# RedBlueAgent（前身 Pentestagent）优化方案 —— 借鉴 SPECTRE 工程实践

> 基准版本：Pentestagent @ `62640f6`（2026-11-08 同步）；SPECTRE @ `2c88924`（lalalala5678/spectre，main 分支浅克隆）
> 性质：**分析方案文档，未改动任何代码**。文中所有 Pentestagent 论断均给出 `文件:行号`，SPECTRE 实践均注明其仓库内出处，可直接按图索骥。

---

## 1. 两个项目对比总览

| 维度 | Pentestagent (RedBlueAgent) | SPECTRE |
|---|---|---|
| 定位 | 红蓝一体 LLM 渗透测试学术项目（本科毕设演化） | 自治多智能体渗透作战控制台 |
| 形态 | 单进程同步 CLI，CPU-only | 多服务分布式平台（caddy→gateway→runtime→Temporal） |
| 语言栈 | Python（零重依赖，LLM 走纯 urllib） | Node.js 后端 + React 前端 + Python 网关 |
| 智能体 | 单 ReAct 循环 × PTES 七阶段状态机 | 14 席位：orchestrator 编排 + recon/exploit/c2/report 等子智能体 |
| 强项 | 入站提示注入防御（三级检测）、出站 scope 校验、评测方法学、测试覆盖关键安全属性 | WAL 断点续跑、Temporal 编排、限速退避、工具协议纪律、QA 验收流程、部署工程化 |
| 短板 | 可靠性设施几乎为零（见 §3） | 单机资源占用重、依赖 Temporal/Node 生态 |
| 代码量 | ~10,045 行 Python | backend/src ~10,400 行 mjs + console + gateway + deploy |

**核心判断**：两者的差距不在算法或安全设计，而集中在两处——**可靠性编排层**（断点续跑/重试/优雅停机）与**工具协议纪律**（截断/空结果/反馈质量）。这两块恰好是 SPECTRE 沉淀最深、且大部分**不依赖其生态**、可平移到单机 Python CLI 的部分。

---

## 2. SPECTRE 可借鉴实践清单

以下按「可移植性」排序，来源均注明 SPECTRE 仓库内位置。

### 2.1 WAL / 断点续跑（可 1:1 移植，纯算法+系统调用）

来源：`backend/src/persist.mjs`（172 行，全仓唯一 Wal 类）、`backend/agent-runtime.mjs`

| 机制 | SPECTRE 实现 | 出处 |
|---|---|---|
| 日志格式 | append-only JSONL，每条 `{t, d}` 判别式结构（sess/msg/meta/bus/墓碑） | persist.mjs |
| 持久化契约 | `append()` 同步 write + **fsync 完成才返回**；断电最多丢在飞 LLM 运行、永不丢转录 | persist.mjs:74-81 |
| 撕裂容忍 | 最后一行 JSON 解析失败→视为 torn tail 丢弃；中间行损坏→fatal（前缀保证） | persist.mjs:89-111 |
| 墓碑 compact | WAL 是唯一真相源；compact 只删墓碑相关记录；拟删 >50% 时对账拒绝 | persist.mjs:123-164 |
| 实例锁 | `.instance.lock` 用 `open(wx)` 独占创建写 PID，防双实例覆写 | agent-runtime.mjs:39-84 |
| 启动重放 | readAll → 重放会话/消息/总线 → 热更配置 → 腰斩检测续跑 | agent-runtime.mjs:86-136 |
| 腰斩回合续跑 | 重放后扫描「末条消息=工具结果且近 1h 活跃」= 被杀回合，注入 `[系统续跑]` | agent-runtime.mjs:847-873 |
| 优雅停机 | SIGTERM→排空在飞回合（110s 上限）→compact→封存 | agent-runtime.mjs:974-993 |

### 2.2 LLM 韧性：重试/退避/自愈（可 1:1 移植）

来源：`backend/src/pi.mjs`、`backend/src/sessions.mjs`

- **请求级重试**：统一 streamFn 包装注入 `maxRetries=3`、超时 300s，配置缺失 fail-fast（pi.mjs:355-388）
- **账户级退避门**：429 触发指数退避 `5s×2^strikes` 封顶 60s，所有后续调用先过闸门；冷却后随机错峰释放（pi.mjs:29-67，config.mjs:100-101）
- **瞬态/永久错误分流**：429/超时重试，401/余额不足不进冷却——「冷却救不了空账户」（sessions.mjs:1244-1254）
- **回合中途死亡自愈**：stopReason=error 且可重试→自动续跑 ≤2 次、60s 退避，上下文全保留（sessions.mjs:1255-1281）

### 2.3 工具协议纪律（AGENTS.md 规范，可 1:1 移植）

来源：`AGENTS.md`（143 行）+ 落地于 `backend/src/tools.mjs`、`pi.mjs`

| 原则 | 含义 | SPECTRE 落地 |
|---|---|---|
| 禁静默截断 | 截断必打标 `[已截断:N/M 字符]`，单源函数 `clipMarked` | pi.mjs:490-496 |
| seq 截断补全 | 截断内容可凭 seq 取回全文，三态标记（可取/不可恢复/未截断） | tools.mjs:371-388 |
| 空结果诊断 | 零命中附分类计数 + 「过滤过窄 vs 库本身为空」判定 + 参数误用提示 | tools.mjs:317-336 |
| 总数披露 | 「匹配 N 条，显示最新 M 条」；导航行放正文前（截断免疫） | tools.mjs:344-393 |
| 服务端推断 | 常漏的必填字段改 Optional，按失败信号>部分完成>非空>兜底推断，回执注明「由系统推断」 | tools.mjs:447-478 |
| 诚实回执 | 无判定输出不得伪装成驳回；writer-lost 显式「本回执不是判定」 | agent-runtime.mjs:599-617 |
| append-only 修订链 | 修订=新事件（revises=原 seq），原版永不覆盖；text 骤降>30% 显式警告 | agent-runtime.mjs:730-777 |
| 历史教训表 | AGENTS.md 内置防回归清单（status 遗漏硬拒、静默截断等 7 条事故） | AGENTS.md |

### 2.4 编排与并发护栏（思想可移植，引擎不搬）

来源：`backend/workflows.mjs`、`activities.mjs`、`tools.mjs`

- **分波滚动窗口**：WAVE=7 并发上限，席位完成即补位——起因是十键全并发 4/10 被 429 击杀（workflows.mjs:129-168）
- **报告门**：任务收尾必有报告，催办 ≤2 次，仍无则系统代拟 no-result——「跑过但无发现」与「没跑」必须可区分（workflows.mjs:404-440）
- **LLM activity 显式不可重试**：`maximumAttempts:1`，重试会重打 agent 造成重复回合（workflows.mjs:46-49）
- **activity 唯一副作用点**：workflow 只经 activity 出站，每次副作用进 history 可观测（activities.mjs 文件头）

### 2.5 配置与部署工程（模式可移植）

- **config 单源 + 冻结**：`config.mjs` 唯一配置源，PORT_MAP 冻结，占位值（`change-me`）拒绝启动（config.mjs:38-43）
- **.env 最小化**：仅 INTERNAL_TOKEN；LLM 配置走设置页 + WAL 持久化
- **systemd 加固**：Restart=always + StartLimitIntervalSec=0、ProtectSystem=strict、ReadWritePaths 白名单（deploy/systemd/）
- **一键部署幂等脚本**：setup.sh 含端口归属裁决（改系统态前先查端口持有者）、密钥自动生成（deploy/setup.sh）

### 2.6 QA 文化（流程可移植）

- **accept-gate 独立验收**：开发者会话不得自证通过，须全新会话只读交付物执行；清理不留痕=验收无效（docs/accept-gate/SKILL.md）
- **零框架测试**：35 个 test.mjs 用 `node --test`，gateway 用 stdlib unittest；**测试直接 import 生产纯函数模块**（tests/helpers.mjs 注释）
- **事故编号注释**：几乎每个关键分支带事故编号（R7-F5、loop41-#10）——注释本身就是「失败模式→机制」决策清单

### 2.7 其他值得借鉴的原则

- **范围合规第一性**（docs/ARCHITECTURE.md §6.9）：任务完成是最高优先级，唯一例外是范围合规——越界永远 fail
- **探测阶梯**「同等信息增益取最轻」：被动优先，可写入信息收集阶段提示词
- **沙箱环境白名单**：子进程 env 仅透传 14 键，API Key/Token 绝不进 `/proc/self/environ`（sandbox/exec-env.mjs:165-181）

---

## 3. Pentestagent 工程现状与差距

### 3.1 可靠性（差距最大维度）

| # | 现状 | 出处 |
|---|---|---|
| R1 | 状态只在启动时落盘一次，循环中从不保存；`_save_state` 已存在但未被循环调用；无任何恢复代码，`session_id` 注释写着 "for resuming" 实际不存在 | agent/core.py:175、core.py:199-203、core.py:140 |
| R2 | 进程被 kill = 全部进度丢失；KeyboardInterrupt 仅生成部分报告 | agent/core.py:180-181 |
| R3 | LLM 异常只记错误 turn 后 continue，无重试/退避——连续失败会烧光 200 轮迭代预算 | agent/react_loop.py:85-98 |
| R4 | llm_kernel 无重试、无流式、无 token 计数，超时 300s 硬编码 | agent/llm_kernel.py:55 |
| R5 | 全仓库无并发（asyncio/threading 零命中），工具串行阻塞 | 全仓库 grep |
| R6 | 审计日志单文件追加，无轮转、无会话分文件 | security/audit_logger.py:25-26 |

### 3.2 正确性 / 安全缺陷（P0 修复对象）

| # | 现状 | 出处 |
|---|---|---|
| B1 | **scope 校验盲区**：出站校验只取 `params.get("target")`，缺失回退 `state.target`（恒在范围内）；而 dirsearch/sqlmap 的目标参数键是 `url`——**这两个工具的实际目标不参与 scope 校验** | security/boundary.py:29；agent/prompts/system_prompt.py:34,43 |
| B2 | **系统提示词注入靶场先验**：「The target has 22 known vulnerabilities」——对任意真实目标都是错误先验（对应内置靶场的 22 漏洞清单） | agent/prompts/system_prompt.py:16 |
| B3 | **守卫降级无审计**：ContextGuard 模型加载失败→仅一条控制台打印→返回 None→守卫直通；无审计事件、无 strict 失败模式——事后无法从日志追溯防线何时失效 | security/context_guard.py:107-109 |
| B4 | **scope 空列表放行一切** | modules/../security/scope_validator.py:17-19 |
| B5 | 审批门用 `input()` 阻塞 stdin，非交互模式一律拒绝，无法自动化 | security/approval_gate.py:61 |
| B6 | **工具输出静默截断**：`raw_stdout[:50000]`、`raw_stderr[:5000]` 无任何标记——LLM 不知道内容被截 | modules/tool_invocation/tools/base_tool.py:59-60 |
| B7 | Prompt 构建时 observation 截 400 字符、thought 截 200，同样无截断标记 | agent/react_loop.py:197 附近 |
| B8 | **审批门模式失配**（实施 P0-5 时发现）：危险模式正则匹配字面 `--script` 文本，但 params 是结构化字典——`{"script": "ssh-brute"}` 永不含 `--script` 字样，nmap 危险脚本从未触发审批；已加语义检查修复 | security/approval_gate.py:39-48（修复前） |
| B9 | **报告服务器 3.10/3.11 语法炸裂**（实施 P2-1 时 ruff 发现）：`report_server.py` 在 f-string 内使用反斜杠转义（PEP 701 前非法），文件在 3.10/3.11 上 import 即 SyntaxError；已修复 | scripts/report_server.py:834、892（修复前） |

### 3.3 死配置 / 死代码 / 文档漂移

| # | 现状 | 出处 |
|---|---|---|
| D1 | config.yaml `tools:` 整节、`security.dangerous_patterns`、`security.auto_approve_scan_only`、`llm.context_window_budget/summarization_threshold` 无代码读取 | config.yaml |
| D2 | .env.example 中 REQUIRE_APPROVAL_FOR_EXPLOITS、LOG_LEVEL、SESSIONS_DIR 等 8 项无代码消费；core.py 实际只读 3 个 LLM 变量 | agent/core.py:56-58 |
| D3 | `AUTO_APPROVABLE` 表定义后从未使用 | security/approval_gate.py:21-24 |
| D4 | README 称「7 场景 ×2=14 次运行」，trap_lab.py 实际 8 个场景→16 次 | README.md:104 vs fusion/trap_lab.py:34-43 |
| D5 | .gitignore 残留旧布局 `redteam/data/` 路径 | .gitignore:21-24 |
| D6 | attack_tree.py（UCB1 攻击树）完整实现且有 9 个测试，但 react_loop 从未调用——孤立组件 | modules/task_planning/attack_tree.py；react_loop.py 全文无引用 |
| D7 | 工具超时全部类属性硬编码，config 不生效 | base_tool.py:24 等 |
| D8 | RAG 默认不可用（要求向量库目录已存在），无显式告警 | agent/core.py:74 |

### 3.4 工程设施缺失

- 无 CI（无 `.github/`）、无 lint/类型检查配置、无 pyproject.toml 打包（测试和 fusion 用 `sys.path.insert` 注入路径，fusion/drill.py:24-26）
- tests/integration/ 与 tests/fixtures/ 为空目录
- 无 API 服务/任务提交接口；report_server.py 是 1,106 行内联 HTML 的只读查看器
- 覆盖盲区：react_loop 主循环（除 2 个融合点）、llm_kernel、approval_gate、audit_logger、报告生成无测试

---

## 4. 分层优化方案

每项含：**问题 → SPECTRE 对应做法 → 落地设计 → 工作量 → 验收标准**。

### P0 正确性 / 安全缺陷修复（合计 ~5 人天，互相独立可并行）

> **实施状态（2026-11-08）：P0 全部 7 项已完成，89 用例全绿（基线 66 + 新增 23）。**
> 实施中额外发现并修复 **B8**（见下）——`is_dangerous` 的危险模式正则匹配字面 `--script` 标志，而实际 params 是结构化字典 `{"script": "ssh-brute"}`，**nmap 危险脚本从未真正触发过审批门**；已在 `approval_gate.is_dangerous` 增加语义检查修复。

#### P0-1 修复 scope 校验 url 参数盲区 〔0.5 天〕
- **问题**：B1——dirsearch/sqlmap 以 `url` 为目标参数键，绕过 scope 校验。这在红队工具里是**出站安全边界的实质漏洞**：LLM 幻觉出的任意 URL 可被扫。
- **SPECTRE 对照**：范围合规唯一例外原则——越界永远 fail（docs/ARCHITECTURE.md §6.9）。
- **落地**：`SecurityBoundaryController.validate`（security/boundary.py:27）改为收集动作的全部目标类参数（`target`/`url`/`host` 白名单键），逐一过 `is_in_scope`，任一越界即拒；`TargetScopeValidator` 增加 URL 解析（`urllib.parse.urlsplit` 取 hostname，现有实现只剥 scheme）。
- **验收**：新增单测：url 指向 scope 外域名时 validate 返回 False 且落 VIOLATION 审计；scope 内 url 放行。

#### P0-2 移除系统提示词的「22 个漏洞」先验 〔0.1 天〕
- **问题**：B2——对真实目标注入错误先验，直接干扰 LLM 判断（可能凑数或提前放弃）。
- **落地**：system_prompt.py:16 改为与目标无关的表述（如 "Discover as many vulnerabilities as evidence supports"）；若需保留靶场提示，挪到 config 可选项。
- **验收**：全仓库 grep 无 "22 known vulnerabilities"；现有 66 测试不回归。

#### P0-3 守卫降级显式化 〔0.5 天〕
- **问题**：B3——入站防线失效只有一条易被淹没的控制台打印，审计日志中无痕。
- **SPECTRE 对照**：占位密钥拒绝启动、docker 降级显式告警非静默（config.mjs:38-43、container.mjs:25-35）。
- **落地**：`ContextGuard.create()`（context_guard.py:84）加载失败时：①控制台红色横幅；②写 `GUARD_DEGRADED` 审计事件（audit_logger 已有 GUARD_EVENT 类型可扩展）；③非交互模式下支持 `--strict-guard` 直接 fail-fast。
- **验收**：删除模型文件复现场景，横幅+审计事件均出现；恢复模型后守卫正常。

#### P0-4 scope 空列表 fail-closed 〔0.2 天〕
- **问题**：B4——未配置 scope = 无限制。
- **落地**：`is_in_scope` 遇空 scope 返回 False（scope_validator.py:17-19）；CLI 增加显式 `--no-scope` 逃生门并落审计。
- **验收**：单测覆盖空 scope 拒绝路径。

#### P0-5 审批门非交互化 〔1 天〕
- **问题**：B5——`input()` 阻塞使自动化不可行；非交互一律拒绝等于功能不可用。
- **落地**：审批策略三模式（config/env）：`reject`（默认，现行为）/ `auto-approve-scan`（只放行扫描类，激活 D3 的 AUTO_APPROVABLE 死代码）/ `file`（审批请求写入 `data/approvals/<sid>/pending/<id>.json`，审批人创建同名 `decisions/<id>.json` 应答，门轮询直至超时默认拒绝，借 SPECTRE「DM 排队」思想）。审批决策全部落审计（已有）。**实施顺序（定案）：reject 与 auto-approve-scan 先行，file 模式随后**。
- **验收**：三种模式单测；file 模式端到端：危险动作挂起→写应答→继续执行。

#### P0-6 截断打标（工具协议第一原则的最小落地） 〔0.5 天〕
- **问题**：B6/B7——静默截断是 SPECTRE AGENTS.md 明示的 bug 形态。
- **落地**：新增单源函数 `clip_marked(text, limit) -> str`（返回 `text[:limit] + f"[已截断:{limit}/{total}字符]"`，对应 clipMarked，pi.mjs:490-496）；base_tool.py:59-60 与 react_loop.py 的 thought/observation 截断全部改走它。
- **验收**：单测：超长输出带标记、短输出无标记；标记含原始总长。

#### P0-7 死配置与文档漂移清理 〔1 天〕
- **问题**：D1/D2/D3/D4/D5/D7——死键误导使用者，文档与代码不一致损害可信度。
- **落地**：①删 config.yaml/.env.example 死键（或激活：工具超时改从 config 读取）；②AUTO_APPROVABLE 并入 P0-5 或删除；③README 7vs8 场景修正；④.gitignore 清理旧路径。
- **验收**：config.yaml 与 .env.example 每个键可指出消费代码位置；README 数字与代码一致。

### P1 可靠性（合计 ~10 人天；P1-1 是地基，先做）

#### P1-1 事件溯源 + 断点续跑 〔3 天〕 ★核心
> **实施状态（2026-11-08）：已完成。** `agent/session_log.py`（EventLog fsync WAL + 撕裂尾行容忍 + 中间损坏 fatal + 原子快照 + SessionLock 陈旧锁回收 + replay_into_state 重放）+ react_loop 事件钩子（action 写前落账 / observation 自包含 / stage_advance / finish / 每 20 轮与阶段推进时快照）+ core `run/resume/_execute` 重构（`--session-id` 复用即恢复，腰斩回合注入系统续跑注记，重复动作哈希跨重启保留）。9 个新测试。
- **问题**：R1/R2——kill 即全丢；这是与 SPECTRE 差距最大单项。
- **SPECTRE 对照**：WAL 全套（§2.1）——JSONL append-only、fsync 前缀保证、torn-tail 容忍、实例锁、腰斩续跑。
- **落地**（Python 单机版，不必搬 Temporal）：
  1. `data/sessions/<sid>/events.jsonl`：每轮追加 `{"t": "action"|"observation"|"llm_error"|"stage_advance"|"guard", "d": {...}}`，写后 `flush()+os.fsync()`（写前落账：先记事件再喂 LLM，对应 SPECTRE「WAL 先于广播」bus.mjs:109-116）
  2. torn-tail 容忍：恢复时最后一行 JSON 解析失败→丢弃并告警（不 fatal）
  3. 快照：每阶段推进 + 每 20 轮写 `state_snapshot.json`（Pydantic `model_dump_json`，`_save_state` 已有，core.py:199 直接复用）
  4. `scripts/run_agent.py --resume <sid>`：读最近快照 + 重放增量事件重建 state/历史 turn
  5. 实例锁：`<sid>.lock` 用 `os.open(O_CREAT|O_EXCL)` 写 PID，防双开（对应 agent-runtime.mjs:39-84）
  6. 腰斩检测：恢复时末事件为 action 无 observation→历史注入 `[系统续跑:上一动作未观察到结果]` 提示 LLM 复查（对应 :847-873）
- **验收**：集成测试：跑 N 轮→`kill -9`→`--resume` 继续→报告完整；事件文件无撕裂（或撕裂行被容忍）；双开被锁拒绝。

#### P1-2 优雅停机 〔1 天〕
> **实施状态（2026-11-08）：已完成（随 P1-1）。** SIGTERM→KeyboardInterrupt 路径：快照落盘 + SESSION_END 审计 + 部分报告 + 锁释放（`core._execute`）。
- **问题**：R2——仅处理 KeyboardInterrupt。
- **SPECTRE 对照**：SIGTERM→排空在飞工具调用→快照→封存（agent-runtime.mjs:974-993）。
- **落地**：signal handler 捕获 SIGTERM/SIGINT：①等待当前子进程工具（有超时上限）②写快照+`SESSION_END(reason=signal)` 审计 ③生成部分报告退出码 143。
- **验收**：`kill <pid>`（SIGTERM）后快照可 `--resume`；报告含已完成阶段。

#### P1-3 LLM 重试 + 退避 + 回合自愈 〔2 天〕
> **实施状态（2026-11-08）：已完成。** `llm_kernel`：瞬态错误（429/5xx/超时/网络抖动）指数退避重试 ≤3（5s×2ⁿ 封顶 60s），永久错误（401/402/403）立即失败附可行动提示；429 触发账户级冷却闸门（跨 invoke 生效，退避睡眠后清闸避免双重等待）。`react_loop`：连续失败 ≥2 注入系统注记、≥5 中止循环保快照（`--session-id` 可恢复），成功即清零。7 个新测试。
- **问题**：R3/R4。
- **SPECTRE 对照**：§2.2 全套——瞬态/永久分流、指数退避门、回合死亡自动续跑 ≤2。
- **落地**：`MinimalLLMClient.invoke`（llm_kernel.py:76）内置：429/5xx/超时→重试 ≤3、`5s×2^n` 封顶 60s（识别智谱 1302 等平台特定码）；401/余额类永久错误→不重试、直接 fail-fast 可行动报错（「检查 API Key/余额」）。react_loop 的 LLM 异常分支增加连续失败计数，≥2 次自动注入 `[系统注记:LLM 临时故障已重试]` 后继续，避免静默烧迭代预算。
- **验收**：单测 mock 429 序列→退避重试后成功；mock 401→立即失败带明确指引。

#### P1-4 工具输出协议改造（AGENTS.md 全量落地） 〔2 天〕
> **实施状态（2026-11-08）：已完成。** ①空结果诊断：五类工具 0 结果/未成功时附 DIAGNOSTIC 行（原因假设 + 下一步指引 + 「0 结果是有效结论」）②总数披露导航行（放正文前，截断免疫）③全文存档：`EventLog.save_tool_output` → `data/sessions/<sid>/tool_outputs/<iter>_<tool>.txt`，`ToolResult.archive_path` 字段渲染 `[完整原始输出已存档: ...]` ④命名等级推断：sqlmap `level/risk` 接受 low/medium/high/... 名字（命令行数字即回执；目标参数永不推断的安全约束已写入注释）。13 个新测试。
- **问题**：B6/B7 之外，空结果与总数披露缺失——LLM 面对空/截断输出只能瞎猜。
- **SPECTRE 对照**：§2.3 空结果诊断（tools.mjs:317-336）、总数披露+导航行前置（:344-393）、seq 补全三态（:371-388）。
- **落地**：
  1. 空结果诊断：各 parser 返回空 findings 时附诊断串（如 nmap：「0 端口开放——host 可能离线/被防火墙过滤；建议核对 target 或尝试 -Pn」，参数误用显式指出）
  2. 总数披露：dirsearch/nikto 合并进上下文时「发现 N 条，已并入前 M 条」
  3. seq 补全：`ToolResult` 保留完整 raw 输出（已有），截断标记附 `完整输出见 data/sessions/<sid>/tool_outputs/<iter>_<tool>.txt`——LLM 无需补读也知晓全文去处（单机版 seq 的最廉价等价物）；**可选扩展（定案：P1 暂缓）**：新增 `read_output` 只读工具让 LLM 按迭代号取回全文，是否值得占一个工具位待 P1-7 攻击树接入后评估
  4. 服务端推断：参数解释器对可推断的非法参数不再硬拒——如 `level=high` 推断为 sqlmap `--level=3` 时在错误串中说明「已按 high 推断为 --level=3，如非本意请显式指定」（对应 tools.mjs:447-478 推断回执）。**安全约束（定案）：仅允许对与目标无关的参数（level/risk/threads/extensions 等）推断；`target`/`url`/`host` 类目标参数永不推断，非法即拒**——SPECTRE 的推断面向查询工具，本项目面向攻击工具，推断错方向的代价不对称
- **验收**：单测：空结果含诊断；截断含路径指引；推断含回执说明。

#### P1-5 审计日志会话化 + 先落盘 〔1 天〕
> **实施状态（2026-11-08）：已完成。** `AuditLogger.set_session(sid, sessions_dir)` → `<sessions_dir>/<sid>/audit.jsonl`（会话前事件留在全局文件），`core._execute` 会话启动时切换并打印路径。轮转未做（单会话文件体量小）。
- **问题**：R6——单文件无轮转。
- **落地**：audit.log → `data/sessions/<sid>/audit.jsonl`（按会话分文件），启动时横幅打印审计路径；写后 flush（与 P1-1 同一 fsync 策略）。
- **验收**：多会话互不混写；审计事件先于后续动作可见。

#### P1-6 压缩按预算触发 + 配置激活 〔0.5 天〕
> **实施状态（2026-11-08）：预算配置已激活**（`llm.context_window_budget` → summarizer 构造参数，随 P0-7 完成）；「按 token 估算实时触发」部分待做（当前仍为每 10 轮触发检查）。
- **问题**：每 10 轮固定触发（react_loop.py:160）、预算 130,000 硬编码（summarizer.py:32）。
- **落地**：改为每次 update 后按 token 估算超阈值触发；阈值从 config `llm.context_window_budget` 读取（激活 D1 死键）。
- **验收**：长会话下 prompt 尺寸有界；config 改阈值生效。

#### P1-7 attack_tree 接入决策循环 〔1.5 天〕
> **实施状态（2026-11-08）：建议制已完成。** 利用/后渗透阶段：未利用漏洞按严重度（critical=1.0/high=0.8/medium=0.5/low=0.3）自动播种为根节点；`_build_messages` 注入 `Attack Plan (advisory, UCB1-ordered)` 段 + `建议优先尝试` 候选；候选动作失败→标记 FAILED 并 `backtrack()` 换兄弟节点，成功→SUCCEEDED；新发现的漏洞（如 sqlmap 确认注入）自动续播。**strict 强约束开关未做**（待靶场 A/B 数据决定是否值得），归入 P2 备选。5 个新测试。
- **问题**：D6——UCB1 攻击树已实现已测试却是死代码；阶段内动作选择纯靠 LLM 自由发挥+重复检测兜底。
- **落地**：react_loop 在漏洞利用/后渗透阶段把 attack_tree 候选注入阶段提示词（「建议优先尝试:…」），动作失败时 `backtrack()`；不强制约束 LLM（建议制，保留自主性），**config 提供 `agent.attack_tree_strict` 开关可切换强约束**（默认关），跑靶场 A/B 对照后再定默认值。
- **验收**：单测：候选注入存在；融合测试不回归；靶场跑一轮观察利用阶段行为变化。

### P2 可选架构演进（按价值排序，互相独立）

#### P2-1 CI + 打包 〔2 天，建议最先做〕
> **实施状态（2026-11-08）：已完成。** pyproject.toml（pip install -e .，extras：dev/report-server/rag/server；tests/conftest.py 统一导入路径，清除 14 处 sys.path.insert 样板）；GitHub Actions（.github/workflows/ci.yml：ruff lint + pytest matrix 3.10–3.13）；ruff 首扫即发现 **B9**——report_server.py 在 f-string 内用反斜杠转义（PEP 701 前语法），**该文件在 3.10/3.11 上是 SyntaxError**，已修复（HTML 实体 + 表达式外提）；requirements.txt 改为 `-e .[dev]` 薄壳（依赖单一来源）。
- GitHub Actions：pytest matrix（3.10–3.12）+ ruff lint + 主分支保护；借 SPECTRE「tests import 生产纯函数」思想，把 react_loop 的 `_build_messages`/`_parse_llm_response` 抽成可测纯函数。
- pyproject.toml：包名 pentestagent，`pip install -e .` 后消灭全部 `sys.path.insert`（drill.py:24-26、各测试文件）。
- 对应 SPECTRE：35 个测试 + lint 豁免台账（docs/lint-exemptions.md）+ ARCHITECTURE 行数表被测试锁定。

#### P2-2 并发工具执行 〔2 天〕
> **实施状态（2026-11-08）：已完成（parallel 动作协议）。** `{"type":"parallel","actions":[...]}`（顶层/params 内两种形状均宽容解析）一次下发 2-3 个独立扫描：逐子项 重复检测/scope/危险检查（危险动作禁入并行批次——审批必须逐个走），全部子动作 **WAL 写前落账** 后 ThreadPoolExecutor(≤3) 执行，按提交顺序回放保证状态与日志确定性，空批次诚实回执。system_prompt/漏洞扫描阶段提示引导使用。6 个新测试。
- 信息收集阶段 nmap/nikto/dirsearch 用 `ThreadPoolExecutor` 并行（subprocess 天然适合）；护栏：并发上限 3（对应 SPECTRE WAVE=7 滚动窗思想，workflows.mjs:129-168）+ P1-3 的退避门防 API 429。
- 验收：靶场信息收集阶段墙钟时间下降 ≥40%；结果合并顺序无关（`_merge_*` 已按 canonical 去重，天然适配）。

#### P2-3 FastAPI 服务化 + SSE + 审批 API 〔5 天〕
> **实施状态（2026-11-08）：已完成（最小可用）。** `server/app.py`（create_app 工厂，依赖注入 sessions_dir/token/agent_runner）：POST /api/sessions（后台线程执行会话，409 冲突检测）、GET /api/sessions（列表）、GET /api/sessions/{sid}（快照）、GET .../events?since=N&follow=（SSE tail events.jsonl，finish 自动收流，撕裂行容错重读）、GET/POST .../approvals（file 审批模式的 HTTP 桥，复用 P0-5 协议）；单一 Bearer Token（PENTESTAGENT_TOKEN，占位值拒启）；`scripts/serve.py` 入口 + `server/static/index.html` 最小控制台（会话列表/实时事件流/审批按钮）。extras `server`。9 个新测试 + curl 冒烟（401/200/SSE/HTML/404）通过。
- `POST /sessions`（提交目标）/ `GET /sessions/{id}/events`（SSE 进度流）/ `POST /approvals/{id}`（异步审批，替代 P0-5 的文件轮询）。
- 对应 SPECTRE 分层思想（gateway 认证→runtime 业务）但**单进程**即可：FastAPI + bearer token（借 INTERNAL_TOKEN 思想：.env 一个 token，无多用户 scrypt——单机不需要）。report_server.py 的 1,106 行内联 HTML 前端可由一个简单 React/静态页替代，或保留现状仅换数据源。
- 前端最小可用：会话列表 + 实时事件流 + 审批按钮。

#### P2-4 探测阶梯写入阶段提示词 〔0.5 天〕
> **实施状态（2026-11-08）：已完成。** 信息收集阶段加入侦察纪律（同等信息增益取最轻、禁止重扫已知、生产目标最小噪声）；漏洞扫描阶段提示 parallel 批量下发。
- 信息收集阶段提示词加入 SPECTRE 资产测绘第一性原则的适配版：「同等信息增益取最轻探测；被动优先」（docs/ARCHITECTURE.md §6.9）。对真实目标测试时显著降低噪声。

#### P2-5 RAG 修活或显式禁用 〔0.5 天〕
> **实施状态（2026-11-08）：已完成（显式指引）。** 知识库目录不存在时打印可行动指引（构建命令/关闭方法），加载异常不再静默吞掉。
- core.py:74 的向量库存在性检查失败时给出可行动指引（「运行 scripts/setup_knowledge_base.py 或 config 关闭 rag」），而非静默 None。

---

## 5. 不照搬清单（明确说不，附理由与替代）

| SPECTRE 组件 | 不搬理由 | Pentestagent 替代 |
|---|---|---|
| **Temporal 编排引擎** | 单机单会话 CLI 引入分布式引擎 = 运维成本碾压收益；SPECTRE 自己也标注 temporal-dev 仅是开发态 | 进程内 ReAct 循环 + P1-1 事件日志恢复；Temporal 的价值点（分波、报告门）只在多智能体场景有意义 |
| **多智能体总线 / [DM] / orchestrator** | 单 agent 无跨席位通信需求；bus 的幂等去重、水位头等机制对象不存在 | 漏洞去重已有 `add_vulnerability` 前缀去重（state_schema.py:162-178），够用 |
| **WAL 三代轮换 + 墓碑 compact** | 单会话 ≤200 轮，events.jsonl 体量小，compact 无必要 | 保留 torn-tail 容忍 + 实例锁即可；轮换作为可选加固留待会话数增长后 |
| **多用户 scrypt 认证 / caddy / systemd×6** | 单机单用户场景过度设计 | P2-3 若做服务化：单 bearer token + 可选单 systemd 单元 |
| **Node / pi-agent-core 生态** | 语言栈不换；llm_kernel 零依赖是本项目优点 | 保持 Python 标准库路线 |
| **React 完整控制台** | P2 阶段按需最小实现，不必对齐 14 席位控制台复杂度 | 单页静态或极简 React |

---

## 6. 实施路线图

```
阶段一 P0（~1 周，7 项互相独立）
  ├─ P0-1 scope 盲区 ●────────────→ 出站安全闭环
  ├─ P0-4 空 scope fail-closed ────┘
  ├─ P0-2 移除 22 漏洞先验
  ├─ P0-3 守卫降级显式化
  ├─ P0-5 审批非交互化
  ├─ P0-6 截断打标（clip_marked 单源函数，P1-4 复用）
  └─ P0-7 死配置清理

阶段二 P1（~2-3 周，P1-1 先行）
  P1-1 事件溯源+断点续跑（地基）
   → P1-2 优雅停机（依赖事件日志）
   → P1-5 审计会话化（同一 fsync 策略）
  P1-3 LLM 退避（独立）  P1-4 工具协议（依赖 P0-6 的 clip_marked）
  P1-6 压缩预算化（独立）  P1-7 attack_tree 激活（独立）

阶段三 P2（可选，P2-1 建议无条件先做）
  P2-1 CI+打包 → 保护后续所有开发
  P2-2 并发工具（收益立竿见影）
  P2-4/P2-5 提示词与 RAG 小改
  P2-3 服务化+前端（需求驱动，最后做）
```

**总工作量估算**：P0 ≈ 5 人天；P1 ≈ 10 人天；P2 ≈ 10 人天（P2-1/2/4/5 共 5 天 + P2-3 5 天）。

**回归保护**：每项落地前先补对应单测（SPECTRE accept-gate 精神：修复者不得只靠自证）；现有 66 用例全绿是每个 PR 的门槛；P1-1 完成后 `kill -9 → resume` 端到端测试进 CI。

---

## 7. 附录：SPECTRE 机制 → 本方案条目对照速查

| SPECTRE 机制 | 出处 | 本方案条目 | 移植深度 |
|---|---|---|---|
| WAL fsync 契约 / torn-tail / 实例锁 / 腰斩续跑 | persist.mjs、agent-runtime.mjs | P1-1 | 1:1 |
| SIGTERM 排空停机 | agent-runtime.mjs:974-993 | P1-2 | 适配 |
| LLM 重试/429 退避门/瞬态永久分流/回合自愈 | pi.mjs、sessions.mjs | P1-3 | 1:1 |
| clipMarked 截断打标 | pi.mjs:490-496 | P0-6 | 1:1 |
| 空结果诊断 / 总数披露 / seq 补全 | tools.mjs:317-393 | P1-4 | 适配（seq→文件路径指引） |
| 服务端推断+回执 | tools.mjs:447-478 | P1-4.4 | 适配 |
| 范围合规永远 fail | ARCHITECTURE.md §6.9 | P0-1/P0-4 | 原则 |
| 探测阶梯最轻优先 | ARCHITECTURE.md §6.9 | P2-4 | 原则 |
| 分波并发护栏 WAVE=7 | workflows.mjs:129-168 | P2-2 | 思想 |
| INTERNAL_TOKEN 最小密钥面 | config.mjs、.env.example | P2-3 | 思想 |
| 占位值拒绝启动 | config.mjs:38-43 | P0-3（strict-guard） | 思想 |
| 事故编号注释 / 历史教训表 | 全仓 / AGENTS.md | 建议长期采纳 | 文化 |
| Temporal / 总线 / 多用户认证 / systemd×6 | — | §5 不搬 | — |
