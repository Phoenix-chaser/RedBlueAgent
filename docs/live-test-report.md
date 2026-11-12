# 全链路实测报告（Live Test Report）

> 日期：2026-11-12 ｜ 环境：Ubuntu 26.04 宿主 + 全容器化（agent 镜像 + 内置 VulnApp 靶场）
> LLM：智谱 GLM-5.3（Coding Plan 端点 `open.bigmodel.cn/api/coding/paas/v4`，OpenAI 兼容）
> 配置：`config.live.yaml`（30 迭代上限 / 压缩阈值 6000）｜ 会话数据均在 `data/`（不入库）

## 环境

```
宿主 ── docker_pentest_net (172.20.0.0/24)
  ├─ docker-target-1   内置靶场 VulnApp（172.20.0.10:5000，22 个故意漏洞）
  └─ pentest-agent     pentestagent:live 镜像（nmap 7.98 / nikto / dirsearch 0.5.0 /
                       sqlmap 1.10.4 / python3.14 + 本项目；msf 故意不装，验证错误回喂）
```

## 矩阵与结果

| # | 场景 | 结果 | 关键证据 |
|---|---|---|---|
| M1 | 完整链路 | ✅ | 12 迭代完成全部 7 阶段；**真实 SQL 注入闭环**：sqlmap 确认 `/login` POST 参数布尔盲注 + SQLite 时间盲注 → 枚举 3 表 → dump 数据；2 漏洞、双语报告生成；parallel 批次 ×2；10/11 工具观察带存档指引 |
| M2 | 断点续跑 | ✅ | `kill -9` 于 seq=7 → `--session-id` 恢复（`会话恢复: 重放 0 个事件（快照 seq=7，日志 seq=7）`）→ 续跑至 finish，**6 漏洞**（dirsearch 修复后攻击面扩大 3 倍）；二次恢复被**实例锁正确拒绝**（`会话 m2-kill 正在被 PID 106 运行`） |
| M3 | 优雅停机 | ✅ | SIGTERM → `Interrupted. Saving snapshot and generating partial report...` → 部分报告（4 迭代/6 漏洞）+ `SESSION_END` 审计 + 快照 seq=日志尾 + 锁释放 |
| M4 | 服务化 | ✅ | `serve.py` + Bearer Token；`POST /api/sessions` 后台线程起会话；**SSE 实时流**逐条推送 8 事件；审批 HTTP 桥：pending 列表 → `POST .../approvals/demo-001` → gate 轮询格式的 decisions 文件；负路径（无 token 401 / 未知请求 404）正确 |
| M5 | 容错路径 | ✅ | msfconsole 未装 → 可读错误回喂，LLM 自行推断"dead end"转向；`[ContextGuard][警告] 守卫降级为直通（joblib 缺失）`横幅 + 恢复指引 + GUARD_STRICT 提示；`[RAG] 知识库目录不存在`显式指引；401 fail-fast（含"检查 API Key"提示）在 key 误配时即触发 |

另有两项计划外验证：BrokenPipe（stdout 管道被关闭）下进程幸存续跑；`pkill` 误伤、docker 单文件挂载 inode 陈旧等环境坑（见下）。

## 实测发现并已修复的问题

| # | 问题 | 根因 | 修复 |
|---|---|---|---|
| L1 | **dirsearch 全军覆没**（`no such option: --format`） | dirsearch 0.5.0 移除 `--format`（改 `-O/--output-formats`），且 JSON report 字段改为 `url`/`contentLength` 驼峰；`-o /dev/stdout` 在 0.5 上挂死 | `DirsearchTool.run` 重写：版本探测选 flag、report 落临时文件读回喂 parser、CLI 输出仅作 fallback；parser 兼容两代字段（modules/tool_invocation/tools/dirsearch_tool.py 等 3 文件） |
| L2 | **恢复后重复动作防线丢失** | `collect` 哈希只来自快照之后的 tail 事件，快照之前的 action 哈希丢失——旧动作可原样重跑 | 新增 `collect_action_hashes`（全量事件扫描）替换 tail 收集（agent/session_log.py、agent/core.py） |

两处均附回归测试（142 用例全绿）。这印证了 SPECTRE 的教训表文化：**实测是唯一能让"看起来对"变成"确实对"的环节**。

## 环境备忘（坑与解法）

- **单文件 bind mount inode 陈旧**：宿主 nano 保存 `.env` 替换 inode，容器内仍是旧内容 → 重建容器重新挂载（或挂目录）
- **Dockerfile.agent 初版漏 uvicorn**：`pip install -e .` 未带 extras；应装 `-e ".[server]"`（已修）
- `serve.py` 默认绑 127.0.0.1（安全默认）；容器场景需 `PENTESTAGENT_HOST=0.0.0.0`
- 宿主对容器 root 创建的 `data/` 子目录无写权限——审批文件注入走 `docker exec`

## 复现命令

```bash
# 1. 靶场 + agent 容器
cd docker && docker compose up -d target
docker build -f docker/Dockerfile.agent -t pentestagent:live --network host .   # 见 Dockerfile.agent 头部完整参数
docker run -d --name pentest-agent --network docker_pentest_net \
  -v $PWD/data:/app/data --env-file .env pentestagent:live

# 2. 完整链路（M1）
docker exec pentest-agent python3 scripts/run_agent.py \
  --config config.live.yaml --target 172.20.0.10 --session-id m1 --no-interactive

# 3. 崩溃恢复（M2）
docker exec pentest-agent sh -c 'p=$(pgrep -f "m1"); kill -9 $p'
docker exec pentest-agent python3 scripts/run_agent.py \
  --config config.live.yaml --session-id m1 --no-interactive   # 自动识别为恢复

# 4. Web 控制台 + 审批（M4）
docker exec -d pentest-agent sh -c 'cd /app && PENTESTAGENT_TOKEN=<token> \
  SECURITY_APPROVAL_POLICY=file PENTESTAGENT_HOST=0.0.0.0 python3 scripts/serve.py'
# 浏览器 http://<容器IP>:8095/ ，右上角填 token
```

## 结论

P0–P2 十九项改造在真实 LLM + 真实工具 + 真实靶场上全链路可用；实测反哺修复 2 个真实缺陷（L1/L2）。agent 具备了在无 Kali 的普通 Linux 上以容器形态执行授权渗透测试的能力。
