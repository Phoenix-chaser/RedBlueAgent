# toolout —— 领域适配数据（真实工具输出，构造即良性）

守卫部署在「工具输出」这个域里，而模板训练数据是「用户指令」分布：未经适配的检测器
在真实工具输出上误报率很高（实测 76%，见 `../README.md`）。这两份文件是领域适配闭环
的固定数据，让任何克隆跑 `bash run_all.sh` 都得到同一个模型。

| 文件 | 用途 |
|---|---|
| `extra_benign.jsonl` | 训练半集。`src/train.py` 在本地没有 `data/extra_benign.jsonl` 时自动并入 |
| `toolout_eval.jsonl` | 评测半集。`src/toolout_bench.py` 在本地没有划分时用它报告 FPR |

## 来源与协议

- 由 `scripts/collect_tool_outputs.py`（agent 镜像内，不调用 LLM）用 agent 自己的五个工具对
  内置靶场收集：VulnApp（172.20.0.10:5000）与 OWASP Juice Shop（172.20.0.13:3000），
  外加一次真实会话（`m1-glm54`）的存档。2026-11-24 收集。
- 取样口径与守卫一致（`toolout_bench.guard_view`）：解析结果里的字符串字段 + 原始输出前 400 字符。
- 划分（`toolout_bench.split_half`）：按工具分层，再按来源存档整份对半分——评测半集是训练时
  没见过的页面/扫描。单数存档多出的一份留给评测半集。
- 去重：同一行（工具 + 文本）只保留一次，避免跨半泄漏。
- 已知瑕疵：`extra_benign.jsonl` 里有 1 行不是工具输出，而是守卫自己的隔离占位符
  （收集时存档写在守卫之后；现在存档保存的是守卫之前的原样输出）。重训会让已发布的
  数字整体偏移，所以保留；守卫按平台标记规则隔离这一类文本，不经过检测器。
  `toolout_bench.py` 重新收集时会跳过内容是占位符的旧存档。
- 只有可信来源（内置靶场、自己的测试会话）的存档才能算「构造即良性」。来自不可信
  目标的存档可能带着注入内容，不能并入这两份文件。

## 重新收集（换靶场或工具版本后）

```bash
# agent 镜像内
python3 scripts/collect_tool_outputs.py --target 172.20.0.10 \
  --sqlmap-url http://172.20.0.10:5000/search?q=1 --sqlmap-url http://172.20.0.10:5000/user/1
# blueteam/ 下
python3 -m src.toolout_bench --sessions-dir ../data/sessions --split-half   # 划分 + 适配前 FPR
python3 -m src.train                                                        # 领域适配
python3 -m src.toolout_bench --sessions-dir ../data/sessions                # 适配后 FPR
```

本地生成的 `data/extra_benign.jsonl` / `data/toolout_eval.jsonl` 优先于这里自带的文件。
文件里出现的 `secret_key`、`admin:admin123` 等都是内置靶场源码里写死的演示值。
