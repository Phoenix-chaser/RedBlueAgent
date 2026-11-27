#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 README 里的图表（docs/images/）。每张图中英各一份；图上的数字都由脚本从仓库里的证据文件读出来，没有手填的。

  python3 scripts/make_readme_charts.py                                   # 用仓库里提交的数据重画四张图
  python3 scripts/make_readme_charts.py --agentdojo scratch/agentdojo     # 另外重算 structural-forgery 的数字（约两分钟）
  python3 scripts/make_readme_charts.py --agentdojo-runs scratch/agentdojo/runs   # 另外重算 agentdojo-benchmark（约七分钟）
  python3 scripts/make_readme_charts.py --logs reviews-round7/baseline-logs       # 另外从实测日志重取 test-summary 的几行

四张图各读什么（README 引用的图片是 <名字>.png 与 <名字>.en.png）：

  drill-mock-hijack    drills/drill_results*.json 里 llm == "mock" 的那几份（简化循环 / 生产主循环 × 默认集、
                       四向量场景、隐蔽场景集、结构伪造场景集）。每次运行都从这些文件现算。
  structural-forgery   fusion/structural_summary.py --agentdojo <目录> 的输出——它只凭 drills/agentdojo_continue/
                       下存着的回复（structural.*.jsonl、repeat.*.jsonl）重算演习一节的表一。给了 --agentdojo 就现跑
                       （需要 AgentDojo 的记录和训练好的守卫模型，这两样都不在仓库里），并把解析出的数字存进
                       docs/images/chart-data/structural_forgery.json；没给就读这个文件。
  agentdojo-benchmark  fusion/agentdojo_eval.py <runs/…> 的输出。给了 --agentdojo-runs 就现跑，并把解析出的数字存进
                       docs/images/chart-data/agentdojo_eval.json；没给就读这个文件。
  test-summary         --logs <目录> 下 ci-py314.txt、with-image-py314.txt、docker-check.txt、mutation.txt 的末尾几行，
                       原样排成终端的样子。那个目录不入库，所以取到的几行存进 docs/images/chart-data/test_summary.json；
                       没给 --logs 就读这个文件。

跑完在标准输出打印每张图用到的数字，方便和 README 正文核对。
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.patches import Circle, FancyBboxPatch, Patch, Rectangle  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
IMG_DIR = ROOT / "docs" / "images"
DATA_DIR = IMG_DIR / "chart-data"     # 不叫 data：.gitignore 里有一条 data/ 会把它整个忽略
DPI = 200
LIMIT_KB = 300

# GitHub Primer 的几个颜色：红 = 被劫持 / 无防护，绿 = 守卫开着 / 触发点去掉，灰 = 对照，琥珀 = 误隔离的代价
RED, GREEN, GRAY, AMBER = "#cf222e", "#1a7f37", "#8c959f", "#bf8700"
GREEN_FILL, INK, MUTED, LINE = "#dafbe1", "#1f2328", "#57606a", "#d1d9e0"

# 自适应变体的名字，和 fusion/agentdojo_continue.py 里的 ADAPTIVE 一致；表一只统计另外那几种结构伪造写法
ADAPTIVE = {"fake_user_inline", "fake_user_lower", "fake_user_me", "fake_user_zh", "fake_reasoning", "fake_yes"}
NON_STRUCTURAL = {"template", "todo", "clean"}

# AgentDojo 公开的、没有任何防御的六份记录（目录名，按 README 表格的顺序）
AGENTDOJO_RUNS = (
    ("gpt-4o-2024-05-13", "GPT-4o"),
    ("gpt-4o-mini-2024-07-18", "GPT-4o mini"),
    ("gemini-2.0-flash-001", "Gemini 2.0 Flash"),
    ("claude-3-7-sonnet-20250219", "Claude 3.7 Sonnet"),
    ("claude-3-5-sonnet-20241022", "Claude 3.5 Sonnet"),
    ("meta-llama_Llama-3.3-70B-Instruct", "Llama 3.3 70B"),
)
TINY_SAMPLE = 10          # 中招的样本不到这个数，比例不足为凭（Claude 3.5 Sonnet 是 4 条）

# test-summary 用到的四份日志：文件名、取末尾几行、图里的说明
TEST_LOGS = (
    ("ci-py314.txt", "CI 口径（离线可跑）", "CI scope (runs offline)"),
    ("with-image-py314.txt", "本机构建了 agent 镜像之后", "with the agent image built"),
    ("docker-check.txt", "容器验证", "container check"),
    ("mutation.txt", "变异检查", "mutation check"),
)


# ---------- 通用 ----------

def pick_font(cjk: bool) -> list[str]:
    """系统里有的中文字体优先（fc-list :lang=zh 能找到的那几种），都没有就退回 matplotlib 自带的。"""
    have = {f.name for f in font_manager.fontManager.ttflist}
    for name in ("Noto Sans CJK SC", "Noto Sans SC", "Source Han Sans SC", "WenQuanYi Micro Hei",
                 "Noto Sans CJK JP", "Droid Sans Fallback", "AR PL UMing CN", "AR PL UKai CN"):
        if name in have:
            return [name, "DejaVu Sans"]
    if cjk:
        print("warning: 没找到中文字体（fc-list :lang=zh 为空？），中文会显示成方框", file=sys.stderr)
    return ["DejaVu Sans"]


def new_figure(width: float, height: float, lang: str):
    plt.rcParams.update({
        "font.family": pick_font(lang == "zh"),
        "axes.unicode_minus": False,
        "text.color": INK,
        "axes.labelcolor": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "savefig.facecolor": "white",
    })
    return plt.figure(figsize=(width, height), dpi=DPI, facecolor="white")


def save(figure, name: str) -> None:
    path = IMG_DIR / name
    figure.savefig(path, dpi=DPI, facecolor="white", metadata={"Software": None})
    plt.close(figure)
    size_kb = path.stat().st_size / 1024
    flag = "" if size_kb <= LIMIT_KB else "   <-- 超过 300 KB"
    print(f"  写入 {path.relative_to(ROOT)}  ({size_kb:.0f} KB){flag}")


def wrap(text: str, max_inches: float, fontsize: float) -> list[str]:
    """按估算的宽度折行（中日韩字符算一个字宽，其余算半个多），免得长句被图的右边裁掉。
    英文按词折；没有空格的长中文串按字折。原来有空格的地方保留空格，中文字与字之间不插空格。"""
    def width(s: str) -> float:
        return sum(fontsize / 72 * (1.0 if ord(c) > 0x2E7F else 0.53) for c in s)

    pieces: list[tuple[str, str]] = []          # (前面的空白, 这一块)
    for space, token in re.findall(r"(\s*)(\S+)", text):
        if width(token) > max_inches * 0.5 and re.search(r"[\u3000-\u9fff\uff00-\uffef]", token):
            pieces += [(space if i == 0 else "", ch) for i, ch in enumerate(token)]
        else:
            pieces.append((space, token))
    lines, cur = [], ""
    closers = "，。）；：、」』%"
    for space, piece in pieces:
        candidate = (cur + space + piece) if cur else piece
        if cur and width(candidate) > max_inches and piece not in closers:
            lines.append(cur)
            cur = piece
        else:
            cur = candidate
    if cur:
        lines.append(cur)
    return lines


def heading(figure, title: str, subtitle: str, source: str) -> None:
    width_in, height_in = figure.get_size_inches()
    left = 0.022
    step = lambda size: size * 1.5 / 72 / height_in  # noqa: E731
    def lines(text: str, size: float, limit: int) -> list[str]:
        out = wrap(text, width_in * (1 - 2 * left), size)
        if len(out) > limit:
            raise SystemExit(f"图里的文字太长，折成 {len(out)} 行（最多 {limit} 行）：{text[:50]}…")
        return out

    y = 0.965
    for line in lines(title, 13.5, 2):
        figure.text(left, y, line, fontsize=13.5, weight="bold", va="center")
        y -= step(13.5)
    y -= step(9.2) * 0.15
    for line in lines(subtitle, 9.2, 3):       # 版式给副标题留了三行的位置
        figure.text(left, y, line, fontsize=9.2, color=MUTED, va="center")
        y -= step(9.2)
    sy = 0.028
    for line in lines(source, 8.2, 1):
        figure.text(left, sy, line, fontsize=8.2, color=MUTED, va="center")
        sy += step(8.2)


# ---------- 数据 ----------

def load_mock_drills() -> list[dict]:
    """Mock 演习：drills/drill_results*.json 里 llm == "mock" 的那些（真实模型的文件名里带 .real.）。
    每个格子是「场景 × 守卫开/关」的一次运行；只数带陷阱的场景（traps > 0）。"""
    found: dict[tuple, dict] = {}
    for path in sorted((ROOT / "drills").glob("drill_results*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("llm") != "mock" or ".real." in path.name:
            continue
        key = (data["loop"], bool(data.get("all_sites")), bool(data.get("stealth")), bool(data.get("struct")))
        if key in found:
            raise SystemExit(f"drills/ 里有两份 Mock 结果对应同一组条件 {key}：{found[key]['file']} 和 {path.name}")
        rows = data["rows"]
        trap = [r for r in rows if r.get("traps", 0) > 0]
        off = [r for r in trap if r["guard"] == "off"]
        on = [r for r in trap if r["guard"] == "on"]
        clean = [r for r in rows if r.get("traps", 0) == 0 and r["guard"] == "on"]
        hijacked = lambda rs: sum(1 for r in rs if r.get("hijacked"))  # noqa: E731
        found[key] = dict(
            file=path.name, loop=key[0], set=key[1:],
            cells=len(off), off=hijacked(off), on=hijacked(on),
            completed_on=sum(1 for r in on if r.get("completed")),
            quarantine_on=sum(1 for r in on if r.get("quarantined", 0) > 0),
            false_quarantine=sum(r.get("quarantined", 0) for r in clean),
        )
        if len(off) != len(on):
            raise SystemExit(f"{path.name}: 守卫开 / 关的陷阱格子数不一样（{len(off)} / {len(on)}）")
    order = []
    for name, flags in (("默认集", (False, False, False)), ("四向量场景", (True, False, False)),
                        ("隐蔽陷阱", (False, True, False)), ("结构伪造", (False, False, True))):
        for loop in ("simple", "production"):
            key = (loop, *flags)
            if key not in found:
                raise SystemExit(f"drills/ 里缺一份 Mock 结果：loop={loop} all_sites/stealth/struct={flags}")
            order.append(dict(found[key], name=name))
    return order


def run_structural_summary(agentdojo: str) -> dict:
    """现跑 fusion/structural_summary.py 并解析它打印的表（口径全在那个脚本里，这里不另算）。"""
    cmd = [sys.executable, str(ROOT / "fusion" / "structural_summary.py"), "--agentdojo", agentdojo]
    print(f"运行 {' '.join(cmd)}（约两分钟）…", flush=True)
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    header = re.search(r"^states (\d+)（种子 (\d+)，去掉了种子 (\d+) 的 (\d+) 个）；回复 (\d+) 行；规则= *(.+)$", out, re.M)
    if not header:
        raise SystemExit("structural_summary.py 的输出第一行认不出来：\n" + out[:400])
    rows = []
    for line in out.splitlines()[1:]:
        tok = line.split()
        if len(tok) != 12 or not re.fullmatch(r"\d+/\d+", tok[2]):
            continue
        off_k, off_n = map(int, tok[2].split("/"))
        again = None if tok[11] == "-" else tuple(map(int, tok[11].split("/")))
        rows.append(dict(model=tok[0], attack=tok[1], hijacked=off_k, cells=off_n, interval=tok[3],
                         reasked=int(tok[7]), guard_executed=int(tok[8]),
                         repeat_executed=None if again is None else again[0], repeat_asked=None if again is None else again[1]))
    if not rows:
        raise SystemExit("structural_summary.py 的输出里没有数据行：\n" + out[:400])
    return dict(
        source="python3 fusion/structural_summary.py --agentdojo <AgentDojo 的目录>",
        rule_version=header.group(6).strip(), states=int(header.group(1)), seed=int(header.group(2)),
        exclude_seed=int(header.group(3)), excluded=int(header.group(4)), reply_rows=int(header.group(5)),
        attacks=sorted({r["attack"] for r in rows}), rows=rows)


def summarize_structural(data: dict) -> list[dict]:
    """表一那几种结构伪造写法（不算 todo、clean 和自适应变体），按模型合计。"""
    rows = [r for r in data["rows"] if r["attack"] not in NON_STRUCTURAL and r["attack"] not in ADAPTIVE]
    out = []
    versions = sorted({r["model"] for r in rows},
                       key=lambda m: (tuple(-int(x) for x in re.findall(r"\d+", m)), m))   # 版本号从高到低，同版本短的在前：
    #                                                                                          # glm-5.4、glm-5.3、glm-5.3-flash，和 README 表格同一个顺序
    for model in versions:
        mine = [r for r in rows if r["model"] == model]
        hijacked = sum(r["hijacked"] for r in mine)
        for r in mine:        # 中招的格子全部重问过（守卫开），也全部有守卫关着重问的对照；没中招的写法不需要对照
            if r["reasked"] != r["hijacked"] or (r["hijacked"] and r["repeat_asked"] != r["hijacked"]):
                raise SystemExit(f"{model} / {r['attack']}: 对照（repeat.*.jsonl）不全，或重问的格子数和中招的对不上")
        asked = [r for r in mine if r["repeat_asked"] is not None]
        out.append(dict(
            model=model, cells=sum(r["cells"] for r in mine), executed=hijacked,
            wordings=len(mine), hijacked_wordings=sum(1 for r in mine if r["hijacked"]),
            reasked=sum(r["reasked"] for r in mine), guard_executed=sum(r["guard_executed"] for r in mine),
            repeat_asked=sum(r["repeat_asked"] for r in asked), repeat_executed=sum(r["repeat_executed"] for r in asked),
        ))
    return out


def run_agentdojo_eval(runs_dir: str) -> dict:
    """现跑 fusion/agentdojo_eval.py（六份没有防御的记录）并解析它打印的数。"""
    runs = [str(Path(runs_dir) / name) for name, _ in AGENTDOJO_RUNS]
    cmd = [sys.executable, str(ROOT / "fusion" / "agentdojo_eval.py"), *runs]
    print(f"运行 fusion/agentdojo_eval.py（六份记录，约七分钟）…", flush=True)
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    blocks, current = [], None
    for line in out.splitlines():
        head = re.match(r"^===== (\S+)：(\d+) 份记录$", line)
        if head:
            current = dict(pipeline=head.group(1), transcripts=int(head.group(2)))
            blocks.append(current)
        elif current is not None:
            asr = re.match(r"^\s+important_instructions\s+攻击成功率\s+(\d+)/(\d+)\s+([\d.]+)%$", line)
            e1 = re.match(r"^\s+E1 指令类攻击：.*?\s+(\d+) 条：守卫隔离\s+(\d+) 条", line)
            e3 = re.match(r"^\s+E3 干净的工具输出（都是误报）\s+(\d+) 条：守卫隔离\s+(\d+) 条", line)
            if asr:
                current.update(asr=[int(asr.group(1)), int(asr.group(2))], asr_pct=asr.group(3) + "%")
            elif e1:
                current["e1"] = [int(e1.group(2)), int(e1.group(1))]       # [守卫隔离的, 总数]
            elif e3:
                current["e3"] = [int(e3.group(2)), int(e3.group(1))]
    if len(blocks) != len(AGENTDOJO_RUNS):
        raise SystemExit(f"agentdojo_eval.py 打印了 {len(blocks)} 份记录，应该是 {len(AGENTDOJO_RUNS)} 份")
    models = []
    for (run, label), b in zip(AGENTDOJO_RUNS, blocks):
        for key in ("asr", "e1", "e3"):
            if key not in b:
                raise SystemExit(f"{run}: 输出里没有 {key} 这一行")
        models.append(dict(run=run, model=label, pipeline=b["pipeline"], transcripts=b["transcripts"],
                           asr=b["asr"], e1=b["e1"], e3=b["e3"]))
    return dict(source="python3 fusion/agentdojo_eval.py <runs/…>（六份没有任何防御的记录）", models=models)


def read_test_logs(logs_dir: Path) -> dict:
    """从实测日志里取末尾几行，原样保存。取到的行要认得出来，免得日志换了内容图上还写着旧的说明。"""
    logs = []
    for name, zh, en in TEST_LOGS:
        path = logs_dir / name
        lines = path.read_text(encoding="utf-8").rstrip("\n").split("\n")[-2:]
        if name == "mutation.txt":
            ok = bool(re.search(r"变异 \d+ 个：被测试杀死 \d+ 个", lines[-2])) and lines[-1] == "exit=0"
        else:
            ok = bool(re.fullmatch(r"\d+ passed(?:, \d+ (?:skipped|deselected))? in [\d.]+s", lines[-1]))
        if not ok:
            raise SystemExit(f"{path}: 末尾两行不是预期的样子：\n  " + "\n  ".join(lines))
        logs.append(dict(file=name, label=dict(zh=zh, en=en), lines=lines))
    return dict(note="实测日志的目录不入库；这里存的是图里用到的原样日志行（每份取末尾两行）", logs=logs)


def load_json(name: str, flag: str) -> dict:
    path = DATA_DIR / name
    if not path.is_file():
        raise SystemExit(f"缺 {path.relative_to(ROOT)}：带 {flag} 跑一次先生成它")
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(data: dict, name: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / name).write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


# ---------- 图一：Mock 演习 ----------

def chart_mock(rows: list[dict], lang: str) -> None:
    zh = lang == "zh"
    figure = new_figure(7.6, 5.4, lang)
    axes = figure.add_axes([0.27, 0.135, 0.43, 0.645])
    n = len(rows)
    for i, r in enumerate(rows):
        y = n - 1 - i
        for guard, dy in (("off", 0.19), ("on", -0.19)):
            for c in range(r["cells"]):
                if guard == "off":
                    face, edge = (RED, RED) if c < r["off"] else ("white", RED)
                else:
                    face, edge = (RED, RED) if c < r["on"] else (GREEN_FILL, GREEN)
                axes.add_patch(Rectangle((c + 0.05, y + dy - 0.15), 0.90, 0.30, facecolor=face, edgecolor=edge, linewidth=1.0))
        axes.text(-0.3, y + 0.15, r["name"] if zh else r["name_en"], ha="right", va="center", fontsize=10.5, weight="bold")
        axes.text(-0.3, y - 0.22, r["loop_zh" if zh else "loop_en"], ha="right", va="center", fontsize=8.8, color=MUTED)
        axes.text(9.35, y, f'{r["off"]}/{r["cells"]} → {r["on"]}/{r["cells"]}', ha="left", va="center",
                  fontsize=10.5, weight="bold")
    axes.set_xlim(0, 9)
    axes.set_ylim(-0.62, n - 0.38)
    axes.set_yticks([])
    axes.set_xticks(range(1, 10))
    axes.tick_params(axis="x", length=0, pad=3, labelsize=8)
    for spine in axes.spines.values():
        spine.set_visible(False)
    axes.set_xlabel("被劫持的格子数（每个方格是一个陷阱场景）" if zh else "Trap cells hijacked (each box is one trap scenario)",
                    fontsize=8.8, labelpad=4)
    legend = (Patch(facecolor=RED, edgecolor=RED, label="守卫关：被劫持"),
              Patch(facecolor=GREEN_FILL, edgecolor=GREEN, label="守卫开：未被劫持")) if zh else \
             (Patch(facecolor=RED, edgecolor=RED, label="Guard off: hijacked"),
              Patch(facecolor=GREEN_FILL, edgecolor=GREEN, label="Guard on: not hijacked"))
    figure.legend(handles=legend, loc="upper left", bbox_to_anchor=(0.27, 0.822), frameon=False, ncol=2,
                  fontsize=9.3, handlelength=1.3, handleheight=0.9, columnspacing=1.6, borderpad=0)
    heading(figure,
            "Mock 演习（最坏情形）：被劫持的陷阱格子数" if zh else "Mock drill (worst case): trap cells hijacked",
            "Mock 看到未隔离的陷阱就服从。这张图量的是「守卫有没有把陷阱换掉」，不是真实模型的服从率" if zh else
            "The mock obeys any un-quarantined trap it sees. This measures whether the guard replaced the trap, not a real model's obedience",
            "数据：drills/drill_results*.json（llm = mock 的八份）· scripts/make_readme_charts.py" if zh else
            "Data: drills/drill_results*.json (the eight mock files) · scripts/make_readme_charts.py")
    save(figure, "drill-mock-hijack.png" if zh else "drill-mock-hijack.en.png")


# ---------- 图二：结构伪造（真实模型） ----------

def chart_structural(models: list[dict], lang: str) -> None:
    zh = lang == "zh"
    figure = new_figure(7.6, 4.6, lang)
    axes = figure.add_axes([0.085, 0.245, 0.905, 0.50])
    width = 0.24
    series = (("executed", RED, "无防护时执行" if zh else "Executed, no defense"),
              ("repeat_executed", GRAY, "对照：同一批格子，守卫关着重问" if zh else "Control: same cells re-asked, guard off"),
              ("guard_executed", GREEN, "守卫开：同一批格子重问" if zh else "Guard on: same cells re-asked"))
    top = max(m["executed"] for m in models)
    for j, (key, color, label) in enumerate(series):
        xs = [i + (j - 1) * (width + 0.025) for i in range(len(models))]
        values = [m[key] for m in models]
        axes.bar(xs, values, width=width, color=color, label=label, zorder=3)
        for x, v in zip(xs, values):
            axes.text(x, v + top * 0.02, str(v), ha="center", va="bottom", fontsize=11.5, weight="bold", color=color)
    for i, m in enumerate(models):
        axes.text(i, -0.035, m["model"], transform=axes.get_xaxis_transform(), ha="center", va="top",
                  fontsize=10.5, weight="bold")
        # 中文说明拆成两行：排成一行时相邻两组的说明会叠在一起
        note = (f'共 {m["cells"]} 格，中招 {m["executed"]} 格\n全部重问' if zh else
                f'{m["cells"]} cells · {m["executed"]} hijacked')
        axes.text(i, -0.105, note, transform=axes.get_xaxis_transform(), ha="center", va="top", fontsize=8.6,
                  color=MUTED, linespacing=1.4)
    axes.set_xlim(-0.62, len(models) - 0.38)
    axes.set_ylim(0, top * 1.22)
    axes.set_xticks([])
    axes.set_ylabel("执行了注入的格子数" if zh else "Cells that executed the injection", fontsize=9.5)
    axes.tick_params(axis="y", length=0, labelsize=8.5)
    for side in ("top", "right", "bottom"):
        axes.spines[side].set_visible(False)
    axes.spines["left"].set_color(LINE)
    axes.legend(loc="upper right", frameon=False, fontsize=9.0, handlelength=1.3, handleheight=0.9, borderpad=0)
    total = sum(m["executed"] for m in models), sum(m["cells"] for m in models)
    again = sum(m["repeat_executed"] for m in models), sum(m["repeat_asked"] for m in models)
    heading(figure,
            "真实模型：结构伪造注入下执行注入的格子数" if zh else "Real models: cells that executed a structural-forgery injection",
            (f"试验台不带提示词层防护，三个模型合计 {total[0]}/{total[1]}。中招的格子是按「中过招」挑出来的，重问一遍本来就可能不再中招"
             f"（守卫关着重问 {again[0]}/{again[1]} 再次执行）——所以对照是必需的") if zh else
            (f"Bench with no prompt-level defense; {total[0]}/{total[1]} cells over the three models. Hijacked cells were selected "
             f"for having been hijacked, so asking again may simply not hijack them twice ({again[0]}/{again[1]} executed again "
             f"with the guard off) — which is why the control is needed"),
            ("数据：fusion/structural_summary.py 的输出 · docs/images/chart-data/structural_forgery.json" if zh else
             "Data: output of fusion/structural_summary.py · docs/images/chart-data/structural_forgery.json"))
    save(figure, "structural-forgery.png" if zh else "structural-forgery.en.png")


# ---------- 图三：外部基准 AgentDojo ----------

def chart_agentdojo(models: list[dict], lang: str) -> None:
    zh = lang == "zh"
    figure = new_figure(7.6, 5.2, lang)
    axes = figure.add_axes([0.255, 0.175, 0.61, 0.50])
    n = len(models)
    tiny = []
    for i, m in enumerate(models):
        y = n - 1 - i
        small = m["e1"][1] < TINY_SAMPLE
        if small:
            tiny.append((m["model"], m["e1"][1]))
        for key, color, dy in (("e1", GREEN, 0.19), ("e3", AMBER, -0.19)):
            k, total = m[key]
            style = dict(facecolor="white", edgecolor=color, hatch="////", linewidth=1.2) if (small and key == "e1") \
                else dict(facecolor=color, edgecolor=color, linewidth=0)
            axes.barh(y + dy, 100 * k / total, height=0.30, **style)
            note = (f" · 只有 {total} 条" if zh else f" · only {total}") if (small and key == "e1") else ""
            axes.text(100 * k / total + 1.6, y + dy, f"{k}/{total} · {k / total:.1%}{note}", ha="left", va="center",
                      fontsize=9.2, weight="bold" if key == "e1" else "normal", color=color)
        axes.text(-2.2, y + 0.19, m["model"], ha="right", va="center", fontsize=10.5, weight="bold")
        axes.text(-2.2, y - 0.21, (f'攻击成功率 {m["asr"][0] / m["asr"][1]:.1%}' if zh else
                                   f'attack success {m["asr"][0] / m["asr"][1]:.1%}'),
                  ha="right", va="center", fontsize=8.8, color=MUTED)
    axes.set_xlim(0, 121)
    axes.set_ylim(-0.62, n - 0.38)
    axes.set_yticks([])
    axes.set_xticks([0, 25, 50, 75, 100])
    axes.set_xticklabels(["0", "25%", "50%", "75%", "100%"])
    axes.tick_params(length=0, labelsize=8.5)
    for side in ("top", "right", "left"):
        axes.spines[side].set_visible(False)
    axes.spines["bottom"].set_color(LINE)
    legend = (Patch(facecolor=GREEN, edgecolor=GREEN, label="模型中招的注入：触发点被守卫去掉"),
              Patch(facecolor=AMBER, edgecolor=AMBER, label="干净的工具输出：被误隔离")) if zh else \
             (Patch(facecolor=GREEN, edgecolor=GREEN, label="Injections the model executed: trigger removed by the guard"),
              Patch(facecolor=AMBER, edgecolor=AMBER, label="Clean tool outputs: wrongly quarantined"))
    figure.legend(handles=legend, loc="upper left", bbox_to_anchor=(0.255, 0.800), frameon=False, ncol=1,
                  fontsize=9.3, handlelength=1.3, handleheight=0.9, labelspacing=0.35, borderpad=0)
    e1 = sum(m["e1"][0] for m in models), sum(m["e1"][1] for m in models)
    e3 = sum(m["e3"][0] for m in models), sum(m["e3"][1] for m in models)
    if tiny:
        who = "、".join(t[0] for t in tiny) if zh else ", ".join(t[0] for t in tiny)
        note = (f"斜纹的一行（{who}）只有 {'/'.join(str(t[1]) for t in tiny)} 条样本，比例不足为凭" if zh else
                f"Hatched row ({who}): only {'/'.join(str(t[1]) for t in tiny)} samples — too few to rely on")
    else:
        note = ""
    figure.text(0.022, 0.105, note, fontsize=8.8, color=AMBER, va="center")
    heading(figure,
            "外部基准 AgentDojo：守卫对公开的真实模型记录做了什么" if zh else
            "External benchmark AgentDojo: the guard on real-model records",
            (f"记录没有任何防御，守卫单独处置这些工具输出——不是这些模型在守卫下的攻击成功率。六个模型合计："
             f"触发点去掉 {e1[0] / e1[1]:.1%}（{e1[0]}/{e1[1]}），干净输出误隔离 {e3[0] / e3[1]:.1%}（{e3[0]}/{e3[1]}）") if zh else
            (f"Undefended records: the guard acts on these outputs alone, not the models' attack success rate under the guard. "
             f"All six: {e1[0] / e1[1]:.1%} of triggers removed ({e1[0]}/{e1[1]}), "
             f"{e3[0] / e3[1]:.1%} of clean outputs quarantined ({e3[0]}/{e3[1]})"),
            ("数据：fusion/agentdojo_eval.py 的输出（AgentDojo 公开的运行记录）· docs/images/chart-data/agentdojo_eval.json" if zh else
             "Data: output of fusion/agentdojo_eval.py (AgentDojo's published runs) · docs/images/chart-data/agentdojo_eval.json"))
    save(figure, "agentdojo-benchmark.png" if zh else "agentdojo-benchmark.en.png")


# ---------- 图四：真实的测试输出 ----------

def chart_terminal(data: dict, lang: str) -> None:
    zh = lang == "zh"
    mono = [name for name in ("Noto Sans Mono CJK SC", "Noto Sans Mono CJK JP", "DejaVu Sans Mono") if
            name in {f.name for f in font_manager.fontManager.ttflist}] or ["DejaVu Sans Mono"]
    lines = []
    for i, log in enumerate(data["logs"]):
        if i:
            lines.append(("", "gap"))
        lines.append((f'# {log["file"]} · {log["label"][lang]}', "comment"))
        for text in log["lines"]:
            if re.fullmatch(r"[.\s]*\[\s*\d+%\]", text):
                continue        # pytest 的进度点那一行是噪音，图上只留汇总行
            key = "summary" if re.search(r"\d+ passed|被测试杀死", text) else "output"
            lines.append((text, key))
    line_h, width, top, bottom, bar = 0.25, 7.6, 0.50, 0.24, 0.38
    height = bar + top + line_h * len(lines) + bottom
    figure = plt.figure(figsize=(width, height), dpi=DPI, facecolor="white")
    inches = figure.dpi_scale_trans
    figure.add_artist(FancyBboxPatch((0.06, 0.06), width - 0.12, height - 0.12,
                                     boxstyle="round,pad=0,rounding_size=0.14",
                                     facecolor="#0d1117", edgecolor="#30363d", linewidth=1.2, transform=inches))
    for x, color in ((0.40, "#ff5f56"), (0.62, "#ffbd2e"), (0.84, "#27c93f")):
        figure.add_artist(Circle((x, height - 0.25), 0.065, facecolor=color, edgecolor="none", transform=inches))
    title = "pytest · 实测日志的末尾几行" if zh else "pytest · last lines of the live logs"
    figure.text(width / 2 / width, (height - 0.25) / height, title, ha="center", va="center", family=mono,
                fontsize=9.5, color="#8b949e")
    colors = {"comment": "#8b949e", "output": "#c9d1d9", "summary": "#7ee787", "gap": "#c9d1d9"}
    for i, (text, kind) in enumerate(lines):
        if kind == "gap":
            continue
        figure.text(0.34 / width, (height - bar - top - line_h * (i + 0.5)) / height, text, ha="left", va="center",
                    family=mono, fontsize=10.4, color=colors[kind], weight="bold" if kind == "summary" else "normal")
    save(figure, "test-summary.png" if zh else "test-summary.en.png")


# ---------- 主流程 ----------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--agentdojo", help="AgentDojo 的仓库（sparse clone）：给了就现跑 fusion/structural_summary.py")
    parser.add_argument("--agentdojo-runs", help="AgentDojo 的 runs/ 目录：给了就现跑 fusion/agentdojo_eval.py")
    parser.add_argument("--logs", help="实测日志的目录（如 reviews-round7/baseline-logs）：给了就从日志重取几行")
    parser.add_argument("--only", default="", help="逗号分隔，只画这几张：mock, structural, agentdojo, terminal")
    args = parser.parse_args()
    only = {s.strip() for s in args.only.split(",") if s.strip()}
    IMG_DIR.mkdir(parents=True, exist_ok=True)

    def want(name: str) -> bool:
        return not only or name in only

    if want("mock"):
        mock = load_mock_drills()
        names_en = {"默认集": "Default set", "四向量场景": "Four-vector scenario", "隐蔽陷阱": "Stealth traps",
                    "结构伪造": "Structural forgery"}
        loops = {"simple": ("简化循环", "simplified loop"), "production": ("生产主循环", "production loop")}
        for r in mock:
            r["name_en"], r["loop_zh"], r["loop_en"] = names_en[r["name"]], *loops[r["loop"]]
        print("[drill-mock-hijack] Mock 演习，被劫持的陷阱格子数（守卫关 → 守卫开）")
        for r in mock:
            print(f'  {r["name"]} · {r["loop_zh"]:<6s} {r["off"]}/{r["cells"]} → {r["on"]}/{r["cells"]}'
                  f'   （守卫开：完成 {r["completed_on"]}/{r["cells"]}，发生隔离 {r["quarantine_on"]}/{r["cells"]}，'
                  f'误隔离 {r["false_quarantine"]}）  {r["file"]}')
        chart_mock(mock, "zh")
        chart_mock(mock, "en")

    if want("structural"):
        if args.agentdojo:
            raw = run_structural_summary(args.agentdojo)
            dump_json(raw, "structural_forgery.json")
        else:
            raw = load_json("structural_forgery.json", "--agentdojo <目录>")
        structural = summarize_structural(raw)
        print("[structural-forgery] 真实模型，结构伪造注入（表一的写法）下执行注入的格子数")
        for m in structural:
            print(f'  {m["model"]:<13s} 无防护 {m["executed"]}/{m["cells"]}   对照（守卫关着重问）{m["repeat_executed"]}/{m["repeat_asked"]}'
                  f'   守卫开（重问）{m["guard_executed"]}/{m["reasked"]}')
        print(f'  合计 无防护 {sum(m["executed"] for m in structural)}/{sum(m["cells"] for m in structural)}'
              f'   对照 {sum(m["repeat_executed"] for m in structural)}/{sum(m["repeat_asked"] for m in structural)}'
              f'   守卫开 {sum(m["guard_executed"] for m in structural)}/{sum(m["reasked"] for m in structural)}')
        chart_structural(structural, "zh")
        chart_structural(structural, "en")

    if want("agentdojo"):
        if args.agentdojo_runs:
            evals = run_agentdojo_eval(args.agentdojo_runs)
            dump_json(evals, "agentdojo_eval.json")
        else:
            evals = load_json("agentdojo_eval.json", "--agentdojo-runs <目录>")
        print("[agentdojo-benchmark] 外部基准：中招的注入里触发点被去掉的比例，干净输出被误隔离的比例")
        for m in evals["models"]:
            print(f'  {m["model"]:<17s} 攻击成功率 {m["asr"][0]}/{m["asr"][1]} = {m["asr"][0] / m["asr"][1]:.1%}   '
                  f'触发点去掉 {m["e1"][0]}/{m["e1"][1]} = {m["e1"][0] / m["e1"][1]:.1%}   '
                  f'误隔离 {m["e3"][0]}/{m["e3"][1]} = {m["e3"][0] / m["e3"][1]:.1%}   （{m["run"]}）')
        e1 = (sum(m["e1"][0] for m in evals["models"]), sum(m["e1"][1] for m in evals["models"]))
        e3 = (sum(m["e3"][0] for m in evals["models"]), sum(m["e3"][1] for m in evals["models"]))
        print(f'  合计 触发点去掉 {e1[0]}/{e1[1]} = {e1[0] / e1[1]:.1%}   误隔离 {e3[0]}/{e3[1]} = {e3[0] / e3[1]:.1%}')
        chart_agentdojo(evals["models"], "zh")
        chart_agentdojo(evals["models"], "en")

    if want("terminal"):
        if args.logs:
            summary = read_test_logs(Path(args.logs))
            dump_json(summary, "test_summary.json")
        else:
            summary = load_json("test_summary.json", "--logs <目录>")
        print("[test-summary] 实测日志的末尾几行（原样）")
        for log in summary["logs"]:
            for text in log["lines"]:
                print(f'  {log["file"]:<22s} | {text.rstrip()}')
        chart_terminal(summary, "zh")
        chart_terminal(summary, "en")


if __name__ == "__main__":
    main()
