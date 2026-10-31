#!/usr/bin/env bash
# RedBlueAgent 一键复现（CPU，约 4 分钟）：
# 1) 蓝队检测器训练（含工具输出领域适配） 2) 攻防演习（guard on/off 对照）
set -e
cd "$(dirname "$0")"
echo "═══ [1/2] 蓝队检测器训练 ═══"
(cd blueteam && python3 -m src.data_gen && python3 -m src.train && python3 -m src.evaluate)
echo "═══ [2/2] 红蓝攻防演习 ═══"
python3 fusion/drill.py
