#!/usr/bin/env bash
# 一键复现：数据生成 → 训练 → 主评测 → 鲁棒性实验（CPU，约 1-2 分钟）
set -e
cd "$(dirname "$0")"
python3 -m src.data_gen
python3 -m src.train
python3 -m src.evaluate
python3 -m src.robustness
echo "全部完成：results/ 下为指标与图表"
