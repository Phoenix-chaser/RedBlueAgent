"""Pytest 共享配置：把仓库根加入 sys.path。

替代各测试文件里的 sys.path.insert 样板（打包后 `pip install -e .`
导出的也是同一组顶层包）。blueteam/ 是独立子项目，不在此列。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
