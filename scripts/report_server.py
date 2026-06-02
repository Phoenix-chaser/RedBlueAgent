#!/usr/bin/env python3
"""
report_server.py - Penetration Test Report Visualization Web Server
                   双语报告可视化 Web 服务 (中/英)

Usage / 运行方式:
    python scripts/report_server.py
    python scripts/report_server.py --port 8888 --reports-dir data/reports

Visit / 访问: http://localhost:8888
"""
import json
import argparse
from html import escape as he
from pathlib import Path
from datetime import datetime
from flask import Flask, abort, Response

app = Flask(__name__)
REPORTS_DIR = Path("data/reports")

# =============================================================================
# Data Loading / 数据加载
# =============================================================================

def load_all_sessions() -> list[dict]:
    sessions = []
    if not REPORTS_DIR.exists():
        return sessions
    for session_dir in sorted(REPORTS_DIR.iterdir(), reverse=True):
        report_file = session_dir / "report.json"
        if report_file.exists():
            try:
                data = json.loads(report_file.read_text(encoding="utf-8"))
                data["_session_id"] = session_dir.name
                sessions.append(data)
            except Exception:
                pass
    return sessions

def load_session(session_id: str) -> dict | None:
    report_file = REPORTS_DIR / session_id / "report.json"
    md_file     = REPORTS_DIR / session_id / "report.md"
    if not report_file.exists():
        return None
    data = json.loads(report_file.read_text(encoding="utf-8"))
    data["_session_id"] = session_id
    data["_markdown"]   = md_file.read_text(encoding="utf-8") if md_file.exists() else ""
    return data

def sev_counts(report: dict) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in report.get("vulnerabilities", []):
        sev = v.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts

def fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    m = int(seconds // 60)
    s = int(seconds % 60)
    return f"{m}m {s}s"

def fmt_dt(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso or "—"

# =============================================================================
# Bilingual Helper / 双语辅助函数
# =============================================================================

def t(zh: str, en: str) -> str:
    """Return a bilingual inline element. CSS toggles which language is shown."""
    return f'<span class="zh">{zh}</span><span class="en">{en}</span>'

def risk_level(sc: dict) -> tuple[str, str, str]:
    """Return (css_class, zh_label, en_label) for the overall risk level."""
    if sc["critical"] > 0:
        return "risk-critical", "严重风险", "Critical Risk"
    if sc["high"] > 0:
        return "risk-high",     "高风险",   "High Risk"
    if sc["medium"] > 0:
        return "risk-medium",   "中风险",   "Medium Risk"
    if sc["low"] > 0:
        return "risk-low",      "低风险",   "Low Risk"
    return "risk-none",         "无漏洞",   "Clean"

# =============================================================================
# Shared CSS
# =============================================================================

BASE_CSS = """
/* ── Variables ──────────────────────────────────────────────────────────── */
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;
  --border:#30363d;--text:#c9d1d9;--dim:#8b949e;
  --green:#3fb950;--blue:#58a6ff;--red:#f85149;
  --orange:#f0883e;--yellow:#e3b341;--purple:#bc8cff;
  --crit-bg:#2d0f0f;--high-bg:#2d1a0f;--med-bg:#2d2a0f;--low-bg:#0f1e2d;
  --radius:8px;--shadow:0 2px 8px rgba(0,0,0,.4);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}

/* ── Language Toggle Button ─────────────────────────────────────────────── */
.lang-btn{
  background:var(--bg3);border:1px solid var(--border);
  padding:4px 12px;border-radius:20px;cursor:pointer;font-size:.8rem;
  font-family:inherit;transition:border-color .15s;
  display:inline-flex;align-items:center;gap:5px;
}
.lang-btn:hover{border-color:var(--blue)}
.lang-seg{
  font-weight:700;letter-spacing:.3px;transition:color .2s;
  color:var(--dim);
}
.lang-sep{color:var(--border);font-size:.7rem;line-height:1}
html[data-lang="zh"] .lang-seg-zh{color:var(--blue)}
html[data-lang="en"] .lang-seg-en{color:var(--blue)}

/* ── Bilingual Transition ────────────────────────────────────────────────── */
.zh,.en{transition:opacity .15s ease}
html[data-lang="en"] .zh{display:none!important}
html[data-lang="zh"] .en{display:none!important}

/* ── Navigation ─────────────────────────────────────────────────────────── */
nav{
  background:var(--bg2);border-bottom:1px solid var(--border);
  padding:10px 28px;display:flex;align-items:center;gap:12px;
  position:sticky;top:0;z-index:100;backdrop-filter:blur(4px);
}
.brand{
  font-weight:700;font-size:1rem;color:var(--green);
  display:flex;align-items:center;gap:7px;text-decoration:none!important;
}
.brand:hover{opacity:.85;text-decoration:none!important}
.brand-sub{color:var(--dim);font-size:.78rem;font-weight:400;margin-left:2px}
.nav-spacer{flex:1}
.nav-link{color:var(--dim);font-size:.84rem;padding:4px 10px;border-radius:4px;transition:.15s}
.nav-link:hover,.nav-link.active{background:var(--bg3);color:var(--text);text-decoration:none}

/* ── Layout ─────────────────────────────────────────────────────────────── */
.container{max-width:1120px;margin:0 auto;padding:28px 20px}
.page-header{margin-bottom:24px}
.page-title{font-size:1.45rem;font-weight:700;display:flex;align-items:center;gap:10px}
.page-sub{color:var(--dim);font-size:.85rem;margin-top:5px}

/* ── Cards ──────────────────────────────────────────────────────────────── */
.card{
  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;margin-bottom:16px;box-shadow:var(--shadow);
}
.card-title{font-size:.95rem;font-weight:600;margin-bottom:14px;
  display:flex;align-items:center;gap:8px;color:var(--text)}
.card-title .card-count{color:var(--dim);font-size:.8rem;font-weight:400;margin-left:4px}
hr{border:none;border-top:1px solid var(--border);margin:16px 0}

/* ── Badges ─────────────────────────────────────────────────────────────── */
.badge{
  display:inline-block;padding:2px 9px;border-radius:4px;
  font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap
}
.sev-critical{background:var(--crit-bg);color:var(--red);border:1px solid #5c1a1a}
.sev-high    {background:var(--high-bg);color:var(--orange);border:1px solid #5c3a1a}
.sev-medium  {background:var(--med-bg);color:var(--yellow);border:1px solid #5c540a}
.sev-low     {background:var(--low-bg);color:var(--blue);border:1px solid #1a3a5c}
.sev-info    {background:var(--bg3);color:var(--dim);border:1px solid var(--border)}

/* ── Tags ───────────────────────────────────────────────────────────────── */
.tag{
  background:var(--bg3);color:var(--dim);border:1px solid var(--border);
  padding:2px 8px;border-radius:4px;font-size:.75rem;white-space:nowrap
}
.tag-green{background:#0d2818;color:var(--green);border-color:#1a4a2a}
.tag-red  {background:var(--crit-bg);color:var(--red);border-color:#5c1a1a}
.tag-blue {background:var(--low-bg);color:var(--blue);border-color:#1a3a5c}

/* ── Risk Badge ─────────────────────────────────────────────────────────── */
.risk-badge{
  display:inline-flex;align-items:center;padding:3px 10px;
  border-radius:20px;font-size:.73rem;font-weight:700;white-space:nowrap
}
.risk-critical{background:var(--crit-bg);color:var(--red);border:1px solid #5c1a1a}
.risk-high    {background:var(--high-bg);color:var(--orange);border:1px solid #5c3a1a}
.risk-medium  {background:var(--med-bg);color:var(--yellow);border:1px solid #5c540a}
.risk-low     {background:var(--low-bg);color:var(--blue);border:1px solid #1a3a5c}
.risk-none    {background:#0d2818;color:var(--green);border:1px solid #1a4a2a}

/* ── Stats Grid ─────────────────────────────────────────────────────────── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(115px,1fr));gap:10px;margin-bottom:18px}
.stat-card{
  background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);
  padding:14px 12px;text-align:center;transition:.15s;
}
.stat-card:hover{border-color:var(--blue)}
.stat-num{font-size:1.7rem;font-weight:700;line-height:1.1}
.stat-label{font-size:.72rem;color:var(--dim);margin-top:5px;line-height:1.3}
.stat-crit{color:var(--red)}
.stat-high{color:var(--orange)}
.stat-med {color:var(--yellow)}
.stat-low {color:var(--blue)}
.stat-ok  {color:var(--green)}
.stat-dim {color:var(--dim)}

/* ── Session Cards (Index) ──────────────────────────────────────────────── */
.session-card{
  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
  padding:16px 20px;margin-bottom:10px;display:flex;align-items:center;gap:16px;
  transition:.15s;box-shadow:var(--shadow);
}
.session-card:hover{border-color:var(--blue);background:var(--bg3);transform:translateY(-1px)}
.session-target{font-weight:600;font-size:.95rem;font-family:monospace}
.session-meta{font-size:.78rem;color:var(--dim);margin-top:3px}
.session-sevs{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.session-actions{margin-left:auto;display:flex;gap:8px;flex-shrink:0}

/* ── Buttons ────────────────────────────────────────────────────────────── */
.btn{
  display:inline-block;padding:6px 16px;border-radius:6px;font-size:.83rem;
  cursor:pointer;border:none;font-family:inherit;text-decoration:none!important;
  transition:.15s;white-space:nowrap;
}
.btn-primary{background:var(--blue);color:#0d1117;font-weight:600}
.btn-primary:hover{opacity:.85;text-decoration:none!important}
.btn-outline{background:transparent;color:var(--dim);border:1px solid var(--border)}
.btn-outline:hover{border-color:var(--blue);color:var(--blue);text-decoration:none!important}
.btn-sm{padding:3px 10px;font-size:.75rem}
.btn-copy{
  background:var(--bg3);border:1px solid var(--border);color:var(--dim);
  padding:2px 8px;border-radius:4px;font-size:.72rem;cursor:pointer;
  font-family:inherit;transition:.15s;
}
.btn-copy:hover{border-color:var(--green);color:var(--green)}

/* ── Filter Toolbar ─────────────────────────────────────────────────────── */
.filter-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.filter-btn{
  display:inline-block;padding:4px 12px;border-radius:20px;font-size:.78rem;
  cursor:pointer;border:1px solid var(--border);background:transparent;
  color:var(--dim);font-family:inherit;transition:.15s;
}
.filter-btn:hover{border-color:var(--blue);color:var(--blue)}
.filter-btn.active{border-color:var(--blue);color:var(--blue);background:rgba(88,166,255,.12)}
.filter-btn.active-crit{border-color:var(--red);color:var(--red);background:rgba(248,81,73,.1)}
.filter-btn.active-high{border-color:var(--orange);color:var(--orange);background:rgba(240,136,62,.1)}
.filter-btn.active-med{border-color:var(--yellow);color:var(--yellow);background:rgba(227,179,65,.1)}
.filter-btn.active-low{border-color:var(--blue);color:var(--blue);background:rgba(88,166,255,.1)}

/* ── Search Input ───────────────────────────────────────────────────────── */
.search-wrap{position:relative;flex:1;min-width:180px;max-width:320px}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--dim);font-size:.85rem;pointer-events:none}
.search-input{
  background:var(--bg3);border:1px solid var(--border);color:var(--text);
  padding:5px 12px 5px 32px;border-radius:20px;font-size:.82rem;
  font-family:inherit;width:100%;outline:none;transition:.15s;
}
.search-input:focus{border-color:var(--blue)}
.search-input::placeholder{color:var(--dim)}

/* ── Severity Bar ───────────────────────────────────────────────────────── */
.sev-bar-wrap{display:flex;height:6px;border-radius:3px;overflow:hidden;gap:1px;margin-top:8px}
.sev-bar-seg{height:100%;transition:.3s}

/* ── Vuln Table ─────────────────────────────────────────────────────────── */
.vuln-table{width:100%;border-collapse:collapse;font-size:.84rem}
.vuln-table th{
  text-align:left;padding:8px 12px;border-bottom:2px solid var(--border);
  color:var(--dim);font-size:.75rem;text-transform:uppercase;letter-spacing:.5px
}
.vuln-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
.vuln-table tr:last-child td{border-bottom:none}
.vuln-data-row{cursor:pointer;transition:.1s}
.vuln-data-row:hover td{background:var(--bg3)}
.vuln-title{font-weight:500}
.vuln-component{color:var(--dim);font-size:.78rem;margin-top:3px}
.expand-arrow{color:var(--dim);font-size:.75rem;margin-right:4px;display:inline-block;transition:.2s}

/* ── Vuln Detail ────────────────────────────────────────────────────────── */
.vuln-detail{
  background:var(--bg3);border:1px solid var(--border);border-radius:6px;
  padding:14px 16px;margin:4px 0 10px;font-size:.83rem;
}
.vuln-detail pre{
  background:#010409;padding:12px;border-radius:4px;
  font-size:.78rem;color:var(--green);overflow-x:auto;white-space:pre-wrap;
  word-break:break-all;margin-top:6px;border:1px solid var(--border);
  position:relative;
}
.detail-label{color:var(--dim);font-size:.75rem;text-transform:uppercase;
  letter-spacing:.4px;margin-top:10px;margin-bottom:4px}

/* ── Charts ─────────────────────────────────────────────────────────────── */
.chart-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap}
.chart-legend{display:flex;flex-direction:column;gap:6px}
.legend-item{display:flex;align-items:center;gap:8px;font-size:.82rem}
.legend-dot{width:11px;height:11px;border-radius:50%;flex-shrink:0}
.legend-count{margin-left:auto;padding-left:20px;font-weight:700}

/* ── Infrastructure ─────────────────────────────────────────────────────── */
.infra-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.infra-host{border:1px solid var(--border);border-radius:6px;padding:14px;background:var(--bg3)}
.infra-host h4{font-size:.88rem;color:var(--blue);margin-bottom:6px;
  display:flex;align-items:center;gap:6px}
.port-row{
  display:flex;gap:10px;align-items:center;padding:5px 0;
  border-bottom:1px solid var(--border);font-size:.8rem
}
.port-row:last-child{border-bottom:none}
.port-num{color:var(--green);font-family:monospace;min-width:75px;font-size:.82rem}

/* ── Recommendations ────────────────────────────────────────────────────── */
.rec-item{
  padding:10px 14px;border:1px solid var(--border);border-radius:6px;
  margin-bottom:8px;font-size:.86rem;background:var(--bg3);
}
.rec-en{color:var(--text)}
.rec-zh{color:var(--dim);margin-top:4px;font-size:.8rem}
.rec-num{color:var(--blue);font-weight:700;margin-right:6px}

/* ── Stage Timeline ─────────────────────────────────────────────────────── */
.timeline{display:flex;align-items:flex-start;flex-wrap:wrap;margin:10px 0;gap:0}
.tl-step{display:flex;align-items:center}
.tl-group{display:flex;flex-direction:column;align-items:center}
.tl-dot{
  width:34px;height:34px;border-radius:50%;display:flex;align-items:center;
  justify-content:center;font-size:.68rem;font-weight:700;flex-shrink:0;
}
.tl-dot.done{background:#0d2818;border:2px solid var(--green);color:var(--green)}
.tl-dot.skip{background:var(--bg3);border:2px solid var(--border);color:var(--dim)}
.tl-line{width:20px;height:2px;flex-shrink:0;margin-top:-18px}
.tl-line.done{background:var(--green)}
.tl-line.skip{background:var(--border)}
.tl-label{font-size:.65rem;color:var(--dim);text-align:center;margin-top:4px;width:50px;line-height:1.3}
.tl-label.done{color:var(--green)}

/* ── Alerts ─────────────────────────────────────────────────────────────── */
.alert{padding:10px 14px;border-radius:6px;margin:10px 0;font-size:.87rem}
.alert-ok  {background:#0d2818;border:1px solid var(--green);color:var(--green)}
.alert-warn{background:#2d2508;border:1px solid var(--yellow);color:var(--yellow)}
.alert-err {background:var(--crit-bg);border:1px solid var(--red);color:var(--red)}

/* ── Empty State ────────────────────────────────────────────────────────── */
.empty{text-align:center;padding:60px 20px;color:var(--dim)}
.empty-icon{font-size:3rem;margin-bottom:14px}
.empty code{background:var(--bg3);padding:2px 8px;border-radius:4px;font-size:.85rem}

/* ── Markdown / Raw ─────────────────────────────────────────────────────── */
.md-raw{
  font-size:.85rem;line-height:1.75;white-space:pre-wrap;font-family:'Segoe UI',system-ui,sans-serif;
  color:var(--text);
}

/* ── Session Search ─────────────────────────────────────────────────────── */
.session-search-wrap{margin-bottom:16px}

/* ── Two-column layout ──────────────────────────────────────────────────── */
.two-col{display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap}
.two-col-left{flex:1;min-width:200px}
.two-col-right{flex:2;min-width:240px}

/* ── Print ──────────────────────────────────────────────────────────────── */
@media print{
  nav,.session-actions,.btn,button{display:none!important}
  .card{box-shadow:none;border:1px solid #ccc}
  body{background:#fff;color:#000}
  :root{--text:#111;--dim:#555;--bg:#fff;--bg2:#fff;--bg3:#f5f5f5;--border:#ddd}
}

/* ── Responsive ─────────────────────────────────────────────────────────── */
@media(max-width:640px){
  .session-card{flex-direction:column;align-items:flex-start}
  .session-actions{margin-left:0}
  .chart-wrap{flex-direction:column}
  .two-col{flex-direction:column}
  nav{padding:10px 14px}
  .container{padding:16px 12px}
}
"""

# =============================================================================
# Shared JavaScript
# =============================================================================

BASE_JS = """
function toggleLang() {
  var html = document.documentElement;
  var cur  = html.getAttribute('data-lang') || 'zh';
  var next = cur === 'zh' ? 'en' : 'zh';
  /* Brief flash on the button to confirm the switch */
  var btn = document.querySelector('.lang-btn');
  if (btn) { btn.style.borderColor = 'var(--blue)'; setTimeout(function(){ btn.style.borderColor = ''; }, 500); }
  html.setAttribute('data-lang', next);
  localStorage.setItem('pentest_lang', next);
  _applyI18nAttrs(next);
}

function _applyI18nAttrs(lang) {
  document.querySelectorAll('[data-ph-zh]').forEach(function(el) {
    el.placeholder = lang === 'zh' ? el.dataset.phZh : el.dataset.phEn;
  });
  document.querySelectorAll('[data-title-zh]').forEach(function(el) {
    el.title = lang === 'zh' ? el.dataset.titleZh : el.dataset.titleEn;
  });
}

document.addEventListener('DOMContentLoaded', function() {
  var lang = document.documentElement.getAttribute('data-lang') || 'zh';
  _applyI18nAttrs(lang);
});

function toggle(id) {
  var el = document.getElementById(id);
  if (!el) return;
  var shown = el.style.display === 'table-row';
  el.style.display = shown ? 'none' : 'table-row';
  var arrow = document.getElementById('arrow-' + id);
  if (arrow) arrow.textContent = shown ? '▶' : '▼';
}

function expandAll() {
  document.querySelectorAll('[id^="vuln-detail-"]').forEach(function(el){
    el.style.display = 'table-row';
  });
  document.querySelectorAll('.expand-arrow').forEach(function(el){
    el.textContent = '▼';
  });
}

function collapseAll() {
  document.querySelectorAll('[id^="vuln-detail-"]').forEach(function(el){
    el.style.display = 'none';
  });
  document.querySelectorAll('.expand-arrow').forEach(function(el){
    el.textContent = '▶';
  });
}

var _activeFilter = 'all';
function filterVulns(sev, btn) {
  _activeFilter = sev;
  document.querySelectorAll('.vuln-data-row').forEach(function(row){
    var show = sev === 'all' || row.dataset.sev === sev;
    row.style.display = show ? '' : 'none';
    if (!show) {
      var detailId = row.dataset.detailId;
      if (detailId) {
        var detail = document.getElementById(detailId);
        if (detail) detail.style.display = 'none';
        var arrow = document.getElementById('arrow-' + detailId);
        if (arrow) arrow.textContent = '▶';
      }
    }
  });
  document.querySelectorAll('.filter-btn').forEach(function(b){
    b.className = b.className.replace(/ active(-\\w+)?/g, '');
  });
  if (btn) {
    btn.classList.add(sev === 'all' ? 'active' : 'active-' + sev);
  }
  _applySearch();
}

function searchVulns(q) {
  var query = q.trim().toLowerCase();
  document.querySelectorAll('.vuln-data-row').forEach(function(row){
    if (_activeFilter !== 'all' && row.dataset.sev !== _activeFilter) return;
    var text = (row.dataset.searchText || row.textContent).toLowerCase();
    row.style.display = (!query || text.includes(query)) ? '' : 'none';
  });
}

function _applySearch() {
  var el = document.getElementById('vuln-search');
  if (el) searchVulns(el.value);
}

function filterSessions(q) {
  var query = q.trim().toLowerCase();
  document.querySelectorAll('.session-card').forEach(function(card){
    var text = (card.dataset.searchText || card.textContent).toLowerCase();
    card.style.display = (!query || text.includes(query)) ? '' : 'none';
  });
}

function copyText(text, btn) {
  navigator.clipboard.writeText(text).catch(function(){
    var ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta);
    ta.select(); document.execCommand('copy');
    document.body.removeChild(ta);
  });
  if (btn) {
    var orig = btn.innerHTML;
    btn.innerHTML = '✓';
    setTimeout(function(){ btn.innerHTML = orig; }, 1500);
  }
}
"""

# =============================================================================
# Base Page
# =============================================================================

def base_page(title_zh: str, body: str, active: str = "", title_en: str = "") -> str:
    title_en = title_en or title_zh
    return f"""<!DOCTYPE html>
<html data-lang="zh"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title_zh} / {title_en} — PentestAgent</title>
<style>{BASE_CSS}</style>
<script>
/* Apply saved language immediately to prevent flash of wrong language */
(function(){{
  var l = localStorage.getItem('pentest_lang') || 'zh';
  document.documentElement.setAttribute('data-lang', l);
}})();
</script>
</head><body>
<nav>
  <a href="/" class="brand">
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    PentestAgent
    <span class="brand-sub zh">报告中心</span>
    <span class="brand-sub en">Reports</span>
  </a>
  <div class="nav-spacer"></div>
  <a href="/" class="nav-link {'active' if active == 'home' else ''}">
    <span class="zh">所有报告</span><span class="en">All Reports</span>
  </a>
  <button class="lang-btn" onclick="toggleLang()" title="Switch Language / 切换语言">
    <span class="lang-seg lang-seg-zh">中文</span>
    <span class="lang-sep">|</span>
    <span class="lang-seg lang-seg-en">EN</span>
  </button>
</nav>
<div class="container">{body}</div>
<script>{BASE_JS}</script>
</body></html>"""

# =============================================================================
# SVG Helpers
# =============================================================================

SEV_COLORS = {
    "critical": "#f85149",
    "high":     "#f0883e",
    "medium":   "#e3b341",
    "low":      "#58a6ff",
    "info":     "#8b949e",
}
SEV_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
SEV_EN = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

def donut_svg(counts: dict) -> str:
    total = sum(counts.values())
    if total == 0:
        return (
            '<svg width="130" height="130" viewBox="0 0 130 130">'
            '<circle cx="65" cy="65" r="48" fill="none" stroke="#21262d" stroke-width="18"/>'
            '<text x="65" y="62" text-anchor="middle" fill="#8b949e" font-size="18" font-weight="700">0</text>'
            '<text x="65" y="78" text-anchor="middle" fill="#8b949e" font-size="10">Vulns</text>'
            '</svg>'
        )
    cx, cy, r, sw = 65, 65, 48, 18
    circumference = 2 * 3.14159 * r
    paths = []
    offset = 0.0
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = counts.get(sev, 0)
        if cnt == 0:
            continue
        frac  = cnt / total
        dash  = frac * circumference
        gap   = circumference - dash
        color = SEV_COLORS[sev]
        paths.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
            f'stroke-width="{sw}" stroke-dasharray="{dash:.2f} {gap:.2f}" '
            f'stroke-dashoffset="-{offset:.2f}" transform="rotate(-90 {cx} {cy})">'
            f'<title>{SEV_ZH[sev]} / {SEV_EN[sev]}: {cnt} ({frac*100:.0f}%)</title>'
            f'</circle>'
        )
        offset += dash

    return (
        f'<svg width="130" height="130" viewBox="0 0 130 130">'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#21262d" stroke-width="{sw}"/>'
        + "".join(paths) +
        f'<text x="{cx}" y="{cy-5}" text-anchor="middle" fill="#c9d1d9" font-size="20" font-weight="700">{total}</text>'
        f'<text x="{cx}" y="{cy+14}" text-anchor="middle" fill="#8b949e" font-size="10">Vulns</text>'
        f'</svg>'
    )

def sev_bar(counts: dict) -> str:
    total = sum(counts.values()) or 1
    segs = "".join(
        f'<div class="sev-bar-seg" style="width:{counts.get(s,0)/total*100:.1f}%;background:{SEV_COLORS[s]}" '
        f'title="{SEV_ZH[s]}/{SEV_EN[s]}: {counts.get(s,0)}"></div>'
        for s in ["critical", "high", "medium", "low", "info"] if counts.get(s, 0) > 0
    )
    return f'<div class="sev-bar-wrap">{segs}</div>' if segs else ""

def stage_timeline(completed: list) -> str:
    STAGES = [
        ("TC", "target_confirmation",   "目标确认", "Target"),
        ("IG", "information_gathering", "信息收集", "Recon"),
        ("VS", "vuln_scanning",         "漏洞扫描", "Scan"),
        ("VA", "vuln_analysis",         "漏洞分析", "Analysis"),
        ("EX", "exploitation",          "漏洞利用", "Exploit"),
        ("PE", "post_exploit",          "后渗透",   "Post-Exp"),
        ("RP", "report",                "报告生成", "Report"),
    ]
    parts = []
    for i, (abbr, key, zh_label, en_label) in enumerate(STAGES):
        done = any(key in c for c in completed) or any(c.startswith(abbr) for c in completed)
        dot_cls   = "done" if done else "skip"
        label_cls = "done" if done else ""
        parts.append(
            f'<div class="tl-group">'
            f'<div class="tl-dot {dot_cls}" title="{zh_label} / {en_label}">{abbr}</div>'
            f'<div class="tl-label {label_cls}">'
            f'<span class="zh">{zh_label}</span>'
            f'<span class="en">{en_label}</span>'
            f'</div>'
            f'</div>'
        )
        if i < len(STAGES) - 1:
            line_cls = "done" if done else "skip"
            parts.append(f'<div class="tl-step"><div class="tl-line {line_cls}"></div></div>')

    return f'<div class="timeline">{"".join(parts)}</div>'

# =============================================================================
# Routes
# =============================================================================

@app.route("/")
def index():
    sessions = load_all_sessions()

    if not sessions:
        body = f"""
<div class="page-header">
  <div class="page-title">
    🛡️ {t("渗透测试报告中心", "Pentest Report Center")}
  </div>
  <div class="page-sub">{t("查看所有自动化渗透测试的结果", "View all automated penetration test results")}</div>
</div>
<div class="card">
  <div class="empty">
    <div class="empty-icon">📋</div>
    <p style="font-size:1rem;margin-bottom:10px">{t("暂无报告", "No Reports Yet")}</p>
    <p style="font-size:.84rem">
      {t("运行", "Run")} <code>python scripts/run_agent.py --target &lt;IP&gt;</code>
      {t("开始测试", "to start a test")}
    </p>
  </div>
</div>"""
        return base_page("报告中心", body, "home", "Report Center")

    # ── Summary stats ──────────────────────────────────────────────────────
    total_sessions = len(sessions)
    all_vulns = sum(len(s.get("vulnerabilities", [])) for s in sessions)
    all_crit  = sum(sev_counts(s)["critical"] for s in sessions)
    all_high  = sum(sev_counts(s)["high"]     for s in sessions)
    all_exp   = sum(s.get("metrics", {}).get("exploited_count", 0) for s in sessions)

    stat_html = f"""<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-num stat-ok">{total_sessions}</div>
    <div class="stat-label">{t("扫描会话", "Scan Sessions")}</div>
  </div>
  <div class="stat-card">
    <div class="stat-num">{all_vulns}</div>
    <div class="stat-label">{t("发现漏洞总计", "Total Vulnerabilities")}</div>
  </div>
  <div class="stat-card">
    <div class="stat-num stat-crit">{all_crit}</div>
    <div class="stat-label">{t("严重漏洞", "Critical Vulns")}</div>
  </div>
  <div class="stat-card">
    <div class="stat-num stat-high">{all_high}</div>
    <div class="stat-label">{t("高危漏洞", "High Vulns")}</div>
  </div>
  <div class="stat-card">
    <div class="stat-num stat-ok">{all_exp}</div>
    <div class="stat-label">{t("成功利用", "Exploited")}</div>
  </div>
</div>"""

    # ── Session cards ───────────────────────────────────────────────────────
    cards = []
    for s in sessions:
        sid    = s["_session_id"]
        target = he(s.get("target", "unknown"))
        gen_at = fmt_dt(s.get("generated_at", ""))
        m      = s.get("metrics", {})
        dur    = fmt_duration(m.get("total_scan_time_seconds", 0))
        iters  = m.get("total_iterations", 0)
        sc     = sev_counts(s)
        total_v = sum(sc.values())

        risk_cls, risk_zh, risk_en = risk_level(sc)
        sev_badges = "".join(
            f'<span class="badge sev-{sev}">{sc[sev]} {t(SEV_ZH[sev], SEV_EN[sev])}</span>'
            for sev in ["critical", "high", "medium", "low", "info"] if sc[sev] > 0
        ) or f'<span class="tag tag-green">{t("无漏洞","Clean")}</span>'

        search_text = he(f"{target} {sid}".lower())
        cards.append(f"""
<div class="session-card" data-search-text="{search_text}">
  <div style="flex:1;min-width:0">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <span class="session-target">🎯 {target}</span>
      <span class="risk-badge {risk_cls}">{t(risk_zh, risk_en)}</span>
      <span class="tag">{total_v} {t("个漏洞","vulns")}</span>
      <span class="tag">⏱ {dur}</span>
      <span class="tag">{iters} {t("轮","iters")}</span>
    </div>
    <div class="session-meta">{gen_at} &nbsp;·&nbsp; <code style="font-size:.75rem">{sid[:20]}…</code></div>
    <div class="session-sevs">{sev_badges}</div>
    {sev_bar(sc)}
  </div>
  <div class="session-actions">
    <a href="/session/{sid}" class="btn btn-primary">{t("查看详情","Details")}</a>
    <a href="/session/{sid}/raw" class="btn btn-outline">{t("原始 MD","Raw MD")}</a>
    <a href="/session/{sid}/download" class="btn btn-outline btn-sm"
      data-title-zh="下载 MD" data-title-en="Download MD">↓ MD</a>
  </div>
</div>""")

    body = f"""
<div class="page-header">
  <div class="page-title">🛡️ {t("渗透测试报告中心", "Pentest Report Center")}</div>
  <div class="page-sub">{t(f"共 {total_sessions} 次扫描记录，按时间倒序排列",
                             f"{total_sessions} scan session(s), newest first")}</div>
</div>
<div class="card">{stat_html}</div>
<div class="session-search-wrap">
  <div class="search-wrap" style="max-width:100%">
    <span class="search-icon">🔍</span>
    <input id="session-search" class="search-input"
      placeholder="搜索目标 IP 或会话 ID…"
      data-ph-zh="搜索目标 IP 或会话 ID…" data-ph-en="Search target IP or session ID…"
      oninput="filterSessions(this.value)">
  </div>
</div>
{"".join(cards)}"""

    return base_page("报告中心", body, "home", "Report Center")


@app.route("/session/<session_id>")
def session_detail(session_id: str):
    s = load_session(session_id)
    if not s:
        abort(404)

    target  = he(s.get("target", "unknown"))
    gen_at  = fmt_dt(s.get("generated_at", ""))
    m       = s.get("metrics", {})
    dur     = fmt_duration(m.get("total_scan_time_seconds", 0))
    iters   = m.get("total_iterations", 0)
    sc      = sev_counts(s)
    vulns   = s.get("vulnerabilities", [])
    recs    = s.get("recommendations", [])
    summary = s.get("executive_summary", "")
    risk_cls, risk_zh, risk_en = risk_level(sc)

    # ── Stats ───────────────────────────────────────────────────────────────
    stat_html = f"""<div class="stats-grid">
  <div class="stat-card"><div class="stat-num stat-crit">{sc['critical']}</div>
    <div class="stat-label">{t("严重","Critical")}</div></div>
  <div class="stat-card"><div class="stat-num stat-high">{sc['high']}</div>
    <div class="stat-label">{t("高危","High")}</div></div>
  <div class="stat-card"><div class="stat-num stat-med">{sc['medium']}</div>
    <div class="stat-label">{t("中危","Medium")}</div></div>
  <div class="stat-card"><div class="stat-num stat-low">{sc['low']}</div>
    <div class="stat-label">{t("低危","Low")}</div></div>
  <div class="stat-card"><div class="stat-num stat-dim">{sc['info']}</div>
    <div class="stat-label">{t("信息","Info")}</div></div>
  <div class="stat-card"><div class="stat-num stat-ok">{m.get('exploited_count',0)}</div>
    <div class="stat-label">{t("已利用","Exploited")}</div></div>
  <div class="stat-card"><div class="stat-num">{dur}</div>
    <div class="stat-label">{t("扫描耗时","Duration")}</div></div>
  <div class="stat-card"><div class="stat-num">{iters}</div>
    <div class="stat-label">{t("迭代次数","Iterations")}</div></div>
</div>"""

    # ── Executive summary ───────────────────────────────────────────────────
    summary_html = (
        f'<p style="font-size:.9rem;line-height:1.75">{he(summary)}</p>'
        if summary else
        f'<p style="color:var(--dim)">{t("无摘要","No summary available")}</p>'
    )

    # ── Donut + legend ──────────────────────────────────────────────────────
    legend = "".join(
        f'<div class="legend-item">'
        f'<div class="legend-dot" style="background:{SEV_COLORS[sv]}"></div>'
        f'<span>{t(SEV_ZH[sv], SEV_EN[sv])}</span>'
        f'<b class="legend-count">{sc[sv]}</b>'
        f'</div>'
        for sv in ["critical", "high", "medium", "low", "info"]
    )
    chart_html = f'<div class="chart-wrap">{donut_svg(sc)}<div class="chart-legend">{legend}</div></div>'

    # ── Stage timeline ──────────────────────────────────────────────────────
    completed_stages = s.get("stages_completed", [])
    if isinstance(completed_stages, (int, float)):
        completed_stages = []
    tl_html = stage_timeline(completed_stages)

    # ── Vulnerability table ─────────────────────────────────────────────────
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_vulns = sorted(vulns, key=lambda v: SEV_ORDER.get(v.get("severity", "info"), 5))

    # Filter buttons
    filter_btns = f"""
<div class="filter-toolbar">
  <button class="filter-btn active" data-filter="all" onclick="filterVulns('all',this)">
    {t("全部","All")} ({len(sorted_vulns)})
  </button>
  {"".join(
    f'<button class="filter-btn" data-filter="{sv}" onclick="filterVulns(\'{sv}\',this)" '
    f'style="color:{SEV_COLORS[sv]};border-color:{SEV_COLORS[sv]}">'
    f'{t(SEV_ZH[sv], SEV_EN[sv])} ({sc[sv]})</button>'
    for sv in ["critical","high","medium","low","info"] if sc[sv] > 0
  )}
  <div class="search-wrap">
    <span class="search-icon">🔍</span>
    <input id="vuln-search" class="search-input"
      placeholder="搜索漏洞…"
      data-ph-zh="搜索漏洞…" data-ph-en="Search vulnerabilities…"
      oninput="searchVulns(this.value)">
  </div>
  <div style="margin-left:auto;display:flex;gap:6px">
    <button class="btn btn-outline btn-sm" onclick="expandAll()">
      {t("展开全部","Expand All")}
    </button>
    <button class="btn btn-outline btn-sm" onclick="collapseAll()">
      {t("折叠全部","Collapse All")}
    </button>
  </div>
</div>"""

    vuln_rows = ""
    for i, v in enumerate(sorted_vulns):
        sev   = (v.get("severity") or "info").lower()
        cve   = he(v.get("cve_id") or "")
        exp   = v.get("exploited", False)
        comp  = he(v.get("affected_component") or "—")
        tool  = he(v.get("discovered_by_tool") or "—")
        title = he(v.get("title") or "—")
        desc  = he(v.get("description") or "")[:400]
        evid  = (v.get("evidence") or "")[:600]
        rem   = he(v.get("remediation") or "")
        detail_id = f"vuln-detail-{i}"

        exp_tag = f'<span class="tag tag-red" style="margin-left:5px">{t("已利用","Exploited")}</span>' if exp else ""
        cve_tag = f'<span class="tag tag-blue" style="margin-left:4px">{cve}</span>' if cve else ""
        search_text = f"{title} {comp} {desc} {cve}".lower()

        vuln_rows += f"""
<tr class="vuln-data-row" id="row-{i}" data-sev="{sev}" data-detail-id="{detail_id}"
    data-search-text="{he(search_text)}" onclick="toggle('{detail_id}')">
  <td style="width:110px"><span class="badge sev-{sev}">{t(SEV_ZH[sev],SEV_EN[sev])}</span></td>
  <td>
    <div class="vuln-title">
      <span id="arrow-{detail_id}" class="expand-arrow">▶</span>
      {title}{exp_tag}{cve_tag}
    </div>
    <div class="vuln-component">
      {comp} &nbsp;·&nbsp; {t("发现工具","Tool")}: {tool}
    </div>
  </td>
</tr>
<tr id="{detail_id}" style="display:none">
  <td colspan="2" style="padding:0 12px 14px">
    <div class="vuln-detail">
      <div class="detail-label">{t("描述","Description")}</div>
      <div style="line-height:1.6">{desc}</div>
      {"<div class='detail-label'>" + t('证据','Evidence') + "</div><pre>" + he(evid) + "<button class='btn-copy btn-sm' onclick=\"event.stopPropagation();copyText(" + repr(evid) + ",this)\" style='float:right;margin-top:-2px'>⎘</button></pre>" if evid else ""}
      {"<div class='detail-label'>" + t('修复建议','Remediation') + "</div><div style='line-height:1.6;margin-top:4px'>" + rem + "</div>" if rem else ""}
    </div>
  </td>
</tr>"""

    vuln_table = (
        filter_btns +
        f"""<table class="vuln-table">
  <thead><tr>
    <th>{t("严重程度","Severity")}</th>
    <th>{t("漏洞详情","Vulnerability")} <span style="color:var(--dim);font-size:.73rem;font-weight:400">({t("点击展开","click to expand")})</span></th>
  </tr></thead>
  <tbody>{vuln_rows}</tbody>
</table>"""
    ) if sorted_vulns else f'<div class="alert alert-ok">✅ {t("未发现漏洞","No vulnerabilities found")}</div>'

    # ── Recommendations ─────────────────────────────────────────────────────
    rec_html = ""
    for i, rec in enumerate(recs):
        if isinstance(rec, dict):
            en = he(rec.get("en", rec.get("text", "")))
            zh = he(rec.get("zh", ""))
        else:
            en = he(str(rec)); zh = ""
        rec_html += f'<div class="rec-item"><div class="rec-en"><span class="rec-num">{i+1}.</span>{en}</div>'
        if zh:
            rec_html += f'<div class="rec-zh">{zh}</div>'
        rec_html += "</div>"
    if not rec_html:
        rec_html = f'<p style="color:var(--dim);font-size:.87rem">{t("暂无建议","No recommendations")}</p>'

    # ── Infrastructure ──────────────────────────────────────────────────────
    hosts_data = s.get("hosts_discovered", s.get("hosts", []))
    infra_html = ""
    for h in hosts_data:
        ip  = he(h.get("ip", "?"))
        hn  = he(h.get("hostname") or "")
        os_ = he(h.get("os") or "Unknown")
        svcs = h.get("services", [])
        ports_html = "".join(
            f'<div class="port-row">'
            f'<span class="port-num">{he(str(sv.get("port","?")))}/{he(sv.get("protocol","tcp"))}</span>'
            f'<span>{he(sv.get("service","?"))} {he(sv.get("version") or "")}</span>'
            f'</div>'
            for sv in svcs
        )
        infra_html += f"""<div class="infra-host">
  <h4>🖥 {ip} {("(" + hn + ")") if hn else ""}</h4>
  <div style="font-size:.78rem;color:var(--dim);margin-bottom:8px">
    OS: {os_} &nbsp;·&nbsp; {len(svcs)} {t("个开放端口","open port(s)")}
  </div>
  {ports_html or f'<div style="color:var(--dim);font-size:.8rem">{t("无端口信息","No port data")}</div>'}
</div>"""

    infra_section = (
        f'<div class="infra-grid">{infra_html}</div>'
        if infra_html else
        f'<p style="color:var(--dim);font-size:.87rem">{t("暂无基础设施信息","No infrastructure data")}</p>'
    )

    # ── Assemble body ───────────────────────────────────────────────────────
    body = f"""
<div class="page-header">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px">
    <div>
      <div style="font-size:.8rem;color:var(--dim);margin-bottom:5px">
        <a href="/">← {t("返回列表","Back to List")}</a>
      </div>
      <div class="page-title">
        🎯 {target}
        <span class="risk-badge {risk_cls}">{t(risk_zh, risk_en)}</span>
      </div>
      <div class="page-sub">
        {gen_at} &nbsp;·&nbsp; <code style="font-size:.78rem">{session_id}</code>
      </div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-start">
      <a href="/session/{session_id}/raw" class="btn btn-outline">{t("原始 Markdown","Raw Markdown")}</a>
      <a href="/session/{session_id}/download" class="btn btn-outline">↓ {t("下载","Download")} .md</a>
      <a href="/api/session/{session_id}" class="btn btn-outline">↓ JSON</a>
      <button class="btn btn-outline" onclick="window.print()">🖨 {t("打印","Print")}</button>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-title">📊 {t("扫描指标","Scan Metrics")}</div>
  {stat_html}
  <div style="margin-top:12px">
    <div style="font-size:.78rem;color:var(--dim);margin-bottom:8px;text-transform:uppercase;letter-spacing:.4px">
      {t("测试阶段进度","Test Stage Progress")}
    </div>
    {tl_html}
  </div>
</div>

<div class="card">
  <div class="card-title">📝 {t("执行摘要","Executive Summary")}</div>
  {summary_html}
</div>

<div class="card two-col" style="display:flex;gap:24px;align-items:flex-start;flex-wrap:wrap">
  <div class="two-col-left">
    <div class="card-title">🍩 {t("漏洞分布","Vuln Distribution")}</div>
    {chart_html}
  </div>
  <div class="two-col-right">
    <div class="card-title">🔧 {t("修复建议","Recommendations")}</div>
    {rec_html}
  </div>
</div>

<div class="card">
  <div class="card-title">
    🐛 {t("漏洞详情","Vulnerabilities")}
    <span class="card-count">({len(sorted_vulns)})</span>
  </div>
  {vuln_table}
</div>

<div class="card">
  <div class="card-title">🌐 {t("发现的基础设施","Discovered Infrastructure")}</div>
  {infra_section}
</div>"""

    return base_page(f"{target} — {t('报告','Report')}", body, "", f"{target} — Report")


@app.route("/session/<session_id>/raw")
def session_raw(session_id: str):
    s = load_session(session_id)
    if not s:
        abort(404)
    md = s.get("_markdown", "")
    if not md:
        abort(404)

    body = f"""
<div style="margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
  <a href="/session/{session_id}">← {t("返回可视化报告","Back to Visual Report")}</a>
  <div style="display:flex;gap:8px">
    <a href="/session/{session_id}/download" class="btn btn-outline btn-sm">↓ {t("下载 .md","Download .md")}</a>
    <button class="btn btn-outline btn-sm" onclick="window.print()">🖨 {t("打印","Print")}</button>
  </div>
</div>
<div class="card">
  <pre class="md-raw">{he(md)}</pre>
</div>"""

    return base_page("原始报告", body, "", "Raw Report")


@app.route("/session/<session_id>/download")
def session_download(session_id: str):
    s = load_session(session_id)
    if not s:
        abort(404)
    md = s.get("_markdown", "")
    return Response(
        md,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=report-{session_id[:8]}.md"}
    )


@app.route("/api/sessions")
def api_sessions():
    sessions = load_all_sessions()
    result = []
    for s in sessions:
        sc = sev_counts(s)
        result.append({
            "session_id":   s["_session_id"],
            "target":       s.get("target"),
            "generated_at": s.get("generated_at"),
            "metrics":      s.get("metrics"),
            "sev_counts":   sc,
        })
    return Response(json.dumps(result, indent=2), mimetype="application/json")


@app.route("/api/session/<session_id>")
def api_session(session_id: str):
    s = load_session(session_id)
    if not s:
        abort(404)
    s.pop("_markdown", None)
    return Response(json.dumps(s, indent=2, default=str), mimetype="application/json")


# =============================================================================
# Entry Point / 入口
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="PentestAgent Report Server / 渗透测试报告可视化服务")
    parser.add_argument("--port",        type=int, default=8888)
    parser.add_argument("--host",        default="0.0.0.0")
    parser.add_argument("--reports-dir", default="data/reports")
    args = parser.parse_args()

    global REPORTS_DIR
    REPORTS_DIR = Path(args.reports_dir)

    print(f"\n  PentestAgent Report Server / 报告服务")
    print(f"  Reports Dir / 报告目录 : {REPORTS_DIR.resolve()}")
    print(f"  URL                    : http://localhost:{args.port}")
    print(f"  Language / 语言切换     : Click EN / 中文 button in the nav\n")

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
