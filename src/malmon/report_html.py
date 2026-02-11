from __future__ import annotations

"""HTML report renderer for MalMon.

Design goals:
- Convert report.json -> report.html **fully** (no missing fields).
- Keep the output readable (tables for common structures, collapsible blocks for large data).
- Do **not** embed/preview ETW XML content in the HTML (large XML can crash browsers).
- Still link to produced artifacts (XML, MMD, TXT, JSON) as separate files.
"""

import argparse
import datetime as dt
import html
import json
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


def _esc(s: Any) -> str:
    return html.escape("" if s is None else str(s))


def _json_pretty(v: Any) -> str:
    return json.dumps(v, indent=2, ensure_ascii=False)


def _is_scalar(v: Any) -> bool:
    return v is None or isinstance(v, (str, int, float, bool))


def _type_label(v: Any) -> str:
    if isinstance(v, dict):
        return f"dict({len(v)})"
    if isinstance(v, list):
        return f"list({len(v)})"
    return type(v).__name__


def _looks_like_pairs_list(v: Any) -> bool:
    if not isinstance(v, list):
        return False
    if not v:
        return False
    for it in v:
        if not (isinstance(it, (list, tuple)) and len(it) == 2):
            return False
        if not _is_scalar(it[0]) or not _is_scalar(it[1]):
            return False
    return True


def _looks_like_list_of_dicts(v: Any) -> bool:
    if not isinstance(v, list):
        return False
    if not v:
        return False
    return all(isinstance(it, dict) for it in v)


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]], table_id: Optional[str] = None) -> str:
    tid = f" id='{_esc(table_id)}'" if table_id else ""
    th = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    tr = []
    for r in rows:
        tds = "".join(f"<td>{c}</td>" for c in r)
        tr.append(f"<tr>{tds}</tr>")
    return f"<table{tid}><thead><tr>{th}</tr></thead><tbody>{''.join(tr)}</tbody></table>"


def _cell(v: Any) -> str:
    """Render a value inside a table cell.

    Never truncates.
    Complex values are shown as collapsible pretty JSON.
    """
    if _is_scalar(v):
        # keep long strings readable
        if isinstance(v, str) and ("\n" in v or len(v) > 160):
            return f"<pre class='scalar'>{_esc(v)}</pre>"
        return f"<span class='scalar'>{_esc(v)}</span>"

    # complex
    body = _esc(_json_pretty(v))
    return (
        "<details class='cell-details'>"
        f"<summary>{_esc(_type_label(v))}</summary>"
        f"<pre>{body}</pre>"
        "</details>"
    )


def _render_pairs_list(title: str, items: List[Sequence[Any]], table_id: str) -> str:
    rows = [[_cell(k), _cell(v)] for k, v in items]
    return (
        f"<div class='block-title'>{_esc(title)}</div>"
        f"<input class='filter' placeholder='Filter…' data-target='{_esc(table_id)}' />"
        + _table(["Key", "Value"], rows, table_id=table_id)
    )


def _render_list_of_dicts(title: str, items: List[Dict[str, Any]], table_id: str) -> str:
    # stable-ish column ordering: common keys first, then alphabetical remainder
    cols: List[str] = []
    freq: Dict[str, int] = {}
    for it in items:
        for k in it.keys():
            freq[k] = freq.get(k, 0) + 1
    cols = sorted(freq.keys(), key=lambda k: (-freq[k], k))

    rows: List[List[str]] = []
    for it in items:
        rows.append([_cell(it.get(c)) for c in cols])

    return (
        f"<div class='block-title'>{_esc(title)}</div>"
        f"<input class='filter' placeholder='Filter…' data-target='{_esc(table_id)}' />"
        + _table(cols, rows, table_id=table_id)
    )


_ID_COUNTER = 0


def _next_id(prefix: str = "t") -> str:
    global _ID_COUNTER
    _ID_COUNTER += 1
    return f"{prefix}{_ID_COUNTER}"


def _render_value(name: str, v: Any, depth: int = 0) -> str:
    """Recursive renderer that guarantees full coverage."""
    # Scalars
    if _is_scalar(v):
        return f"<div class='kv'><div class='k'>{_esc(name)}</div><div class='v'>{_cell(v)}</div></div>"

    # Dict
    if isinstance(v, dict):
        inner: List[str] = []
        # Prefer a key/value table view (with recursion) for dicts.
        for k in sorted(v.keys(), key=lambda x: str(x)):
            inner.append(_render_value(str(k), v[k], depth + 1))

        inner_html = "".join(inner) if inner else "<div class='muted'>empty</div>"

        open_attr = " open" if depth <= 0 else ""
        return (
            f"<details class='node'{open_attr}>"
            f"<summary><span class='node-name'>{_esc(name)}</span> <span class='muted'>({_esc(_type_label(v))})</span></summary>"
            f"<div class='node-body'>{inner_html}</div>"
            "</details>"
        )

    # List
    if isinstance(v, list):
        open_attr = " open" if depth <= 0 else ""
        body = ""
        # Recognize common shapes and render as tables
        if _looks_like_pairs_list(v):
            table_id = _next_id("pairs")
            body = _render_pairs_list("Items", v, table_id)
        elif _looks_like_list_of_dicts(v):
            table_id = _next_id("lod")
            body = _render_list_of_dicts("Items", v, table_id)
        else:
            # generic list
            parts: List[str] = []
            for i, it in enumerate(v):
                parts.append(_render_value(f"[{i}]", it, depth + 1))
            body = "".join(parts) if parts else "<div class='muted'>empty</div>"

        return (
            f"<details class='node'{open_attr}>"
            f"<summary><span class='node-name'>{_esc(name)}</span> <span class='muted'>({_esc(_type_label(v))})</span></summary>"
            f"<div class='node-body'>{body}</div>"
            "</details>"
        )

    # Fallback
    return f"<div class='kv'><div class='k'>{_esc(name)}</div><div class='v'><pre>{_esc(_json_pretty(v))}</pre></div></div>"


def _section(title: str, anchor: str, body: str) -> str:
    return f"<section id='{_esc(anchor)}'><h2>{_esc(title)}</h2>{body}</section>"


def _copy_if_needed(src: Path, dst_dir: Path) -> str:
    """Copy file next to the HTML so relative links work.

    Returns the filename to link to (relative).
    """
    try:
        if not src.exists() or not src.is_file():
            return src.name
        dst = dst_dir / src.name
        if dst.exists():
            return dst.name
        if dst.resolve() == src.resolve():
            return dst.name
        shutil.copy2(src, dst)
        return dst.name
    except Exception:
        return src.name


def _artifact_links(report: Dict[str, Any], base_dir: Path, html_dir: Path) -> List[List[str]]:
    """Build a table of output artifacts with clickable relative links."""
    arts = report.get("artifacts", {}) or {}
    rows: List[List[str]] = []
    if not isinstance(arts, dict):
        return rows

    for k in sorted(arts.keys()):
        v = arts.get(k)
        if not isinstance(v, str) or not v:
            rows.append([_esc(k), _cell(v)])
            continue

        p = Path(v)
        if not p.is_absolute():
            p = (base_dir / p).resolve()

        if p.exists() and p.is_file():
            rel_name = _copy_if_needed(p, html_dir)
            link = f"<a href='{_esc(rel_name)}' target='_blank'>{_esc(rel_name)}</a>"
            rows.append([_esc(k), link])
        else:
            rows.append([_esc(k), _esc(v)])
    return rows


def render_report_html(report: Dict[str, Any], *, base_dir: Path, out_path: Path) -> str:
    tool = report.get("tool", {}) or {}
    generated = dt.datetime.now().isoformat(timespec="seconds")

    # Nav
    nav_items = [
        ("Status", "status"),
        ("Process", "process"),
        ("Files", "files"),
        ("Network", "network"),
        ("Registry", "registry"),
        ("Artifacts", "artifacts"),
        ("Config", "config"),
        ("Full JSON", "full-json"),
    ]

    nav_html = "".join(
        f"<a class='navlink' href='#{_esc(a)}'>{_esc(t)}</a>" for t, a in nav_items
    )

    # Status: lightweight summary + subsystems
    status = report.get("status", {}) or {}
    subs = status.get("subsystems") or {}
    subs_rows = []
    if isinstance(subs, dict):
        for k in sorted(subs.keys()):
            v = subs.get(k) or {}
            subs_rows.append([_esc(k), _esc(v.get("status")), _esc(v.get("note"))])

    status_summary = _table(
        ["Field", "Value"],
        [
            ["admin", _cell(status.get("admin"))],
            ["root_pid", _cell(status.get("root_pid"))],
            ["tracked_count", _cell(status.get("tracked_count"))],
            ["tracked_live_count", _cell(status.get("tracked_live_count"))],
            ["out_dir", _cell(status.get("out_dir"))],
        ],
    )
    if subs_rows:
        status_summary += "<div class='block-title'>Subsystems</div>" + _table(
            ["Name", "Status", "Note"], subs_rows, table_id=_next_id("subs")
        )

    # Process: tree + table
    proc = report.get("process", {}) or {}
    tree = proc.get("tree")
    tree_txt = ""
    if isinstance(tree, dict):
        lines: List[str] = []

        def walk(n: Dict[str, Any], pref: str = "") -> None:
            pid = n.get("pid")
            img = n.get("image") or "unknown"
            lines.append(f"{pref}- {pid} ({img})")
            for c in (n.get("children") or []):
                if isinstance(c, dict):
                    walk(c, pref + "  ")

        walk(tree)
        tree_txt = "\n".join(lines)
    else:
        tree_txt = "<no tree available>"

    proc_body = "<div class='block-title'>Process Tree</div>" + f"<pre>{_esc(tree_txt)}</pre>"
    process_table = proc.get("process_table") or []
    if isinstance(process_table, list) and process_table:
        # Render as list-of-dicts table (keeps all columns)
        proc_body += _render_list_of_dicts("Processes (tracked)", process_table, _next_id("procs"))

    # Files / Network / Registry: render via generic renderer (guaranteed full coverage)
    files_body = _render_value("files", report.get("files", {}), depth=0)
    net_body = _render_value("network", report.get("network", {}), depth=0)
    reg_body = _render_value("registry", report.get("registry", {}), depth=0)

    # Artifacts: special linked table + also full dict view
    art_rows = _artifact_links(report, base_dir=base_dir, html_dir=out_path.parent)
    art_body = ""
    if art_rows:
        art_body += _table(["Key", "File"], art_rows, table_id=_next_id("arts"))
    art_body += "<details class='node'><summary><span class='node-name'>artifacts (raw)</span></summary><div class='node-body'>" + _render_value(
        "artifacts", report.get("artifacts", {}), depth=1
    ) + "</div></details>"

    config_body = _render_value("config", report.get("config", {}), depth=0)

    # Full JSON explorer (ensures nothing is missing)
    full_json_body = (
        "<p class='muted'>This section renders the entire report.json recursively. Nothing is omitted.</p>"
        + _render_value("report", report, depth=0)
    )

    css = """
    :root{--bg:#0b0f14;--card:#111826;--text:#e5e7eb;--muted:#9ca3af;--border:#243041;--accent:#60a5fa;--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace}
    body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.35}
    header{padding:18px 20px;border-bottom:1px solid var(--border);background:linear-gradient(180deg,#0b0f14,#0b0f14 55%,#0e1522)}
    h1{margin:0 0 6px 0;font-size:20px}
    .meta{color:var(--muted);font-size:13px;display:flex;flex-wrap:wrap;gap:10px}
    .wrap{word-break:break-word;overflow-wrap:anywhere}
    main{padding:16px 20px;max-width:1180px;margin:0 auto}
    section{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:14px 14px 8px 14px;margin:14px 0}
    h2{margin:0 0 10px 0;font-size:15px;color:#dbeafe}
    a{color:var(--accent);text-decoration:none}
    a:hover{text-decoration:underline}
    .muted{color:var(--muted)}
    .nav{position:sticky;top:0;z-index:5;background:rgba(11,15,20,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--border)}
    .navinner{max-width:1180px;margin:0 auto;padding:10px 20px;display:flex;gap:10px;flex-wrap:wrap}
    .navlink{padding:6px 10px;border:1px solid var(--border);border-radius:999px;color:#c7d2fe;font-size:13px}
    .navlink:hover{border-color:#3b82f6}
    .block-title{margin:12px 0 8px 0;font-size:13px;color:#c7d2fe}
    pre{background:#0b1220;border:1px solid var(--border);border-radius:12px;padding:12px;overflow:auto;white-space:pre-wrap}
    pre.scalar{font-family:var(--mono);font-size:12px}
    table{width:100%;border-collapse:collapse;margin:8px 0 12px 0;font-size:13px}
    th,td{border-bottom:1px solid var(--border);padding:8px 10px;vertical-align:top}
    th{color:#c7d2fe;text-align:left;font-weight:600;position:sticky;top:0;background:#0e1522}
    td{color:var(--text)}
    .filter{width:100%;max-width:420px;margin:8px 0 10px 0;padding:8px 10px;border-radius:10px;border:1px solid var(--border);background:#0b1220;color:var(--text)}
    details{margin:8px 0}
    summary{cursor:pointer;color:#c7d2fe}
    .node{border:1px solid var(--border);border-radius:12px;padding:8px 10px;background:#0e1522}
    .node-body{padding:8px 6px 2px 6px}
    .node-name{font-family:var(--mono);font-size:12px}
    .kv{display:grid;grid-template-columns: minmax(160px, 220px) 1fr;gap:10px;padding:6px 2px;border-bottom:1px dashed rgba(36,48,65,.6)}
    .kv:last-child{border-bottom:none}
    .k{font-family:var(--mono);font-size:12px;color:#c7d2fe}
    .v{min-width:0}
    .scalar{font-family:var(--mono);font-size:12px;white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere}
    .cell-details pre{max-height:55vh}
    """

    js = """
    (function(){
      function filterTable(input){
        const id = input.getAttribute('data-target');
        const table = document.getElementById(id);
        if(!table) return;
        const q = (input.value || '').toLowerCase();
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(tr => {
          const txt = tr.innerText.toLowerCase();
          tr.style.display = txt.indexOf(q) >= 0 ? '' : 'none';
        });
      }
      document.querySelectorAll('input.filter').forEach(inp => {
        inp.addEventListener('input', () => filterTable(inp));
        filterTable(inp);
      });
    })();
    """

    header = (
        f"<h1>MalMon Report</h1>"
        f"<div class='meta'>"
        f"<span><span class='muted'>Generated:</span> {_esc(generated)}</span>"
        f"<span><span class='muted'>Tool:</span> {_esc(tool.get('name','MalMon'))} {_esc(tool.get('version',''))}</span>"
        f"<span><span class='muted'>Mode:</span> {_esc(tool.get('mode',''))}</span>"
        f"<span><span class='muted'>Start:</span> {_esc(tool.get('start_utc',''))}</span>"
        f"<span><span class='muted'>End:</span> {_esc(tool.get('end_utc',''))}</span>"
        f"</div>"
    )

    return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>MalMon Report</title>
  <style>{css}</style>
</head>
<body>
  <header>{header}</header>
  <div class='nav'><div class='navinner'>{nav_html}</div></div>

  <main>
    {_section('Status', 'status', status_summary + _render_value('status (raw)', status, depth=1))}
    {_section('Process', 'process', proc_body)}
    {_section('Files', 'files', files_body)}
    {_section('Network', 'network', net_body)}
    {_section('Registry', 'registry', reg_body)}
    {_section('Artifacts', 'artifacts', art_body)}
    {_section('Config', 'config', config_body)}
    {_section('Full JSON', 'full-json', full_json_body)}
  </main>

  <script>{js}</script>
</body>
</html>
"""


def write_html_report(report: Dict[str, Any], out_path: Path, base_dir: Optional[Path] = None) -> None:
    """Write a single HTML report next to the run output.

    - Does not embed XML.
    - Links artifacts as separate files (copies them next to the HTML if needed).
    """
    base_dir = (base_dir or out_path.parent).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    html_text = render_report_html(report, base_dir=base_dir, out_path=out_path)
    out_path.write_text(html_text, encoding='utf-8')


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog='malmon2html',
        description='Convert MalMon report.json to report.html (full coverage; no XML embedding).',
    )
    ap.add_argument('json_report', help='Path to report.json')
    ap.add_argument('--out', default=None, help='Output HTML path (default: beside report.json as report.html)')
    args = ap.parse_args(argv)

    in_path = Path(args.json_report)
    if not in_path.exists():
        print(f"[ERROR] JSON report not found: {in_path}")
        return 2

    out_path = Path(args.out) if args.out else (in_path.parent / 'report.html')
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        report = json.loads(in_path.read_text(encoding='utf-8'))
    except Exception as e:
        print(f"[ERROR] Failed to read JSON: {type(e).__name__}: {e}")
        return 3

    try:
        write_html_report(report, out_path, base_dir=in_path.parent)
        print(f"[OK] Wrote: {out_path}")
        return 0
    except Exception as e:
        print(f"[ERROR] Failed to write HTML: {type(e).__name__}: {e}")
        return 4


if __name__ == '__main__':
    raise SystemExit(main())
