from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from .monitor import FlowMonMonitor
from .utils import clamp, is_windows, normalize_image, resolve_exe

# -----------------------------
# CLI parsing (flex common options anywhere)
# -----------------------------

COMMON_SPECS = {
    "--duration": ("duration", True, int),
    "--grace": ("grace", True, int),
    "--poll-ms": ("poll_ms", True, int),
    "--out": ("out", True, str),
    "--disable-etw": ("disable_etw", False, bool),
    "--disable-network": ("disable_network", False, bool),
    "--disable-registry": ("disable_registry", False, bool),
    "--raw-network": ("raw_network", False, bool),
    "--raw-registry": ("raw_registry", False, bool),
    "--max-raw-events": ("max_raw_events", True, int),
    "--ignore-image": ("ignore_image", True, str),  # repeatable
    "--max-nodes": ("max_nodes", True, int),
    "--max-depth": ("max_depth", True, int),
    "--office-attach-timeout": ("office_attach_timeout", True, int),
    "--disable-files": ("disable_files", False, bool),
    "--out-html": ("out_html", True, str),
    "--disable-html": ("disable_html", False, bool),
}



def default_cfg() -> Dict[str, Any]:
    return {
        "duration": 30,
        "grace": 3,
        "poll_ms": 1000,
        "out": "MalMon_output",
        "disable_etw": False,
        "disable_network": False,
        "disable_registry": False,
        "raw_network": False,
        "raw_registry": False,
        "max_raw_events": 2000,
        "ignore_image": [],
        "max_nodes": 120,
        "max_depth": 10,
        "office_attach_timeout": 15,
        "disable_files": False,
        "disable_html": False,
        "out_html": None,
    }

def extract_common(tokens: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Extract known common options from anywhere in tokens.
    Supports '--' separator: once seen, stop extracting and leave rest untouched.
    """
    cfg = default_cfg()
    out: List[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == "--":
            out.extend(tokens[i:])  # keep the rest
            break

        spec = COMMON_SPECS.get(t)
        if not spec:
            out.append(t)
            i += 1
            continue

        key, takes_value, cast = spec
        # optional value: --out-html may be used with no explicit path
        if key == "out_html":
            if (i + 1 >= len(tokens)) or tokens[i + 1].startswith("--"):
                cfg[key] = "__DEFAULT__"
                i += 1
                continue
        if not takes_value:
            cfg[key] = True
            i += 1
            continue

        if i + 1 >= len(tokens):
            out.append(t)
            i += 1
            continue

        raw = tokens[i + 1]
        try:
            val = cast(raw) if cast is not bool else True
            if key == "ignore_image":
                cfg[key].append(raw)
            else:
                cfg[key] = val
        except Exception:
            out.append(t)
            out.append(raw)
        i += 2

    cfg["duration"] = clamp(int(cfg["duration"]), 1, 24 * 3600)
    cfg["grace"] = clamp(int(cfg["grace"]), 0, 120)
    cfg["poll_ms"] = clamp(int(cfg["poll_ms"]), 200, 60000)
    cfg["max_raw_events"] = clamp(int(cfg["max_raw_events"]), 0, 200000)
    cfg["max_nodes"] = clamp(int(cfg["max_nodes"]), 10, 2000)
    cfg["max_depth"] = clamp(int(cfg["max_depth"]), 1, 50)
    cfg["office_attach_timeout"] = clamp(int(cfg["office_attach_timeout"]), 5, 120)
    # normalize out_html sentinel
    if cfg.get("out_html") == "__DEFAULT__":
        cfg["out_html"] = None
    return cfg, out

def build_help_parser() -> argparse.ArgumentParser:
    from .constants import TOOL_NAME
    p = argparse.ArgumentParser(prog=TOOL_NAME, add_help=True)
    p.add_argument("--full-help", action="store_true", help="Print full help for all subcommands")
    sub = p.add_subparsers(dest="cmd")

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--duration", type=int, default=30, help="Monitoring window in seconds (default: 30)")
        sp.add_argument("--grace", type=int, default=3, help="Grace after last tracked exit before stopping (default: 3)")
        sp.add_argument("--poll-ms", type=int, default=1000, help="Poll interval in ms (default: 1000)")
        sp.add_argument("--out", type=str, default="MalMon_output", help="Output directory (default: MalMon_output)")
        sp.add_argument("--out-html", nargs="?", const="__DEFAULT__", default=None, help="Write HTML report to this path (default: <out>\\report.html). You can pass only --out-html to use the default.")
        sp.add_argument("--disable-etw", action="store_true", help="Disable ETW")
        sp.add_argument("--disable-network", action="store_true", help="Disable network monitoring")
        sp.add_argument("--disable-registry", action="store_true", help="Disable registry monitoring")
        sp.add_argument("--raw-network", action="store_true", help="Include raw network events (capped)")
        sp.add_argument("--raw-registry", action="store_true", help="Include raw registry events (capped)")
        sp.add_argument("--max-raw-events", type=int, default=2000, help="Cap for raw events (default: 2000)")
        sp.add_argument("--ignore-image", action="append", default=[], help="Ignore child processes by image name (repeatable)")
        sp.add_argument("--max-nodes", type=int, default=120, help="Max nodes in process_tree.mmd (default: 120)")
        sp.add_argument("--max-depth", type=int, default=10, help="Max depth in process_tree.mmd (default: 10)")
        sp.add_argument("--office-attach-timeout", type=int, default=15, help="Office attach timeout seconds (default: 15)")
        sp.add_argument("--disable-files", action="store_true", help="Disable file monitoring (ETW Kernel-File)")
        sp.add_argument("--disable-html", action="store_true", help="Disable HTML report generation (report.html)")
    exe = sub.add_parser("exe", help="Run an EXE and monitor it", add_help=True)
    add_common(exe)
    exe.add_argument("target", help="Path or name of executable (searches PATH)")
    exe.add_argument("args", nargs=argparse.REMAINDER, help="Arguments for the executable (use -- to force pass-through)")

    off = sub.add_parser("office", help="Open an Office document and monitor Office process", add_help=True)
    add_common(off)
    off.add_argument("document", help="Path to Office document")

    wait = sub.add_parser("wait", help="Wait for a process to appear then monitor it", add_help=True)
    add_common(wait)
    wait.add_argument("--image", required=True, help="Process image name (e.g., rundll32.exe)")
    wait.add_argument("--cmd-contains", default=None, help="Substring filter on command line")
    wait.add_argument("--timeout", type=int, default=60, help="Wait timeout seconds (default: 60)")
    wait.add_argument("--allow-existing", action="store_true", help="Allow selecting already-running processes")

    return p

def print_full_help(parser: argparse.ArgumentParser) -> None:
    print(parser.format_help())
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            for name, sp in a.choices.items():
                print("\n" + "=" * 10 + f" {name} " + "=" * 10)
                print(sp.format_help())

# -----------------------------
# Modes
# -----------------------------

def mode_exe(argv_after_sub: List[str]) -> int:
    cfg, rest = extract_common(argv_after_sub)

    if not rest:
        print("[ERROR] exe: missing <path_or_name>")
        return 1

    if "--" in rest:
        idx = rest.index("--")
        target = rest[0]
        target_args = rest[1:idx] + rest[idx + 1 :]
    else:
        target = rest[0]
        target_args = rest[1:]

    mon = FlowMonMonitor(cfg, mode="exe")

    if not mon.admin and (not cfg["disable_registry"]) and (not cfg["disable_etw"]):
        mon.log("[!] Not running as Administrator? → Registry ETW disabled automatically if needed")

    mon.start_etw()

    exe_path = resolve_exe(target)
    if not exe_path:
        mon._set_sub("launcher", "failed", f"Cannot resolve executable: {target}")
        mon.stop_and_export_etw()
        mon.write_outputs()
        return 1

    creationflags = 0x08000000  # CREATE_NO_WINDOW
    try:
        p = subprocess.Popen(
            [exe_path] + target_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        mon.set_root(p.pid)
        mon.log(f"[*] Launched EXE PID={p.pid}")
        mon._set_sub("launcher", "ok", "Process started.")
    except Exception as e:
        mon._set_sub("launcher", "failed", f"{type(e).__name__}: {e}")
        mon.stop_and_export_etw()
        mon.write_outputs()
        return 1

    mon.run_for_duration()
    mon.stop_and_export_etw()
    mon.write_outputs()
    return 0

def guess_office_images(doc: Path) -> Set[str]:
    ext = doc.suffix.lower()
    if ext in (".doc", ".docx", ".docm", ".rtf"):
        return {"winword.exe"}
    if ext in (".xls", ".xlsx", ".xlsm"):
        return {"excel.exe"}
    if ext in (".ppt", ".pptx", ".pptm"):
        return {"powerpnt.exe"}
    return {"winword.exe", "excel.exe", "powerpnt.exe"}

def mode_office(argv_after_sub: List[str]) -> int:
    cfg, rest = extract_common(argv_after_sub)
    if not rest:
        print("[ERROR] office: missing <path_to_office_file>")
        return 1

    doc = Path(rest[0]).resolve()
    mon = FlowMonMonitor(cfg, mode="office")

    if not mon.admin and (not cfg["disable_registry"]) and (not cfg["disable_etw"]):
        mon.log("[!] Not running as Administrator? → Registry ETW disabled automatically if needed")

    mon.start_etw()

    if not doc.exists():
        mon._set_sub("office_launch", "failed", f"File not found: {doc}")
        mon.stop_and_export_etw()
        mon.write_outputs()
        return 1

    before = mon.snapshot_processes()
    before_pids = set(before.keys())

    try:
        os.startfile(str(doc))  # type: ignore[attr-defined]
        mon._set_sub("office_launch", "ok", "Opened via shell association.")
    except Exception as e:
        mon._set_sub("office_launch", "failed", f"{type(e).__name__}: {e}")
        mon.stop_and_export_etw()
        mon.write_outputs()
        return 1

    expected = guess_office_images(doc)
    deadline = time.time() + clamp(int(cfg["office_attach_timeout"]), 5, 120)
    chosen_pid = None

    while time.time() < deadline:
        snap = mon.snapshot_processes()
        candidates = []
        for pid, rec in snap.items():
            if pid in before_pids:
                continue
            if not rec.image:
                continue
            if normalize_image(rec.image) not in expected:
                continue
            cl = rec.cmdline or ""
            if str(doc).lower() in cl.lower():
                chosen_pid = pid
                break
            candidates.append(pid)

        if chosen_pid is not None:
            break
        if candidates:
            chosen_pid = candidates[0]
            break
        time.sleep(0.25)

    if chosen_pid is None:
        snap = mon.snapshot_processes()
        for pid, rec in snap.items():
            if rec.image and normalize_image(rec.image) in expected:
                chosen_pid = pid
        if chosen_pid is not None:
            mon._set_sub("office_attach", "degraded", "Could not match doc path; selected an existing Office instance (uncertain).")
        else:
            mon._set_sub("office_attach", "failed", "Could not identify Office process.")
            mon.stop_and_export_etw()
            mon.write_outputs()
            return 1
    else:
        mon._set_sub("office_attach", "ok", "Office process attached (best-effort).")

    mon.set_root(chosen_pid)
    mon.log(f"[*] Attached Office PID={chosen_pid}")

    mon.run_for_duration()
    mon.stop_and_export_etw()
    mon.write_outputs()
    return 0

def mode_wait(argv_after_sub: List[str]) -> int:
    cfg, rest = extract_common(argv_after_sub)

    image = None
    cmd_contains = None
    timeout = 60
    allow_existing = False

    i = 0
    while i < len(rest):
        t = rest[i]
        if t == "--image" and i + 1 < len(rest):
            image = rest[i + 1]
            i += 2
            continue
        if t == "--cmd-contains" and i + 1 < len(rest):
            cmd_contains = rest[i + 1]
            i += 2
            continue
        if t == "--timeout" and i + 1 < len(rest):
            timeout = int(rest[i + 1])
            i += 2
            continue
        if t == "--allow-existing":
            allow_existing = True
            i += 1
            continue
        print(f"[ERROR] wait: unknown option: {t}")
        return 1

    if not image:
        print("[ERROR] wait: missing --image <process_name>")
        return 1

    mon = FlowMonMonitor(cfg, mode="wait")

    if not mon.admin and (not cfg["disable_registry"]) and (not cfg["disable_etw"]):
        mon.log("[!] Not running as Administrator? → Registry ETW disabled automatically if needed")

    mon.start_etw()

    want_img = normalize_image(image)
    start = time.time()
    timeout = clamp(int(timeout), 1, 24 * 3600)

    start_snap = mon.snapshot_processes()
    existing = set(start_snap.keys())

    chosen_pid = None
    while time.time() - start < timeout:
        snap = mon.snapshot_processes()
        for pid, rec in snap.items():
            if not rec.image:
                continue
            if normalize_image(rec.image) != want_img:
                continue
            if (not allow_existing) and (pid in existing):
                continue
            if cmd_contains:
                cl = rec.cmdline or ""
                if cmd_contains.lower() not in cl.lower():
                    continue
            chosen_pid = pid
            break

        if chosen_pid is not None:
            break
        time.sleep(0.25)

    if chosen_pid is None:
        mon._set_sub("wait_match", "failed", f"Timed out waiting for {image} (timeout={timeout}s).")
        mon.stop_and_export_etw()
        mon.write_outputs()
        return 1

    mon.set_root(chosen_pid)
    mon.log(f"[*] Found process PID={chosen_pid}")
    mon._set_sub("wait_match", "ok", "Matched process.")

    mon.run_for_duration()
    mon.stop_and_export_etw()
    mon.write_outputs()
    return 0

# -----------------------------
# Main
# -----------------------------

def main(argv: List[str] | None = None) -> int:
    if not is_windows():
        print("[ERROR] MalMon is Windows-only.", file=sys.stderr)
        return 2

    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    help_parser = build_help_parser()

    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        help_parser.print_help()
        return 0

    if "--full-help" in argv:
        print_full_help(help_parser)
        return 0

    if argv[0] in ("-h", "--help"):
        help_parser.print_help()
        return 0

    cmd = argv[0].lower()
    rest = argv[1:]

    if ("-h" in rest) or ("--help" in rest):
        _ = help_parser.parse_args([cmd, "--help"])
        return 0

    if cmd == "exe":
        return mode_exe(rest)
    if cmd == "office":
        return mode_office(rest)
    if cmd == "wait":
        return mode_wait(rest)

    print(f"[ERROR] Unknown subcommand: {cmd}")
    help_parser.print_help()
    return 1
