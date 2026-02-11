from __future__ import annotations

import ctypes
import datetime as dt
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

def is_windows() -> bool:
    return os.name == "nt"

def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def run_cmd(cmd: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        return cp.returncode, (cp.stdout or "").strip(), (cp.stderr or "").strip()
    except Exception as e:
        return 999, "", f"{type(e).__name__}: {e}"

def safe_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        if isinstance(x, int):
            return x
        s = str(x).strip()
        if not s:
            return None
        return int(s)
    except Exception:
        return None

def strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag

def normalize_image(name: str) -> str:
    return Path(name).name.lower().strip()

def clean_image_name(s: Optional[str]) -> str:
    if not s:
        return "unknown"
    s = str(s).strip().strip('"').strip("'")
    base = os.path.basename(s)
    return base if base else s

def resolve_exe(token: str) -> Optional[str]:
    token = os.path.expandvars(token)
    p = Path(token)
    if p.exists() and p.is_file():
        return str(p.resolve())

    path_env = os.environ.get("PATH", "")
    pathext = os.environ.get("PATHEXT", ".EXE;.BAT;.CMD").split(";")
    has_ext = bool(Path(token).suffix)

    for d in path_env.split(";"):
        d = d.strip().strip('"')
        if not d:
            continue
        base = Path(d) / token
        if has_ext:
            if base.exists():
                return str(base.resolve())
        else:
            for ext in pathext:
                ext = ext.strip()
                if not ext:
                    continue
                cand = Path(str(base) + ext)
                if cand.exists():
                    return str(cand.resolve())
    return None

def is_loopback_ip(ip: str) -> bool:
    ip = ip.lower().strip()
    return ip == "127.0.0.1" or ip == "::1"

def loopback_canonical_endpoint(local_ip: str, local_port: int, remote_ip: str, remote_port: int) -> str:
    """
    Heuristic: for loopback connections, count the "server-ish" port (lower port / non-ephemeral).
    This collapses noisy endpoints like 127.0.0.1:53591 into 127.0.0.1:31337.
    """
    if is_loopback_ip(local_ip) and is_loopback_ip(remote_ip):
        EPHEMERAL = 49152
        local_ephem = local_port >= EPHEMERAL
        remote_ephem = remote_port >= EPHEMERAL
        if local_ephem != remote_ephem:
            chosen_port = local_port if not local_ephem else remote_port
            return f"127.0.0.1:{chosen_port}"
        return f"127.0.0.1:{min(local_port, remote_port)}"
    return f"{remote_ip}:{remote_port}"

def first_int(payload: Dict[str, str], keys: List[str]) -> Optional[int]:
    for want in keys:
        for k, v in payload.items():
            if k.lower() == want.lower():
                return safe_int(v)
    return None

def first_str(payload: Dict[str, str], keys: List[str]) -> Optional[str]:
    for want in keys:
        for k, v in payload.items():
            if k.lower() == want.lower():
                s = str(v).strip()
                return s if s else None
    return None

def quote_cmdline(cmdline_list: Any) -> Optional[str]:
    if isinstance(cmdline_list, list):
        return " ".join(shlex.quote(x) for x in cmdline_list)
    if isinstance(cmdline_list, str):
        return cmdline_list
    return None
