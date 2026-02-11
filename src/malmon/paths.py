from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Any, Dict, Optional

from .constants import SUSPICIOUS_EXT, MACRO_DOC_EXT
from .utils import is_windows

def _qdos_device(drive: str) -> Optional[str]:
    """drive like 'C:' -> returns device path prefix if possible."""
    if not is_windows():
        return None
    try:
        buf = ctypes.create_unicode_buffer(2048)
        rc = ctypes.windll.kernel32.QueryDosDeviceW(drive, buf, 2048)
        if rc == 0:
            return None
        return buf.value
    except Exception:
        return None

def build_device_map() -> Dict[str, str]:
    """
    Map device prefix -> drive letter, e.g. '\\Device\\HarddiskVolume3' -> 'C:'
    Helps render ETW paths nicely.
    """
    m: Dict[str, str] = {}
    if not is_windows():
        return m
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drv = f"{ch}:"
        if os.path.exists(drv + "\\"):
            dev = _qdos_device(drv)
            if dev:
                m[dev.lower()] = drv
    return m

def normalize_win_path(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    s = str(p).strip().strip('"').strip("'")
    s = s.replace("/", "\\")
    if s.startswith("\\\\?\\"):
        s = s[4:]
    if s.startswith("\\??\\"):
        s = s[4:]
    return s

def device_to_drive_path(p: Optional[str], devmap: Dict[str, str]) -> Optional[str]:
    if not p:
        return None
    s = p
    low = s.lower()
    for dev_prefix, drive in devmap.items():
        if low.startswith(dev_prefix):
            return drive + s[len(dev_prefix) :]
    return s

def canonical_path_key(p: str) -> str:
    try:
        return os.path.normcase(os.path.normpath(p))
    except Exception:
        return p.lower().strip()

def path_bucket(p: str) -> str:
    s = p.lower()
    if "\\programs\\startup" in s:
        return "STARTUP"
    if "\\appdata\\local\\temp" in s or "\\windows\\temp" in s:
        return "TEMP"
    if "\\appdata\\roaming" in s:
        return "ROAMING"
    if "\\appdata\\local" in s:
        return "LOCALAPPDATA"
    if "\\downloads" in s:
        return "DOWNLOADS"
    if "\\desktop" in s:
        return "DESKTOP"
    if "\\programdata" in s:
        return "PROGRAMDATA"
    return "OTHER"

def artifact_score(path: str) -> int:
    """
    Quick heuristic score to sort “most interesting” artifacts for console display.
    """
    s = 0
    b = path_bucket(path)
    if b == "STARTUP":
        s += 6
    elif b in ("ROAMING", "LOCALAPPDATA", "TEMP"):
        s += 4
    elif b in ("DOWNLOADS", "PROGRAMDATA"):
        s += 3
    elif b == "DESKTOP":
        s += 2

    ext = Path(path).suffix.lower()
    if ext in SUSPICIOUS_EXT:
        s += 4
    if ext in MACRO_DOC_EXT:
        s += 3

    low = path.lower()
    if "\\temp\\" in low and (ext in SUSPICIOUS_EXT or ext in (".dat", ".bin", ".tmp")):
        s += 1

    return s
