from __future__ import annotations

import dataclasses
from typing import Optional

@dataclasses.dataclass
class Subsystem:
    name: str
    status: str  # ok / failed / disabled / degraded / exported / pending
    note: str = ""

@dataclasses.dataclass
class ProcRec:
    pid: int
    ppid: Optional[int] = None
    image: Optional[str] = None  # may be device path; we sanitize on render
    exe: Optional[str] = None
    cmdline: Optional[str] = None
    first_seen_utc: Optional[str] = None
    last_seen_utc: Optional[str] = None
    seen_live: bool = False

@dataclasses.dataclass
class NetEvent:
    utc: str
    pid: int
    local: str
    remote: str

@dataclasses.dataclass
class RegEvent:
    utc: str
    pid: int
    op: str
    key: Optional[str] = None
