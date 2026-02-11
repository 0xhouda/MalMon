from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from .utils import run_cmd, strip_ns

class EtwSession:
    def __init__(self, name: str, etl_path: Path, provider: str, keywords: str, level: str):
        self.name = name
        self.etl_path = etl_path
        self.provider = provider
        self.keywords = keywords
        self.level = level
        self.started = False
        self.start_err: Optional[str] = None
        self.stop_err: Optional[str] = None
        self.export_err: Optional[str] = None

    def start(self) -> bool:
        cmd = [
            "logman",
            "start",
            self.name,
            "-o",
            str(self.etl_path),
            "-nb",
            "16",
            "256",
            "-bs",
            "1024",
            "-p",
            self.provider,
            self.keywords,
            self.level,
            "-ets",
        ]
        rc, out, err = run_cmd(cmd, timeout=10)
        if rc != 0:
            self.start_err = (err or out or f"logman rc={rc}").strip()
            self.started = False
            return False
        self.started = True
        return True

    def stop(self) -> bool:
        if not self.started:
            return True
        cmd = ["logman", "stop", self.name, "-ets"]
        rc, out, err = run_cmd(cmd, timeout=10)
        if rc != 0:
            self.stop_err = (err or out or f"logman rc={rc}").strip()
            return False
        return True

    def export_xml(self, xml_path: Path) -> bool:
        if not self.etl_path.exists():
            self.export_err = "ETL file missing; cannot export."
            return False
        cmd = ["tracerpt", str(self.etl_path), "-o", str(xml_path), "-of", "XML", "-lr", "-gmt", "-y"]
        rc, out, err = run_cmd(cmd, timeout=90)
        if rc != 0:
            self.export_err = (err or out or f"tracerpt rc={rc}").strip()
            return False
        return xml_path.exists()

def iter_tracerpt_events(xml_path: Path) -> Iterable[Dict[str, Any]]:
    """
    Streaming tracerpt XML parser (generic). Yields:
      {provider, event_id, utc, exec_pid, payload{...}}
    """
    try:
        for _, elem in ET.iterparse(str(xml_path), events=("end",)):
            if strip_ns(elem.tag) != "Event":
                continue

            provider_name = None
            event_id = None
            utc = None
            exec_pid = None
            payload: Dict[str, str] = {}

            sys_el = None
            for c in list(elem):
                if strip_ns(c.tag) == "System":
                    sys_el = c
                    break

            if sys_el is not None:
                for sc in list(sys_el):
                    t = strip_ns(sc.tag)
                    if t == "Provider":
                        provider_name = sc.attrib.get("Name") or sc.attrib.get("ProviderName")
                    elif t == "EventID":
                        event_id = (sc.text or "").strip()
                    elif t == "TimeCreated":
                        utc = sc.attrib.get("SystemTime") or (sc.text or "").strip()
                    elif t == "Execution":
                        exec_pid = sc.attrib.get("ProcessID") or sc.attrib.get("ProcessId")

            for c in list(elem):
                if strip_ns(c.tag) == "EventData":
                    for d in list(c):
                        if strip_ns(d.tag) == "Data":
                            nm = d.attrib.get("Name") or ""
                            val = (d.text or "").strip()
                            if nm:
                                payload[nm] = val
                    break

            yield {
                "provider": provider_name,
                "event_id": event_id,
                "utc": utc,
                "exec_pid": exec_pid,
                "payload": payload,
            }

            elem.clear()
    except Exception:
        return
