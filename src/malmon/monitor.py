from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .constants import (
    CREATE_DISP_MAY_CREATE,
    CREATE_DISP_NOT_CREATE,
    CREATE_DISP_STRONG_CREATE,
    CREATE_DISPOSITION_MAP,
    FILE_CREATE_OPS,
    FILE_DELETE_OPS,
    FILE_EVENT_ID_MAP,
    FILE_WRITE_OPS,
    REG_EVENT_ID_MAP,
    WRITE_OPS,
)
from .etw import EtwSession, iter_tracerpt_events
from .models import NetEvent, ProcRec, RegEvent, Subsystem
from .paths import (
    artifact_score,
    build_device_map,
    canonical_path_key,
    device_to_drive_path,
    normalize_win_path,
    path_bucket,
)
from .utils import (
    clean_image_name,
    clamp,
    first_int,
    first_str,
    is_admin,
    normalize_image,
    run_cmd,
    safe_int,
    utc_now,
)

class FlowMonMonitor:
    def __init__(self, cfg: Dict[str, Any], mode: str):
        self.cfg = cfg
        self.mode = mode

        self.admin = is_admin()
        self.run_start = utc_now()
        self.out_dir = Path(cfg["out"]).resolve()
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self.run_id = uuid.uuid4().hex[:12]

        self.root_pid: Optional[int] = None
        self.ignore_images = {normalize_image(x) for x in cfg.get("ignore_image", [])}

        self.procs: Dict[int, ProcRec] = {}
        self.tracked: Set[int] = set()
        self.etw_only_pids: Set[int] = set()

        # net
        self.net_unique: Set[Tuple[int, str]] = set()  # (pid, canonical_remote)
        self.net_top: Counter[str] = Counter()
        self.net_raw: List[NetEvent] = []

        # registry
        self.reg_total = 0
        self.reg_write_total = 0
        self.reg_open_total = 0

        self.reg_ops_all: Counter[str] = Counter()
        self.reg_ops_write: Counter[str] = Counter()
        self.reg_ops_open: Counter[str] = Counter()

        self.reg_keys_write: Counter[str] = Counter()
        self.reg_keys_open: Counter[str] = Counter()

        self.reg_keys_by_write_op: Dict[str, Counter[str]] = defaultdict(Counter)
        self.reg_handle_to_key: Dict[str, str] = {}
        self.reg_raw: List[RegEvent] = []

        # files (ETW Kernel-File)
        self.file_ops_all: Counter[str] = Counter()
        self.file_ops_create: Counter[str] = Counter()
        self.file_ops_write: Counter[str] = Counter()
        self.file_ops_delete: Counter[str] = Counter()

        self.file_paths_create: Counter[str] = Counter()
        self.file_paths_write: Counter[str] = Counter()
        self.file_paths_delete: Counter[str] = Counter()

        self.file_object_to_name: Dict[str, str] = {}
        self.file_key_to_name: Dict[str, str] = {}

        self._devmap = build_device_map()

        # file counters: keep BOTH (all) and (filtered/interesting)
        self.file_total_all = 0
        self.file_create_total_all = 0
        self.file_write_total_all = 0
        self.file_delete_total_all = 0

        self.file_total_f = 0
        self.file_create_total_f = 0
        self.file_write_total_f = 0
        self.file_delete_total_f = 0

        self.file_ops_all_f: Counter[str] = Counter()
        self.file_ops_create_f: Counter[str] = Counter()
        self.file_ops_write_f: Counter[str] = Counter()
        self.file_ops_delete_f: Counter[str] = Counter()

        self.file_paths_create_f: Counter[str] = Counter()
        self.file_paths_write_f: Counter[str] = Counter()
        self.file_paths_delete_f: Counter[str] = Counter()

        self.file_path_state: Dict[str, Dict[str, Any]] = {}

        self.file_sess: Optional[EtwSession] = None
        self.file_etw_xml: Optional[Path] = None
        self.file_new_created: Dict[str, Dict[str, Any]] = {}
        self.file_new_artifacts: Dict[str, Dict[str, Any]] = {}

        # subsystems
        self.subsystems: Dict[str, Subsystem] = {}
        self._set_sub("process_etw", "disabled" if cfg["disable_etw"] else "pending", "")
        self._set_sub("registry_etw", "disabled" if (cfg["disable_etw"] or cfg["disable_registry"]) else "pending", "")
        self._set_sub("network", "disabled" if cfg["disable_network"] else "pending", "")
        self._set_sub("file_etw", "disabled" if (cfg.get("disable_files") or cfg["disable_etw"]) else "pending", "")

        # psutil (optional)
        self.have_psutil = False
        self.psutil = None
        try:
            import psutil  # type: ignore
            self.psutil = psutil
            self.have_psutil = True
        except Exception:
            self.have_psutil = False

        # ETW
        self.proc_sess: Optional[EtwSession] = None
        self.reg_sess: Optional[EtwSession] = None
        self.proc_etw_xml: Optional[Path] = None
        self.reg_etw_xml: Optional[Path] = None

        # Auto-disable registry ETW if not admin
        if (not self.admin) and (not cfg["disable_etw"]) and (not cfg["disable_registry"]):
            self.cfg["disable_registry"] = True
            self._set_sub("registry_etw", "disabled", "Not elevated; registry ETW disabled automatically.")

    def _set_sub(self, name: str, status: str, note: str = "") -> None:
        self.subsystems[name] = Subsystem(name=name, status=status, note=note)

    def log(self, s: str) -> None:
        print(s, flush=True)

    def set_root(self, pid: int) -> None:
        self.root_pid = pid
        self.track(pid)

    def track(self, pid: int) -> None:
        self.tracked.add(pid)
        if pid not in self.procs:
            self.procs[pid] = ProcRec(pid=pid)

    def is_ignored(self, image: Optional[str]) -> bool:
        if not image:
            return False
        return normalize_image(image) in self.ignore_images

    # -------------------------
    # ETW lifecycle
    # -------------------------

    def start_etw(self) -> None:
        if self.cfg["disable_etw"]:
            self._set_sub("process_etw", "disabled", "Disabled by user.")
            self._set_sub("registry_etw", "disabled", "Disabled by user.")
            self._set_sub("file_etw", "disabled", "Disabled by user.")
            return

        # Process ETW
        self.log("[*] Starting Process ETW session...")
        proc_etl = self.out_dir / f"fw_proc_{self.run_id}.etl"
        proc_xml = self.out_dir / f"fw_proc_{self.run_id}.xml"
        self.proc_etw_xml = proc_xml

        self.proc_sess = EtwSession(
            name=f"flowMon_proc_{self.run_id}",
            etl_path=proc_etl,
            provider="Microsoft-Windows-Kernel-Process",
            keywords="0x50",
            level="win:Informational",
        )

        if not self.proc_sess.start():
            # Retry broad
            self.proc_sess = EtwSession(
                name=f"flowMon_proc_{self.run_id}",
                etl_path=proc_etl,
                provider="Microsoft-Windows-Kernel-Process",
                keywords="0xFFFFFFFF",
                level="win:Informational",
            )
            if not self.proc_sess.start():
                self._set_sub("process_etw", "failed", f"ETW start failed: {self.proc_sess.start_err}")
            else:
                self._set_sub("process_etw", "ok", "ETW session started (fallback keywords).")
        else:
            self._set_sub("process_etw", "ok", "ETW session started.")

        # File ETW
        if self.cfg.get("disable_files") or self.cfg["disable_etw"]:
            if self.subsystems.get("file_etw", Subsystem("file_etw", "")).status == "pending":
                self._set_sub("file_etw", "disabled", "Disabled by user or ETW disabled.")
        else:
            self.log("[*] Starting File ETW session...")
            file_etl = self.out_dir / f"fw_file_{self.run_id}.etl"
            file_xml = self.out_dir / f"fw_file_{self.run_id}.xml"
            self.file_etw_xml = file_xml

            self.file_sess = EtwSession(
                name=f"flowMon_file_{self.run_id}",
                etl_path=file_etl,
                provider="Microsoft-Windows-Kernel-File",
                keywords="0xFFFFFFFF",
                level="win:Informational",
            )

            if not self.file_sess.start():
                self._set_sub("file_etw", "failed", f"ETW start failed: {self.file_sess.start_err}")
            else:
                self._set_sub("file_etw", "ok", "ETW session started.")

        # Registry ETW
        if self.cfg["disable_registry"]:
            if self.subsystems["registry_etw"].status == "pending":
                self._set_sub("registry_etw", "disabled", "Disabled by user or auto-disabled.")
        else:
            self.log("[*] Starting Registry ETW session...")
            reg_etl = self.out_dir / f"fw_reg_{self.run_id}.etl"
            reg_xml = self.out_dir / f"fw_reg_{self.run_id}.xml"
            self.reg_etw_xml = reg_xml

            self.reg_sess = EtwSession(
                name=f"flowMon_reg_{self.run_id}",
                etl_path=reg_etl,
                provider="Microsoft-Windows-Kernel-Registry",
                keywords="0xFFFFFFFF",
                level="win:Informational",
            )

            if not self.reg_sess.start():
                self._set_sub("registry_etw", "failed", f"ETW start failed: {self.reg_sess.start_err}")
            else:
                self._set_sub("registry_etw", "ok", "ETW session started.")

    def stop_and_export_etw(self) -> None:
        if self.proc_sess:
            self.proc_sess.stop()
            if self.proc_etw_xml:
                ok = self.proc_sess.export_xml(self.proc_etw_xml)
                if ok:
                    self._set_sub("process_etw", "exported", f"Exported: {self.proc_etw_xml.name}")
                else:
                    self._set_sub(
                        "process_etw",
                        "failed",
                        f"Export failed: {self.proc_sess.export_err or self.proc_sess.stop_err}",
                    )

        if self.reg_sess:
            self.reg_sess.stop()
            if self.reg_etw_xml:
                ok = self.reg_sess.export_xml(self.reg_etw_xml)
                if ok:
                    self._set_sub("registry_etw", "exported", f"Exported: {self.reg_etw_xml.name}")
                else:
                    self._set_sub(
                        "registry_etw",
                        "failed",
                        f"Export failed: {self.reg_sess.export_err or self.reg_sess.stop_err}",
                    )

        if self.file_sess:
            self.file_sess.stop()
            if self.file_etw_xml:
                ok = self.file_sess.export_xml(self.file_etw_xml)
                if ok:
                    self._set_sub("file_etw", "exported", f"Exported: {self.file_etw_xml.name}")
                else:
                    self._set_sub(
                        "file_etw",
                        "failed",
                        f"Export failed: {self.file_sess.export_err or self.file_sess.stop_err}",
                    )

    # -------------------------
    # Snapshots
    # -------------------------

    def snapshot_processes(self) -> Dict[int, ProcRec]:
        snap: Dict[int, ProcRec] = {}
        if self.have_psutil and self.psutil:
            for p in self.psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]):
                try:
                    info = p.info
                    pid = int(info.get("pid"))
                    rec = ProcRec(pid=pid)
                    rec.ppid = safe_int(info.get("ppid"))
                    rec.image = info.get("name") or None
                    rec.exe = info.get("exe") or None
                    cl = info.get("cmdline")
                    if isinstance(cl, list):
                        rec.cmdline = " ".join(__import__("shlex").quote(x) for x in cl)
                    elif isinstance(cl, str):
                        rec.cmdline = cl
                    ct = info.get("create_time")
                    if ct:
                        rec.first_seen_utc = dt.datetime.fromtimestamp(float(ct), tz=dt.timezone.utc).isoformat()
                    snap[pid] = rec
                except Exception:
                    continue
            return snap

        # CIM fallback (slow)
        ps = r"""
        $p = Get-CimInstance Win32_Process |
             Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate |
             ConvertTo-Json -Compress
        Write-Output $p
        """
        rc, out, err = run_cmd(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=25)
        if rc != 0 or not out:
            return snap
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for row in data:
                pid = safe_int(row.get("ProcessId"))
                if pid is None:
                    continue
                rec = ProcRec(pid=pid)
                rec.ppid = safe_int(row.get("ParentProcessId"))
                rec.image = row.get("Name")
                rec.exe = row.get("ExecutablePath")
                rec.cmdline = row.get("CommandLine")
                cd = row.get("CreationDate")
                if cd:
                    rec.first_seen_utc = str(cd)
                snap[pid] = rec
        except Exception:
            pass
        return snap

    def poll_and_expand_tree(self, snap: Dict[int, ProcRec]) -> None:
        now = utc_now().isoformat()

        # merge snapshot into proc table
        for pid, rec in snap.items():
            if pid not in self.procs:
                self.procs[pid] = ProcRec(pid=pid)
            p = self.procs[pid]
            p.ppid = p.ppid if p.ppid is not None else rec.ppid
            p.image = p.image or rec.image
            p.exe = p.exe or rec.exe
            p.cmdline = p.cmdline or rec.cmdline
            p.seen_live = True
            p.last_seen_utc = now
            if p.first_seen_utc is None:
                p.first_seen_utc = rec.first_seen_utc or now
            self.procs[pid] = p

        # expand descendants: if parent tracked -> child tracked
        added = True
        while added:
            added = False
            for pid, p in list(self.procs.items()):
                if pid in self.tracked:
                    continue
                if p.ppid is None:
                    continue
                if p.ppid in self.tracked and (not self.is_ignored(p.image)):
                    self.tracked.add(pid)
                    added = True

    def network_snapshot(self) -> None:
        from .utils import loopback_canonical_endpoint  # avoid import cycle
        if self.cfg["disable_network"]:
            return

        try:
            if self.have_psutil and self.psutil:
                conns = self.psutil.net_connections(kind="tcp")
                for c in conns:
                    try:
                        pid = c.pid
                        if pid is None or pid not in self.tracked:
                            continue
                        if not c.laddr or not c.raddr:
                            continue
                        local_ip, local_port = c.laddr.ip, int(c.laddr.port)
                        remote_ip, remote_port = c.raddr.ip, int(c.raddr.port)

                        canon_remote = loopback_canonical_endpoint(local_ip, local_port, remote_ip, remote_port)
                        self.net_unique.add((pid, canon_remote))
                        self.net_top[canon_remote] += 1

                        if self.cfg["raw_network"] and len(self.net_raw) < self.cfg["max_raw_events"]:
                            self.net_raw.append(
                                NetEvent(
                                    utc=utc_now().isoformat(),
                                    pid=pid,
                                    local=f"{local_ip}:{local_port}",
                                    remote=f"{remote_ip}:{remote_port}",
                                )
                            )
                    except Exception:
                        continue
                self._set_sub("network", "ok", "Collected via snapshot (psutil).")
                return

            # fallback: netstat -ano
            rc, out, err = run_cmd(["netstat", "-ano", "-p", "tcp"], timeout=10)
            if rc != 0 or not out:
                self._set_sub("network", "degraded", f"netstat unavailable: {err or out}")
                return

            for line in out.splitlines():
                line = line.strip()
                if not line or not line.lower().startswith("tcp"):
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                local = parts[1]
                remote = parts[2]
                pid = safe_int(parts[-1])
                if pid is None or pid not in self.tracked:
                    continue
                if remote in ("0.0.0.0:0", "*:*"):
                    continue

                try:
                    lip, lp = local.rsplit(":", 1)
                    rip, rp = remote.rsplit(":", 1)
                    canon_remote = loopback_canonical_endpoint(lip, int(lp), rip, int(rp))
                except Exception:
                    canon_remote = remote

                self.net_unique.add((pid, canon_remote))
                self.net_top[canon_remote] += 1

                if self.cfg["raw_network"] and len(self.net_raw) < self.cfg["max_raw_events"]:
                    self.net_raw.append(NetEvent(utc=utc_now().isoformat(), pid=pid, local=local, remote=remote))

            self._set_sub("network", "ok", "Collected via snapshot (netstat).")

        except Exception as e:
            self._set_sub("network", "degraded", f"Network snapshot error: {type(e).__name__}: {e}")

    # -------------------------
    # ETW parsing (post-run)
    # -------------------------

    def parse_etw_process_xml(self) -> None:
        if not self.proc_etw_xml or not self.proc_etw_xml.exists():
            return
        try:
            for ev in iter_tracerpt_events(self.proc_etw_xml):
                provider = (ev.get("provider") or "").lower()
                if "kernel-process" not in provider:
                    continue
                payload: Dict[str, str] = ev.get("payload", {})

                child = first_int(payload, ["ProcessID", "ProcessId", "NewProcessId", "PID"])
                parent = first_int(payload, ["ParentProcessID", "ParentProcessId", "PPID", "ParentPID"])
                img = first_str(payload, ["ImageName", "ProcessName", "ImageFileName", "FileName", "Name"])

                if child is None:
                    child = safe_int(ev.get("exec_pid"))

                if child is None:
                    continue

                if img:
                    img = os.path.basename(img)

                if child not in self.procs:
                    self.procs[child] = ProcRec(pid=child)
                    self.etw_only_pids.add(child)

                p = self.procs[child]
                if parent is not None and p.ppid is None:
                    p.ppid = parent
                if img and not p.image:
                    p.image = img
                self.procs[child] = p

            if self.root_pid is not None:
                self._expand_from_ppids()

        except Exception:
            return

    def parse_etw_file_xml(self) -> None:
        if self.cfg.get("disable_files"):
            return
        if not self.file_etw_xml or not self.file_etw_xml.exists():
            return

        def is_noisy_path(p: str) -> bool:
            s = (p or "").lower()
            noisy = (
                r"\windows\system32",
                r"\windows\winsxs",
                r"\windows\servicing",
                r"\program files",
                r"\program files (x86)",
                r"\microsoft.net",
                r"\windows\softwaredistribution",
                r"\appdata\local\microsoft\windows\inetcache",
                r"\appdata\local\google\chrome\user data\default\cache",
                r"\appdata\local\microsoft\edge\user data\default\cache",
            )
            return any(x in s for x in noisy)

        def is_interesting_path(p: str) -> bool:
            s = (p or "").lower()
            if not s:
                return False
            if is_noisy_path(s):
                return False
            interesting = (
                r"\users\\",
                r"\appdata\local\temp",
                r"\appdata\roaming",
                r"\desktop",
                r"\downloads",
                r"\windows\temp",
                r"\programdata",
                r"\programs\startup",
            )
            return any(x in s for x in interesting)

        def classify_creation_confidence(create_disp: Optional[int]) -> str:
            if create_disp in CREATE_DISP_STRONG_CREATE:
                return "high"
            if create_disp in CREATE_DISP_MAY_CREATE:
                return "medium"
            if create_disp in CREATE_DISP_NOT_CREATE:
                return "none"
            return "unknown"

        parsed_total_all = 0
        parsed_create_all = 0
        parsed_write_all = 0
        parsed_delete_all = 0

        parsed_total_f = 0
        parsed_create_f = 0
        parsed_write_f = 0
        parsed_delete_f = 0

        try:
            for ev in iter_tracerpt_events(self.file_etw_xml):
                provider = (ev.get("provider") or "").lower()
                if "kernel-file" not in provider:
                    continue

                payload: Dict[str, str] = ev.get("payload", {})
                exec_pid = safe_int(ev.get("exec_pid"))

                pid = first_int(payload, ["ProcessID", "ProcessId", "PID"]) or exec_pid
                if pid is None or pid not in self.tracked:
                    continue

                eid = safe_int(ev.get("event_id"))
                op = FILE_EVENT_ID_MAP.get(eid, f"FileEventID_{eid}") if eid is not None else "FileEvent"
                utc = (ev.get("utc") or utc_now().isoformat())

                fname = first_str(payload, ["FileName", "FilePath", "Path", "TargetFileName", "NewFileName", "OldFileName", "Name"])
                fobj = first_str(payload, ["FileObject", "FileObj", "FileObjectPointer", "Object"])
                fkey = first_str(payload, ["FileKey", "FileId", "Key"])

                fname = normalize_win_path(fname)
                fname = device_to_drive_path(fname, self._devmap)

                if op == "Create" and fobj and fname:
                    self.file_object_to_name[fobj] = fname

                if op == "Close" and fobj:
                    if not fname and fobj in self.file_object_to_name:
                        fname = self.file_object_to_name.get(fobj)
                    if fkey and fname:
                        self.file_key_to_name[fkey] = fname

                if (not fname) and fkey and (fkey in self.file_key_to_name):
                    fname = self.file_key_to_name.get(fkey)

                # ---- ALL counters (no filtering) ----
                parsed_total_all += 1
                self.file_ops_all[op] += 1

                if op in FILE_CREATE_OPS:
                    parsed_create_all += 1
                    self.file_ops_create[op] += 1
                    if fname:
                        self.file_paths_create[fname] += 1

                if op in FILE_WRITE_OPS:
                    parsed_write_all += 1
                    self.file_ops_write[op] += 1
                    if fname:
                        self.file_paths_write[fname] += 1

                if op in FILE_DELETE_OPS:
                    parsed_delete_all += 1
                    self.file_ops_delete[op] += 1
                    if fname:
                        self.file_paths_delete[fname] += 1

                # ---- filtered view (interesting paths only) ----
                if not fname or (not is_interesting_path(fname)):
                    continue

                parsed_total_f += 1
                self.file_ops_all_f[op] += 1

                if op in FILE_CREATE_OPS:
                    parsed_create_f += 1
                    self.file_ops_create_f[op] += 1
                    self.file_paths_create_f[fname] += 1

                if op in FILE_WRITE_OPS:
                    parsed_write_f += 1
                    self.file_ops_write_f[op] += 1
                    self.file_paths_write_f[fname] += 1

                if op in FILE_DELETE_OPS:
                    parsed_delete_f += 1
                    self.file_ops_delete_f[op] += 1
                    self.file_paths_delete_f[fname] += 1

                # ---- state tracking for "real creation" detection ----
                k = canonical_path_key(fname)
                st = self.file_path_state.get(k)
                if not st:
                    st = {
                        "path": fname,
                        "first_utc": utc,
                        "pid": pid,
                        "first_op": op,
                        "saw_create": False,
                        "saw_write": False,
                        "saw_delete": False,
                        "create_disp": None,
                        "create_disp_name": None,
                        "bucket": path_bucket(fname),
                        "score": artifact_score(fname),
                    }
                    self.file_path_state[k] = st

                if op == "Create":
                    st["saw_create"] = True
                    disp = first_int(payload, ["CreateDisposition", "Disposition", "CreateDisp", "CreateDispositionValue"])
                    if disp is not None:
                        st["create_disp"] = disp
                        st["create_disp_name"] = CREATE_DISPOSITION_MAP.get(disp, str(disp))

                if op in FILE_WRITE_OPS:
                    st["saw_write"] = True
                if op in FILE_DELETE_OPS:
                    st["saw_delete"] = True

                if op in FILE_CREATE_OPS and fname not in self.file_new_artifacts:
                    self.file_new_artifacts[fname] = {"path": fname, "first_utc": utc, "pid": pid, "reason": "create"}
                if op in FILE_WRITE_OPS and fname not in self.file_new_artifacts:
                    self.file_new_artifacts[fname] = {"path": fname, "first_utc": utc, "pid": pid, "reason": "write"}
                if op in FILE_DELETE_OPS and fname not in self.file_new_artifacts:
                    self.file_new_artifacts[fname] = {"path": fname, "first_utc": utc, "pid": pid, "reason": "delete"}

        except Exception:
            pass

        # ---- compute "probable real creations" ----
        self.file_new_created.clear()
        for st in self.file_path_state.values():
            disp = st.get("create_disp")
            conf = classify_creation_confidence(disp)

            probable = False
            why = ""

            if conf == "high":
                probable = True
                why = f"CreateDisposition={st.get('create_disp_name')} (strong)"
            elif conf in ("medium", "unknown"):
                if st.get("saw_write") and st.get("saw_create"):
                    probable = True
                    why = f"Create + Write (disp={st.get('create_disp_name') or 'n/a'})"

            if probable:
                self.file_new_created[st["path"]] = {
                    "path": st["path"],
                    "first_utc": st["first_utc"],
                    "pid": st["pid"],
                    "bucket": st["bucket"],
                    "score": st["score"],
                    "create_disposition": st.get("create_disp_name"),
                    "confidence": conf,
                    "why": why,
                }

        self.file_total_all = parsed_total_all
        self.file_create_total_all = parsed_create_all
        self.file_write_total_all = parsed_write_all
        self.file_delete_total_all = parsed_delete_all

        self.file_total_f = parsed_total_f
        self.file_create_total_f = parsed_create_f
        self.file_write_total_f = parsed_write_f
        self.file_delete_total_f = parsed_delete_f

        # keep original fields for backward compatibility (now = filtered)
        self.file_total = self.file_total_f
        self.file_create_total = self.file_create_total_f
        self.file_write_total = self.file_write_total_f
        self.file_delete_total = self.file_delete_total_f

        if "file_etw" in self.subsystems and self.subsystems["file_etw"].status in ("ok", "exported"):
            self.subsystems["file_etw"].note = (
                f"AllEvents={parsed_total_all} InterestingEvents={parsed_total_f} "
                f"CreatesF={parsed_create_f} WritesF={parsed_write_f} DeletesF={parsed_delete_f} "
                f"ProbableCreates={len(self.file_new_created)} NewArtifacts={len(self.file_new_artifacts)}"
            )

    def _expand_from_ppids(self) -> None:
        added = True
        while added:
            added = False
            for pid, p in list(self.procs.items()):
                if pid in self.tracked:
                    continue
                if p.ppid is None:
                    continue
                if p.ppid in self.tracked and (not self.is_ignored(p.image)):
                    self.tracked.add(pid)
                    added = True

    def parse_etw_registry_xml(self) -> None:
        if self.cfg["disable_registry"]:
            return
        if not self.reg_etw_xml or not self.reg_etw_xml.exists():
            return

        parsed_total = 0
        parsed_write = 0
        parsed_open = 0

        OPEN_OPS = {"RegOpenKey"}

        try:
            for ev in iter_tracerpt_events(self.reg_etw_xml):
                provider = (ev.get("provider") or "").lower()
                if "kernel-registry" not in provider:
                    continue

                payload: Dict[str, str] = ev.get("payload", {})
                exec_pid = safe_int(ev.get("exec_pid"))

                pid = first_int(payload, ["ProcessID", "ProcessId", "PID"]) or exec_pid
                if pid is None or pid not in self.tracked:
                    continue

                eid = safe_int(ev.get("event_id"))
                op = "RegEvent" if eid is None else REG_EVENT_ID_MAP.get(eid, f"RegEventID_{eid}")

                key = first_str(payload, ["KeyName", "KeyPath", "ObjectName", "Path", "FullPath", "RelativeName"])
                val = first_str(payload, ["ValueName", "Value", "Name"])
                handle = first_str(payload, ["KeyHandle", "KeyObject", "Object", "Handle"])

                if key and val and (val.lower() not in key.lower()):
                    key = f"{key}\\{val}"

                if handle and key:
                    self.reg_handle_to_key[handle] = key
                if (not key) and handle and (handle in self.reg_handle_to_key):
                    key = self.reg_handle_to_key.get(handle)

                parsed_total += 1
                self.reg_ops_all[op] += 1

                if op in OPEN_OPS:
                    parsed_open += 1
                    self.reg_ops_open[op] += 1
                    if key:
                        self.reg_keys_open[key] += 1

                if op in WRITE_OPS:
                    parsed_write += 1
                    self.reg_ops_write[op] += 1
                    if key:
                        self.reg_keys_write[key] += 1
                        self.reg_keys_by_write_op[op][key] += 1

                if self.cfg["raw_registry"] and len(self.reg_raw) < self.cfg["max_raw_events"]:
                    self.reg_raw.append(RegEvent(utc=(ev.get("utc") or utc_now().isoformat()), pid=pid, op=op, key=key))
        except Exception:
            pass

        self.reg_total = parsed_total
        self.reg_write_total = parsed_write
        self.reg_open_total = parsed_open

        if "registry_etw" in self.subsystems and self.subsystems["registry_etw"].status in ("ok", "exported"):
            self.subsystems["registry_etw"].note = f"ParsedEvents={parsed_total} Writes={parsed_write} Opens={parsed_open}"

    # -------------------------
    # Run control
    # -------------------------

    def run_for_duration(self) -> None:
        duration_s = clamp(int(self.cfg["duration"]), 1, 24 * 3600)
        grace_s = clamp(int(self.cfg["grace"]), 0, 120)

        end_time = time.time() + duration_s
        last_live_seen = time.time()

        while True:
            snap = self.snapshot_processes()
            self.poll_and_expand_tree(snap)
            self.network_snapshot()

            any_tracked_live = any((pid in snap) for pid in self.tracked)
            if any_tracked_live:
                last_live_seen = time.time()

            now = time.time()
            if now >= end_time:
                break
            if (not any_tracked_live) and (now - last_live_seen >= grace_s) and len(self.tracked) > 0:
                break

            time.sleep(max(0.2, float(self.cfg["poll_ms"]) / 1000.0))

    # -------------------------
    # Tree + report
    # -------------------------

    def build_tree(self) -> Optional[Dict[str, Any]]:
        root = self.root_pid
        if root is None or root not in self.tracked:
            roots = []
            for pid in sorted(self.tracked):
                p = self.procs.get(pid)
                if not p or p.ppid is None or p.ppid not in self.tracked:
                    roots.append(pid)
            root = roots[0] if roots else None

        if root is None:
            return None

        kids: Dict[int, List[int]] = defaultdict(list)
        for pid in self.tracked:
            p = self.procs.get(pid)
            if not p or p.ppid is None:
                continue
            if p.ppid in self.tracked:
                kids[p.ppid].append(pid)

        for k in kids:
            kids[k] = sorted(set(kids[k]))

        def node(pid: int) -> Dict[str, Any]:
            p = self.procs.get(pid, ProcRec(pid=pid))
            return {"pid": pid, "image": clean_image_name(p.image), "children": [node(c) for c in kids.get(pid, [])]}

        return node(root)

    def mermaid_tree(self, root_node: Optional[Dict[str, Any]]) -> str:
        max_nodes = clamp(int(self.cfg["max_nodes"]), 10, 2000)
        max_depth = clamp(int(self.cfg["max_depth"]), 1, 50)

        sb = ["flowchart TD"]
        if not root_node:
            sb.append('  A["No root process identified"]')
            return "\n".join(sb)

        seen: Set[int] = set()
        nodes = 0

        def walk(n: Dict[str, Any], depth: int) -> None:
            nonlocal nodes
            if nodes >= max_nodes or depth > max_depth:
                return
            pid = int(n["pid"])
            if pid in seen:
                return
            seen.add(pid)
            nodes += 1

            img = (n.get("image") or "unknown").replace('"', "'")
            sb.append(f'  P{pid}["{pid} {img}"]')

            for c in (n.get("children") or []):
                if nodes >= max_nodes:
                    break
                cpid = int(c["pid"])
                sb.append(f"  P{pid} --> P{cpid}")
                walk(c, depth + 1)

        walk(root_node, 0)
        if nodes >= max_nodes:
            sb.append(f"  %% truncated: maxNodes={max_nodes}")
        sb.append(f"  %% maxDepth={max_depth}")
        return "\n".join(sb)

    def render_tree_text(self, root_node: Optional[Dict[str, Any]]) -> str:
        if not root_node:
            return "  <no process tree available>"

        lines: List[str] = []

        def walk(n: Dict[str, Any], pref: str) -> None:
            pid = n.get("pid")
            img = clean_image_name(n.get("image"))
            lines.append(f"{pref}- {pid} ({img})")
            for c in (n.get("children") or []):
                walk(c, pref + "  ")

        walk(root_node, "")
        return "\n".join(lines)

    def build_report(self) -> Dict[str, Any]:
        from .constants import TOOL_NAME, TOOL_VERSION
        root_node = self.build_tree()

        tracked_live = [pid for pid in self.tracked if self.procs.get(pid, ProcRec(pid)).seen_live]
        etw_desc = max(0, len(self.tracked) - 1)

        process_table = []
        for pid in sorted(self.tracked):
            p = self.procs.get(pid, ProcRec(pid=pid))
            process_table.append(
                {
                    "pid": pid,
                    "ppid": p.ppid,
                    "image": clean_image_name(p.image),
                    "exe": p.exe,
                    "cmdline": p.cmdline,
                    "seen_live": p.seen_live,
                    "first_seen_utc": p.first_seen_utc,
                    "last_seen_utc": p.last_seen_utc,
                }
            )

        report: Dict[str, Any] = {
            "tool": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "mode": self.mode,
                "start_utc": self.run_start.isoformat(),
                "end_utc": utc_now().isoformat(),
            },
            "status": {
                "admin": self.admin,
                "root_pid": self.root_pid,
                "tracked_count": len(self.tracked),
                "tracked_live_count": len(tracked_live),
                "descendants_etw": etw_desc,
                "subsystems": {k: dataclasses.asdict(v) for k, v in sorted(self.subsystems.items())},
                "out_dir": str(self.out_dir),
            },
            "process": {
                "tracked_pids": sorted(self.tracked),
                "tree": root_node,
                "process_table": process_table,
            },
            "files": {
                "parsed_total": self.file_total_f,
                "parsed_creates": self.file_create_total_f,
                "parsed_writes": self.file_write_total_f,
                "parsed_deletes": self.file_delete_total_f,
                "parsed_total_all": self.file_total_all,
                "parsed_creates_all": self.file_create_total_all,
                "parsed_writes_all": self.file_write_total_all,
                "parsed_deletes_all": self.file_delete_total_all,
                "parsed_total_filtered": self.file_total_f,
                "parsed_creates_filtered": self.file_create_total_f,
                "parsed_writes_filtered": self.file_write_total_f,
                "parsed_deletes_filtered": self.file_delete_total_f,
                "top_operations_all": self.file_ops_all.most_common(),
                "top_operations_creates": self.file_ops_create.most_common(),
                "top_operations_writes": self.file_ops_write.most_common(),
                "top_operations_deletes": self.file_ops_delete.most_common(),
                "top_operations_all_filtered": self.file_ops_all_f.most_common(),
                "top_paths_create_filtered": self.file_paths_create_f.most_common(),
                "top_paths_write_filtered": self.file_paths_write_f.most_common(),
                "top_paths_delete_filtered": self.file_paths_delete_f.most_common(),
                "new_file_artifacts_unique_count": len(self.file_new_artifacts),
                "new_file_artifacts_unique": list(self.file_new_artifacts.values()),
                "new_created_files_unique_count": len(self.file_new_created),
                "new_created_files_unique": list(self.file_new_created.values()),
                "top_paths_create": self.file_paths_create.most_common(),
                "top_paths_write": self.file_paths_write.most_common(),
                "top_paths_delete": self.file_paths_delete.most_common(),
                "attribution": "ETW Microsoft-Windows-Kernel-File (best-effort; may be noisy).",
            },
            "network": {
                "unique_connections": len(self.net_unique),
                "top_remote_endpoints": self.net_top.most_common(),
                "raw_events": [dataclasses.asdict(x) for x in self.net_raw] if self.cfg["raw_network"] else None,
                "attribution": "Snapshot (psutil/netstat). Fast short-lived conns may be missed if polling too slow.",
            },
            "registry": {
                "parsed_total": self.reg_total,
                "parsed_writes": self.reg_write_total,
                "parsed_open": self.reg_open_total,
                "top_operations_all": self.reg_ops_all.most_common(),
                "top_operations_writes": self.reg_ops_write.most_common(),
                "top_operations_open": self.reg_ops_open.most_common(),
                "top_keys_writes": self.reg_keys_write.most_common(),
                "top_keys_open": self.reg_keys_open.most_common(),
                "top_keys_createkey": self.reg_keys_by_write_op["RegCreateKey"].most_common(),
                "top_keys_setvalue": self.reg_keys_by_write_op["RegSetValue"].most_common(),
                "top_keys_deletekey": self.reg_keys_by_write_op["RegDeleteKey"].most_common(),
                "top_keys_deletevalue": self.reg_keys_by_write_op["RegDeleteValue"].most_common(),
                "raw_events": [dataclasses.asdict(x) for x in self.reg_raw] if self.cfg["raw_registry"] else None,
                "attribution": "ETW Kernel-Registry (best-effort; often requires elevation).",
            },
            "artifacts": {
                "json_report": str(self.out_dir / "report.json"),
                "process_tree_mermaid": str(self.out_dir / "process_tree.mmd"),
                "process_etw_xml": str(self.proc_etw_xml) if (self.proc_etw_xml and self.proc_etw_xml.exists()) else None,
                "registry_etw_xml": str(self.reg_etw_xml) if (self.reg_etw_xml and self.reg_etw_xml.exists()) else None,
                "file_etw_xml": str(self.file_etw_xml) if (self.file_etw_xml and self.file_etw_xml.exists()) else None,
            },
            "config": dict(self.cfg),
        }
        return report

    def render_console(self, report: Dict[str, Any]) -> str:
        W = 90

        def bar(title: str) -> List[str]:
            return ["=" * W, title, "=" * W]

        st = report["status"]
        proc = report["process"]
        net = report["network"]
        reg = report["registry"]
        subs = st["subsystems"]

        proc_etw = subs.get("process_etw", {})
        reg_etw = subs.get("registry_etw", {})

        files = report.get("files") or {}
        file_etw = subs.get("file_etw", {})

        root_node = proc.get("tree")
        tree_text = self.render_tree_text(root_node)

        cmd_lines = proc.get("process_table") or []
        etw_only = [x for x in cmd_lines if (not x.get("seen_live"))]
        etw_only_count = len(etw_only)

        top_remote = net.get("top_remote_endpoints") or []

        top_ops_w = (reg.get("top_operations_writes") or [])[:10]
        top_ops_o = (reg.get("top_operations_open") or [])[:10]

        top_keys_o = (reg.get("top_keys_open") or [])[:10]
        top_keys_create = (reg.get("top_keys_createkey") or [])[:10]
        top_keys_set = (reg.get("top_keys_setvalue") or [])[:10]
        top_keys_delk = (reg.get("top_keys_deletekey") or [])[:10]
        top_keys_delv = (reg.get("top_keys_deletevalue") or [])[:10]

        lines: List[str] = []

        lines += bar("STATUS")
        lines.append(f"Admin: {st.get('admin')}")
        lines.append(f"Root PID: {st.get('root_pid')}")
        lines.append(f"Tracked (live): {st.get('tracked_live_count')}")
        lines.append(f"Descendants (ETW): {st.get('descendants_etw')}")
        lines.append(f"Process ETW: {proc_etw.get('status','unknown')}")
        lines.append(f"Registry ETW: {reg_etw.get('status','unknown')}")
        lines.append("")

        lines += bar("PROCESS TREE (ETW)" if proc_etw.get("status") in ("ok", "exported") else "PROCESS TREE (snapshot)")
        lines.append(tree_text)
        lines.append("")

        lines += bar("COMMAND LINES (best-effort)")
        for x in cmd_lines:
            pid = x.get("pid")
            img = clean_image_name(x.get("image"))
            exe = x.get("exe")
            cmd = x.get("cmdline")
            lines.append(f"- PID {pid} :: {img}")
            if exe:
                lines.append(f" EXE: {exe}")
            if cmd:
                lines.append(f" CommandLine: {cmd}")
            lines.append("")

        if etw_only_count > 0:
            lines.append(f"[!] Note: {etw_only_count} PID(s) seen via ETW but not observed live; command lines may be unavailable.")
            lines.append("")

        # ---- FILES ----
        lines += bar("FILES (ETW)" if file_etw.get("status") in ("ok", "exported") else "FILES")

        lines.append(
            f"All file events (tracked pids): {files.get('parsed_total_all', 0)} "
            f"(C={files.get('parsed_creates_all',0)} W={files.get('parsed_writes_all',0)} D={files.get('parsed_deletes_all',0)})"
        )
        lines.append(
            f"Interesting paths (filtered):   {files.get('parsed_total_filtered', 0)} "
            f"(C={files.get('parsed_creates_filtered',0)} W={files.get('parsed_writes_filtered',0)} D={files.get('parsed_deletes_filtered',0)})"
        )
        lines.append("")

        def fmt_row(cols: List[Any], widths: List[int]) -> str:
            out = []
            for c, w in zip(cols, widths):
                s = str(c)
                if len(s) > w:
                    s = s[: max(0, w - 1)] + "…"
                out.append(s.ljust(w))
            return " ".join(out).rstrip()

        created = (files.get("new_created_files_unique") or [])
        created_sorted = sorted(created, key=lambda x: (-int(x.get("score", 0)), str(x.get("first_utc", ""))))
        created_top = created_sorted[:12]

        lines.append(f"Probable NEW file creations (unique): {len(created)}")
        if created_top:
            lines.append(fmt_row(["S", "Conf", "PID", "When(UTC)", "Bucket", "Path"], [2, 6, 6, 26, 12, 36]))
            lines.append("-" * W)
            for x in created_top:
                lines.append(
                    fmt_row(
                        [
                            x.get("score", ""),
                            x.get("confidence", ""),
                            x.get("pid", ""),
                            x.get("first_utc", ""),
                            x.get("bucket", ""),
                            x.get("path", ""),
                        ],
                        [2, 6, 6, 26, 12, 36],
                    )
                )
        else:
            lines.append("  <none>")
        lines.append("")

        new_art = (files.get("new_file_artifacts_unique") or [])
        new_art_recent = new_art[-10:]
        lines.append(f"New file artifacts (create/write/delete) unique: {len(new_art)}")
        lines.append("Recent artifacts:")
        if new_art_recent:
            for x in new_art_recent:
                lines.append(f"  - {x.get('path')}  [{x.get('reason')}] pid={x.get('pid')} utc={x.get('first_utc')}")
        else:
            lines.append("  <none>")
        lines.append("")

        top_file_ops_f = (files.get("top_operations_all_filtered") or [])[:10]
        top_create_f = (files.get("top_paths_create_filtered") or [])[:10]
        top_write_f = (files.get("top_paths_write_filtered") or [])[:10]
        top_delete_f = (files.get("top_paths_delete_filtered") or [])[:10]

        lines.append("Top file operations (filtered):")
        if top_file_ops_f:
            for op, cnt in top_file_ops_f:
                lines.append(f"{int(cnt):6d} {op}")
        else:
            lines.append("  <none>")
        lines.append("")

        lines.append("Top paths (create) (filtered):")
        if top_create_f:
            for p, cnt in top_create_f:
                lines.append(f"{int(cnt):6d} {p}")
        else:
            lines.append("  <none>")
        lines.append("")

        lines.append("Top paths (write/modify) (filtered):")
        if top_write_f:
            for p, cnt in top_write_f:
                lines.append(f"{int(cnt):6d} {p}")
        else:
            lines.append("  <none>")
        lines.append("")

        lines.append("Top paths (delete) (filtered):")
        if top_delete_f:
            for p, cnt in top_delete_f:
                lines.append(f"{int(cnt):6d} {p}")
        else:
            lines.append("  <none>")
        lines.append("")

        # ---- NETWORK ----
        lines += bar("NETWORK")
        lines.append(f"Captured unique conns (filtered): {net.get('unique_connections', 0)}")
        lines.append("Top remote endpoints:")
        if top_remote:
            for ep, cnt in top_remote:
                lines.append(f"{int(cnt):6d} {ep}")
        lines.append("")

        # ---- REGISTRY ----
        lines += bar("REGISTRY (ETW)" if reg_etw.get("status") in ("ok", "exported") else "REGISTRY")
        lines.append(f"Registry events parsed (filtered): {reg.get('parsed_total', 0)}")
        lines.append(f"Write ops parsed (filtered): {reg.get('parsed_writes', 0)}")
        lines.append(f"Open ops parsed (filtered): {reg.get('parsed_open', 0)}")
        lines.append("")

        lines.append("Top operations (writes):")
        if top_ops_w:
            for op, cnt in top_ops_w:
                lines.append(f"{int(cnt):6d} {op}")
        else:
            lines.append("  <none>")
        lines.append("")

        lines.append("Top operations (open):")
        if top_ops_o:
            for op, cnt in top_ops_o:
                lines.append(f"{int(cnt):6d} {op}")
        else:
            lines.append("  <none>")
        lines.append("")

        lines.append("Top keys (RegCreateKey):")
        if top_keys_create:
            for k, cnt in top_keys_create:
                lines.append(f"{int(cnt):6d} {k}")
        else:
            lines.append("  <none>")
        lines.append("")

        lines.append("Top keys (RegSetValue):")
        if top_keys_set:
            for k, cnt in top_keys_set:
                lines.append(f"{int(cnt):6d} {k}")
        else:
            lines.append("  <none>")
        lines.append("")

        lines.append("Top keys (RegDeleteKey):")
        if top_keys_delk:
            for k, cnt in top_keys_delk:
                lines.append(f"{int(cnt):6d} {k}")
        else:
            lines.append("  <none>")
        lines.append("")

        lines.append("Top keys (RegDeleteValue):")
        if top_keys_delv:
            for k, cnt in top_keys_delv:
                lines.append(f"{int(cnt):6d} {k}")
        else:
            lines.append("  <none>")
        lines.append("")

        lines.append("Top keys (open):")
        if top_keys_o:
            for k, cnt in top_keys_o:
                lines.append(f"{int(cnt):6d} {k}")
        else:
            lines.append("  <none>")
        lines.append("")

        # ---- OUTPUT FILES ----
        lines += bar("OUTPUT FILES")
        artifacts = report.get("artifacts", {})
        lines.append(f"- JSON report: {artifacts.get('json_report')}")
        lines.append(f"- Process tree graph (Mermaid): {artifacts.get('process_tree_mermaid')}")
        if artifacts.get("file_etw_xml"):
            lines.append(f"- File ETW XML: {artifacts.get('file_etw_xml')}")
        if artifacts.get("process_etw_xml"):
            lines.append(f"- Process ETW XML: {artifacts.get('process_etw_xml')}")
        if artifacts.get("registry_etw_xml"):
            lines.append(f"- Registry ETW XML: {artifacts.get('registry_etw_xml')}")
        lines.append("")

        return "\n".join(lines)

    def write_outputs(self) -> None:
        # parse ETW xml to enrich report
        self.parse_etw_process_xml()
        self.parse_etw_registry_xml()
        self.parse_etw_file_xml()

        report = self.build_report()

        # Always render console to stdout (useful during triage)
        console = self.render_console(report)
        print(console, flush=True)

        # Core outputs (keep JSON/TXT/Mermaid as before)
        json_path = self.out_dir / "report.json"
        mmd_path = self.out_dir / "process_tree.mmd"
        txt_path = self.out_dir / "console_report.txt"

        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        mmd_path.write_text(self.mermaid_tree(report["process"]["tree"]), encoding="utf-8")
        txt_path.write_text(console, encoding="utf-8")

        # HTML report (full JSON -> HTML; does NOT embed XML content)
        if not bool(self.cfg.get("disable_html", False)):
            try:
                from .report_html import write_html_report

                out_html = self.cfg.get("out_html")
                if out_html:
                    html_path = Path(str(out_html)).expanduser().resolve()
                else:
                    html_path = self.out_dir / "report.html"

                write_html_report(report, html_path, base_dir=self.out_dir)
            except Exception as e:
                self.log(f"[!] HTML report generation failed: {type(e).__name__}: {e}")


