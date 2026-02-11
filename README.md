# MalMon

**MalMon** is a **Windows-only** dynamic runtime monitor aimed at quick malware/suspicious-sample triage.  
It can **run a target** (EXE), **open an Office document**, or **wait for a process** — then tracks the process tree and exports a **structured JSON an HTML report** + readable console output.

---

## What it monitors (best-effort)

- **Process tree** (descendants of the tracked root PID)  
  Source: **ETW** `Microsoft-Windows-Kernel-Process` (when enabled) + live snapshots.
- **Network** (TCP connections for tracked PIDs)  
  Source: `psutil.net_connections()` (preferred) or `netstat -ano` fallback.  
  ⚠️ Very short-lived connections can be missed if polling is too slow.
- **Registry** (tracked PIDs)  
  Source: **ETW** `Microsoft-Windows-Kernel-Registry` (often requires Administrator).
- **Files** (tracked PIDs)  
  Source: **ETW** `Microsoft-Windows-Kernel-File`.  
  Includes:
  - “filtered interesting paths” view (Temp/Downloads/Roaming/Startup…)
  - “probable new file creations” heuristics

---

## Requirements

- Windows 10/11 (or Windows Server) with:
  - `logman` + `tracerpt` (usually available by default)
- Python **3.9+**
- Optional: `psutil` (recommended; used for faster snapshots)

> ⚠️ Registry ETW frequently requires **Administrator**.  
> If not elevated, MalMon auto-disables registry ETW.

---

## Install (dev)

From inside the project folder:

```bash
python -m pip install -U pip
python -m pip install -e .
```

After that you will have:

- `malmon` (main CLI)

---

## Quick usage

### 1) Run an EXE and monitor it

```bash
# hellp options 
malmon --help # to show main help options 

malmon --full-help # to show all help options 

# Monitor for 30 seconds (default)
malmon exe C:\path\to\sample.exe

# Pass arguments to the target EXE (use -- to force pass-through)
malmon exe C:\path\to\sample.exe -- --arg1 --arg2

# Change output folder and duration
malmon exe C:\path\to\sample.exe --out MyRun_01 --duration 60
```


## Use Cases
```bash
# 1) Analyze an EXE (launch + monitor)
malmon exe "C:\path\to\sample.exe" --duration 30 --out "MalMon_output" --out-html

# pass arguments to the target (use -- to force pass-through)
malmon exe "C:\path\to\sample.exe" --duration 60 --out "MalMon_output" --out-html -- --arg1 value1 --arg2

# 2) Analyze an Office document (Word/Excel/PowerPoint)
malmon office "C:\path\to\document.docx" --duration 45 --out "MalMon_output" --out-html
malmon office "C:\path\to\sheet.xlsx"   --duration 45 --out "MalMon_output" --out-html
malmon office "C:\path\to\slides.pptx"  --duration 45 --out "MalMon_output" --out-html

# 3) Analyze a DLL (option A): run an exported function with rundll32 then monitor it
malmon exe C:\Windows\System32\rundll32.exe "C:\path\to\sample.dll",Run --duration 30 --out "MalMon_output" --out-html

# 3) Analyze a DLL (option B): wait for a loader process to appear then monitor it
# (useful if you have a custom loader or you want to attach to an already-known process name)
malmon wait --image rundll32.exe --cmd-contains sample.dll --duration 30 --out "MalMon_output" --out-html

```


---

## Support ⭐ && Feedback
If MalMon helped you during triage or analysis, please leave a ⭐ on the repo.

## Contact
Have an issue, Suggestions, improvements:
LinkedIn: https://www.linkedin.com/in/0xHouda/
