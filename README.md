# MalMon

**MalMon** is a **Windows-only** dynamic runtime monitor aimed at quick malware/suspicious-sample triage.  
It can **run a target** (EXE), **open an Office document**, or **wait for a process** — then tracks the process tree and exports a **structured JSON report** + readable console output.

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
# Monitor for 30 seconds (default)
malmon exe C:\path\to\sample.exe

# Pass arguments to the target EXE (use -- to force pass-through)
malmon exe C:\path\to\sample.exe -- --arg1 --arg2

# Change output folder and duration
malmon exe C:\path\to\sample.exe --out MyRun_01 --duration 60
```

### هل لازم أكتب Path ولا ينفع أكتب اسم البرنامج بس؟

ينفع في وضع `exe` تكتب **اسم exe بس** لو موجود في `PATH`، لأن MalMon بيعمل:
- لو الملف موجود كـ path → يستخدمه
- لو مش موجود → يدور في `PATH` + `PATHEXT` (زي ما Windows بيعمل)

أمثلة:

```bash
malmon exe notepad
malmon exe cmd -- /c whoami
```

لو البرنامج **مش** في PATH، يبقى لازم تكتب **المسار الكامل** (أو path نسبي من الـ current directory).

---

### 2) Office document mode

```bash
malmon office C:\path\to\doc.docm --duration 90
```

MalMon يفتح المستند عبر Windows association وبعدين يحاول يـ attach على الـ Office process المناسب (best-effort).  
لو ماقدرش يطابق مسار الملف في command line، ممكن يختار instance موجودة (وبيعلّم الحالة **degraded**).

---

### 3) Wait mode (attach when process appears)

```bash
malmon wait --image rundll32.exe --timeout 120 --duration 60
malmon wait --image powershell.exe --cmd-contains "EncodedCommand" --timeout 120
```

---

## Help / Full help

General help:

```bash
malmon --help
```

Help for a specific subcommand:

```bash
malmon exe --help
malmon office --help
malmon wait --help
```

**Full help for all subcommands in one output:**

```bash
malmon --full-help
```

---

## Outputs

MalMon writes to the output folder (default: `MalMon_output`):

- `report.json` — structured report (everything)
- `console_report.txt` — human-readable summary
- `process_tree.mmd` — Mermaid flowchart for the process tree
- `fw_proc_<runid>.xml/.etl` — ETW process capture (if enabled)
- `fw_reg_<runid>.xml/.etl` — ETW registry capture (if enabled)
- `fw_file_<runid>.xml/.etl` — ETW file capture (if enabled)

---

## Convert JSON report to HTML

After you have `report.json`, convert it:

```bash
malmon MalMon_output\report.json

# or choose output path:
malmon MalMon_output\report.json --out MalMon_output\report.html
```

The HTML is a **standalone file** and can be opened locally in any browser.

✅ The generated HTML also includes an **ETW XML files** section with links to the `.xml` captures (and a safe preview snippet).

---

## Notes / Limitations

- Best-effort: ETW can fail if permissions/providers are missing.
- File/registry ETW can be noisy; MalMon includes a filtered view for files.
- Network is snapshot-based (not packet capture).

---

## License

Add your preferred license (MIT/Apache-2.0/etc.) before publishing publicly.


## HTML report (built-in)

By default, MalMon generates `report.html` inside the output folder.

✅ The HTML includes an **ETW XML** section that is **safe for large files**:
- Shows **links** to the generated `.xml` files (they remain on disk).
- Shows **lightweight stats** (event count, top providers, time range when available).
- Shows a **small sample table** of events (preview) inside the HTML.

This avoids browser crashes that can happen when embedding huge XML contents in one HTML file.

Options:

```bash
malmon exe C:\path\to\sample.exe --disable-html
malmon exe C:\path\to\sample.exe --out-html                 # write to <out>\report.html
malmon exe C:\path\to\sample.exe --out-html C:\test\report.html
```

> Tip: If you set `--out-html` to a different folder, MalMon will copy the `.xml` files next to the HTML so the links still work.

