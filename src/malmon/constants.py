from __future__ import annotations

from pathlib import Path

TOOL_NAME = "MalMon"
TOOL_VERSION = "1.0.1"

# -----------------------------
# Registry ETW event-id mapping
# Source: Velociraptor Windows.ETW.Registry EventLookup (common kernel-registry IDs)
# https://docs.velociraptor.app/artifact_references/pages/windows.etw.registry/
# -----------------------------

REG_EVENT_ID_MAP = {
    1: "RegCreateKey",
    2: "RegOpenKey",
    3: "RegDeleteKey",
    4: "RegQueryKey",
    5: "RegSetValue",
    6: "RegDeleteValue",
    7: "RegQueryValue",
    8: "RegEnumerateKey",
    9: "RegEnumerateValue",
}

WRITE_OPS = {"RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue"}

# -----------------------------
# File ETW event-id mapping (Microsoft-Windows-Kernel-File)
# Common event IDs:
# 12 Create, 14 Close, 15 Read, 16 Write, 17 SetInformation, 18 SetDelete, 19 Rename, 11 NameDelete
# -----------------------------

FILE_EVENT_ID_MAP = {
    11: "NameDelete",
    12: "Create",
    14: "Close",
    15: "Read",
    16: "Write",
    17: "SetInformation",
    18: "SetDelete",
    19: "Rename",
}

FILE_CREATE_OPS = {"Create"}
FILE_WRITE_OPS = {"Write", "SetInformation"}  # غالباً الـ drop/modify بيظهر هنا
FILE_DELETE_OPS = {"SetDelete", "NameDelete"}
FILE_RENAME_OPS = {"Rename"}

# --- CreateDisposition (best-effort, Kernel-File payload may expose it) ---
# Win32 CreateFile dispositions:
# 1 CREATE_NEW, 2 CREATE_ALWAYS, 3 OPEN_EXISTING, 4 OPEN_ALWAYS, 5 TRUNCATE_EXISTING
CREATE_DISPOSITION_MAP = {
    1: "CREATE_NEW",
    2: "CREATE_ALWAYS",
    3: "OPEN_EXISTING",
    4: "OPEN_ALWAYS",
    5: "TRUNCATE_EXISTING",
}
CREATE_DISP_STRONG_CREATE = {1, 2}  # high confidence "new/always create"
CREATE_DISP_MAY_CREATE = {4}  # medium confidence
CREATE_DISP_NOT_CREATE = {3, 5}  # open existing / truncate existing

SUSPICIOUS_EXT = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".com",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".hta",
    ".lnk",
    ".reg",
    ".msi",
    ".cab",
    ".jar",
    ".chm",
}
MACRO_DOC_EXT = {".docm", ".xlsm", ".pptm"}
