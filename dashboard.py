"""
Multi-File Integrity Monitoring System (FIMS)
Streamlit Dashboard
"""

import os
import sys
import json
import hashlib
import streamlit as st
from datetime import datetime

# ── Environment detection ─────────────────────────────────────────────────────
# Streamlit Cloud runs on Linux; local machine is Windows
IS_LOCAL = sys.platform == "win32"

if IS_LOCAL:
    BASE_DIR      = r"C:\Users\harie\Desktop\FIMS"
    MONITORED_DIR = os.path.join(BASE_DIR, "monitored_files")
    BASELINE_FILE = os.path.join(BASE_DIR, "hashes", "baseline.json")
    REPORT_JSON   = os.path.join(BASE_DIR, "reports", "scan_report.json")
    REPORT_TXT    = os.path.join(BASE_DIR, "reports", "scan_report.txt")
else:
    BASE_DIR      = None
    MONITORED_DIR = None
    BASELINE_FILE = None
    REPORT_JSON   = None
    REPORT_TXT    = None


# ── Sample data for cloud demo ────────────────────────────────────────────────
DEMO_BASELINE = {
    "timestamp": "2025-04-01 09:00:00",
    "files": {
        "sample1.txt": "a3f1e2c4b5d67890abcdef1234567890abcdef1234567890abcdef1234567890",
        "sample2.txt": "b4e2f3d5c6e78901bcdef0123456789abcdef0123456789abcdef0123456789a",
        "sample3.txt": "c5f3e4d6b7f89012cdef01234567890bcdef01234567890bcdef01234567890b"
    }
}

DEMO_REPORT = {
    "baseline_timestamp": "2025-04-01 09:00:00",
    "scan_timestamp":     "2025-04-01 09:15:42",
    "summary": {
        "total_changes": 3,
        "modified": 1,
        "deleted":  1,
        "added":    1
    },
    "changes": {
        "modified": [
            {
                "file":     "sample1.txt",
                "old_hash": "a3f1e2c4b5d67890abcdef1234567890abcdef1234567890abcdef1234567890",
                "new_hash": "99ff1122aabbccddeeff00112233445566778899aabbccddeeff001122334455"
            }
        ],
        "deleted": [
            {
                "file":     "sample2.txt",
                "old_hash": "b4e2f3d5c6e78901bcdef0123456789abcdef0123456789abcdef0123456789a"
            }
        ],
        "added": [
            {
                "file":     "malicious.txt",
                "new_hash": "ff00ee11dd22cc33bb44aa5599887766554433221100ffeeddccbbaa99887766"
            }
        ]
    }
}


# ── Utilities ─────────────────────────────────────────────────────────────────
def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (IOError, PermissionError) as e:
        return f"ERROR: {e}"


def scan_directory(directory):
    if not directory or not os.path.isdir(directory):
        return {}
    hashes = {}
    for filename in sorted(os.listdir(directory)):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            hashes[filename] = compute_sha256(filepath)
    return hashes


def load_baseline():
    if not IS_LOCAL:
        return DEMO_BASELINE
    if not BASELINE_FILE or not os.path.exists(BASELINE_FILE):
        return None
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)


def save_baseline(hashes):
    data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "files": hashes
    }
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=4)
    return data


def load_report():
    if not IS_LOCAL:
        return DEMO_REPORT
    if not REPORT_JSON or not os.path.exists(REPORT_JSON) or os.path.getsize(REPORT_JSON) == 0:
        return None
    with open(REPORT_JSON, "r") as f:
        return json.load(f)


def run_integrity_check():
    baseline_data   = load_baseline()
    if not baseline_data:
        return None
    baseline_hashes = baseline_data["files"]
    current_hashes  = scan_directory(MONITORED_DIR)
    scan_time       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    modified, deleted, added = [], [], []

    for filename, old_hash in baseline_hashes.items():
        if filename not in current_hashes:
            deleted.append({"file": filename, "old_hash": old_hash})
        elif current_hashes[filename] != old_hash:
            modified.append({"file": filename, "old_hash": old_hash, "new_hash": current_hashes[filename]})

    for filename in current_hashes:
        if filename not in baseline_hashes:
            added.append({"file": filename, "new_hash": current_hashes[filename]})

    report = {
        "baseline_timestamp": baseline_data["timestamp"],
        "scan_timestamp":     scan_time,
        "summary": {
            "total_changes": len(modified) + len(deleted) + len(added),
            "modified": len(modified),
            "deleted":  len(deleted),
            "added":    len(added)
        },
        "changes": {
            "modified": modified,
            "deleted":  deleted,
            "added":    added
        }
    }

    with open(REPORT_JSON, "w") as f:
        json.dump(report, f, indent=4)

    with open(REPORT_TXT, "w") as f:
        f.write("=" * 55 + "\n")
        f.write("  FIMS Integrity Scan Report\n")
        f.write("=" * 55 + "\n")
        f.write(f"  Baseline taken : {baseline_data['timestamp']}\n")
        f.write(f"  Scan time      : {scan_time}\n")
        f.write("-" * 55 + "\n\n")
        total = report["summary"]["total_changes"]
        if total == 0:
            f.write("  STATUS: ALL FILES INTACT\n\n")
        else:
            f.write(f"  STATUS: {total} CHANGE(S) DETECTED\n\n")
            if modified:
                f.write("  MODIFIED FILES:\n")
                for item in modified:
                    f.write(f"    - {item['file']}\n")
                    f.write(f"      Old: {item['old_hash']}\n")
                    f.write(f"      New: {item['new_hash']}\n")
                f.write("\n")
            if deleted:
                f.write("  DELETED FILES:\n")
                for item in deleted:
                    f.write(f"    - {item['file']}\n")
                    f.write(f"      Was: {item['old_hash']}\n")
                f.write("\n")
            if added:
                f.write("  ADDED (UNAUTHORISED) FILES:\n")
                for item in added:
                    f.write(f"    - {item['file']}\n")
                    f.write(f"      Hash: {item['new_hash']}\n")
                f.write("\n")
        f.write("=" * 55 + "\n")

    return report


# ══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD UI
# ══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="FIMS Dashboard",
    page_icon="🔒",
    layout="wide"
)

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🔒 Multi-File Integrity Monitoring System")
st.markdown("**Hemstone Kerry**")

if not IS_LOCAL:
    st.info("🌐 **Cloud Demo Mode** — Running on Streamlit Cloud with sample data to demonstrate system functionality.")

st.divider()

# ── Sidebar ───────────────────────────────────────────────────────────────────
st.sidebar.title("⚙️ Controls")

if IS_LOCAL:
    st.sidebar.markdown("Use the buttons below to run each phase.")
    run_baseline = st.sidebar.button("📁 Phase 1 — Run Baseline Scan", use_container_width=True)
    run_check    = st.sidebar.button("🔍 Phase 3 — Run Integrity Check", use_container_width=True)
    st.sidebar.divider()
    st.sidebar.markdown("**Monitored Directory:**")
    st.sidebar.code(MONITORED_DIR)
else:
    st.sidebar.markdown("Running in **Cloud Demo Mode.**")
    st.sidebar.markdown("To run the full live system, clone this repo and run locally:")
    st.sidebar.code("streamlit run dashboard.py")
    run_baseline = False
    run_check    = False

# ── Phase 1: Run Baseline ─────────────────────────────────────────────────────
if IS_LOCAL and run_baseline:
    with st.spinner("Scanning directory and generating hashes..."):
        hashes = scan_directory(MONITORED_DIR)
        data   = save_baseline(hashes)
    st.success(f"✅ Baseline saved — {len(hashes)} file(s) scanned at {data['timestamp']}")

# ── Baseline Table ────────────────────────────────────────────────────────────
st.subheader("📋 Baseline — Trusted File State")
baseline_data = load_baseline()

if baseline_data:
    st.caption(f"Baseline created: {baseline_data['timestamp']}")
    baseline_rows = [
        {"File": fname, "SHA-256 Hash": hash_val}
        for fname, hash_val in baseline_data["files"].items()
    ]
    st.dataframe(baseline_rows, use_container_width=True)
else:
    st.info("No baseline found. Click **Phase 1 — Run Baseline Scan** in the sidebar.")

st.divider()

# ── Phase 3: Run Check ────────────────────────────────────────────────────────
if IS_LOCAL and run_check:
    with st.spinner("Running integrity check..."):
        report = run_integrity_check()
    if report:
        total = report["summary"]["total_changes"]
        if total == 0:
            st.success("✅ All files are INTACT. No changes detected.")
        else:
            st.error(f"⚠️ {total} change(s) detected!")

# ── Report Display ────────────────────────────────────────────────────────────
st.subheader("📊 Integrity Check Report")
report = load_report()

if report:
    summary = report["summary"]
    changes = report["changes"]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Changes", summary["total_changes"],
                delta=None if summary["total_changes"] == 0 else f"+{summary['total_changes']}",
                delta_color="inverse")
    col2.metric("🟡 Modified", summary["modified"])
    col3.metric("🔴 Deleted",  summary["deleted"])
    col4.metric("🟠 Added",    summary["added"])

    st.caption(f"Baseline: {report['baseline_timestamp']}  |  Scan: {report['scan_timestamp']}")
    st.divider()

    if changes["modified"]:
        st.markdown("### 🟡 Modified Files")
        for item in changes["modified"]:
            with st.expander(f"📝 {item['file']}"):
                st.markdown("**Old Hash (Baseline):**")
                st.code(item["old_hash"])
                st.markdown("**New Hash (Current):**")
                st.code(item["new_hash"])

    if changes["deleted"]:
        st.markdown("### 🔴 Deleted Files")
        for item in changes["deleted"]:
            with st.expander(f"🗑️ {item['file']}"):
                st.markdown("**Hash at Baseline:**")
                st.code(item["old_hash"])
                st.warning("This file no longer exists in the monitored directory.")

    if changes["added"]:
        st.markdown("### 🟠 Unauthorised Added Files")
        for item in changes["added"]:
            with st.expander(f"⚠️ {item['file']}"):
                st.markdown("**Hash of New File:**")
                st.code(item["new_hash"])
                st.error("This file was NOT present in the baseline. Potential intrusion.")

    if summary["total_changes"] == 0:
        st.success("✅ All files are INTACT. No unauthorised changes detected.")

else:
    st.info("No report found. Click **Phase 3 — Run Integrity Check** in the sidebar.")
