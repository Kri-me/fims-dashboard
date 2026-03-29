# 🔒 Multi-File Integrity Monitoring System (FIMS)
### Using SHA-256 Hashing

**Student:** Hemstone Kerry Ochieng  
**Adm No:** 22YAD106792  
**Course:** RBCS 7416 — Information Security  

---

## Overview

A Python-based File Integrity Monitoring System that scans a target directory, generates SHA-256 cryptographic hashes for all files, and detects any unauthorised modifications, deletions, or additions by comparing against a saved baseline.

---

## Project Structure

```
FIMS/
├── monitored_files/        # Directory being monitored
│   ├── sample1.txt
│   ├── sample2.txt
│   └── sample3.txt
├── hashes/
│   └── baseline.json       # Saved baseline hashes
├── reports/
│   ├── scan_report.txt     # Human-readable report
│   └── scan_report.json    # Machine-readable report
├── fims.py                 # Core CLI script (all 3 phases)
├── fims.ipynb              # Jupyter Notebook version
├── dashboard.py            # Streamlit dashboard
├── setup_fims.py           # One-time folder setup script
└── requirements.txt
```

---

## Phases

| Phase | Description |
|-------|-------------|
| Phase 1 | Baseline Scan — hash all files and save baseline |
| Phase 2 | Simulate Tampering — modify, delete, and add files |
| Phase 3 | Integrity Check — re-scan and detect changes |

---

## How to Run Locally

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/fims-dashboard.git
cd fims-dashboard
```

### 2. Install dependencies
```bash
pip install streamlit
```

### 3. Run the setup script (first time only)
```bash
python setup_fims.py
```

### 4. Run the CLI system
```bash
python fims.py
```

### 5. Run the Streamlit dashboard
```bash
streamlit run dashboard.py
```

---

## Live Dashboard

🌐 **[View Live Dashboard](#)** ← *(link to be added after deployment)*

> When running on Streamlit Cloud, the dashboard operates in **Cloud Demo Mode** using sample data to demonstrate system functionality.

---

## Technologies Used

- Python 3.x
- `hashlib` — SHA-256 hashing
- `json` — baseline and report storage
- `os` — directory scanning
- `streamlit` — visual dashboard

---

## License

For academic use — RBCS 7416, Information Security.
