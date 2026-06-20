# triAAge-collector

A lightweight Windows forensic triage script coupled with a portable HTML dashboard for quick artifact analysis.

![Triage Dashboard Preview](https://img.shields.io/badge/DFIR-Tool-blueviolet)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Project Overview

**triAAge-collector** is a two-part DFIR tool designed for analysts to quickly gather volatile artifacts from a suspected Windows machine and visualize them immediately in a secure, local web dashboard.

*   **`triage.ps1`**: Runs on the target host to collect live system info, active processes (with parent-child relationships and file hashes), network connections, and common persistence mechanisms.
*   **`report-viewer.html`**: A completely static, offline-ready dashboard that parses the output JSON, offering filterable, searchable, and resizable tables to pivot and detect anomalies quickly.

<img width="1053" height="163" alt="ps1_screenshot" src="https://github.com/user-attachments/assets/5cc16965-9e80-4878-bbd9-5517dea5b05b" />
<img width="1053" height="754" alt="viewer_screenshot" src="https://github.com/user-attachments/assets/a91cbf03-cd53-4fd3-b6bc-0dca8889b716" />


---

## Key Features

### 1. Host triage collector
*   **System Profiling**: Gathers Hostname, OS details, current user context, and timezone-aware local time (ISO 8601).
*   **Process Auditing**:
    *   Retrieves process command lines.
    *   Maps Parent Process IDs (PPID) to trace process lineage (e.g., shell launched by a web server).
    *   Computes SHA256 hashes of running binaries.
*   **Network Mapping**: Extracts active TCP/UDP connections and binds them to the owning Process ID (PID).
*   **Autostart/Persistence Discovery**:
    *   Inspects HKLM/HKCU Registry `Run` and `RunOnce` keys.
    *   Scans User & System Startup directories.
    *   Lists non-system automatic services (de-noised by filtering standard Windows paths).

### 2. Interactive analysis web app
*   **Zero-Dependency**: Built with pure vanilla HTML, CSS, and JS. No server or internet connection required.
*   **Interactive Tables**: Supports real-time text filtering and resizable columns (drag-and-drop handles) to easily read long command lines.
*   **Forensic Heuristics**: Automatically highlights suspicious process paths (e.g., binaries executed from `\Temp\` or `\AppData\`).

---

## Getting started

### Step 1: Collect artifacts on the target host
1. Open PowerShell as **Administrator**.
2. Run the collector script:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\triage.ps1
   ```
3. The script will create a folder named `TriAAge_Reports/` in the same directory and save a JSON report (e.g., `TriAAge_DESKTOP-NAME_20260620_113000.json`).

### Step 2: Analyze the JSON report
1. Double-click `report-viewer.html` to open it in your browser.
2. Click **Load JSON report** and select the generated JSON file.
3. Use the tabs (Processes, Network, Persistence) and search bars to investigate the system's state.

---

## Repository structure

```text
├── triage.ps1           # Target host collector script
├── report-viewer.html   # HTML5 viewer dashboard
├── .gitignore           # Ignores generated triage reports
└── README.md            # This documentation file
```

---

## License

This project is licensed under the MIT License. Feel free to use, modify, and share it.
