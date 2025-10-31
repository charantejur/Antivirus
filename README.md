## Charan Antivirus Utility

A simple antivirus/quarantine utility driven by `antivirus.py`. It scans uploaded files, quarantines suspicious items, and organizes inputs under `uploads/` with isolated storage in `quarantine/`.

### Features
- **Scan files** in `uploads/`
- **Quarantine** flagged files into `quarantine/`
- **Simple, local-only workflow** suitable for demos or small utilities

## Requirements
- **Python 3.10+** (works on Windows PowerShell)

## Getting Started (Windows PowerShell)
```powershell
# From the project root
cd C:\Users\vinay\Desktop\Charan

# (Optional) Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Run the scanner
python antivirus.py
```

If your execution policy blocks venv activation, you can temporarily allow it in the current session:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\.venv\Scripts\Activate.ps1
```

## Usage
1. Place files you want to scan inside the `uploads/` directory.
2. Run `python antivirus.py` from the project root.
3. Review the console output for scan results.
4. Any flagged files will be moved to `quarantine/`.

## Project Structure
```text
Charan/
  antivirus.py   # Main scan/quarantine script
  uploads/       # Drop files here to be scanned
  quarantine/    # Suspicious files are moved here
  README.md      # This file
```

## Quarantine Handling
- Files moved to `quarantine/` are considered unsafe—do not execute them.
- To restore a file you are sure is safe, move it back to `uploads/` (or its original location) after verifying it.

## Configuration
If `antivirus.py` exposes configurable options (e.g., patterns, thresholds, or logging), set them within the script or via environment variables as indicated by in-file docs.


## License
Provided as-is with no warranty. You may adapt and use at your own risk.



