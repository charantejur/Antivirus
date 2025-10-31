## Antivirus Utility

A simple antivirus/quarantine utility driven by `antivirus.py`. It scans uploaded files, quarantines suspicious items, and organizes inputs under `uploads/` with isolated storage in `quarantine/`.

### Features
- **Scan files** in `uploads/`
- **Quarantine** flagged files into `quarantine/`
- **Simple, local-only workflow** suitable for demos or small utilities

## Requirements
- **Python 3.10+** (works on Windows PowerShell)


## Usage
1. Place files you want to scan inside the `uploads/` directory.
2. Run `python antivirus.py` from the project root.
3. Review the console output for scan results.
4. Any flagged files will be moved to `quarantine/`.

## Project Structure
```text
Antivirus/
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

