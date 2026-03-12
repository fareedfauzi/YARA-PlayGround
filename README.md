# YARA Playground

A toolkit for threat researchers to manage YARA rules, write signatures, and scan files. It provides a simple interface for collecting rules from many sources and fixing broken ones using AI.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Main Features](#main-features)
- [Folder Structure](#folder-structure)
- [Installation](#installation)
- [AI Configuration](#ai-configuration)

---

## Quick Start

Run the application with:

```powershell
python Scripts/yara_playground.py
```

To create a standalone EXE, run `build_exe.bat`.

---

## Main Features

### YARA Collector
Downloads and organizes YARA rules from over 50 sources.
- **Master Rules**: Automatically groups valid rules into one file.
- **Problematic Rules**: Moves broken rules to a separate folder so they don't stop the scanner.
- **AI Repair**: Uses OpenAI to fix syntax errors in broken rules automatically.

### YARA Editor and Tester
An editor for writing and testing YARA rules.
- **Syntax Highlighting**: Colors for keywords, strings, and regex.
- **Live Check**: Checks if your rule is valid while you type.
- **Drag and Drop**: Drag files directly into the editor to test them.

### Search and Scan
- **Search**: Find rules by name or content across all folders.
- **Scanner**: Scan files or entire folders to find threats.
- **Snippet View**: View only the specific rule that matched a file.

---

## Folder Structure

| Folder | Description |
| :--- | :--- |
| **Master Rules/** | Contains the main, valid YARA rules. |
| **Problematic Rules/** | Rules with syntax errors. |
| **Fixed Rules/** | Rules that were successfully repaired. |
| **Downloaded Public Rules/** | Raw rules from external sources. |
| **config/** | Settings and API configurations. |

---

## Installation

1. **Requirements**: Python 3.11 or newer.
2. **Setup**: Install the required libraries:

```powershell
pip install -r requirements.txt
```

---

## AI Configuration

To use the AI repair feature, you need an OpenAI API key.

1. Go to the `config/` folder.
2. Duplicate `AI.cfg.example` and rename it to `AI.cfg`.
3. Open `AI.cfg` and add your key:

```json
{
  "base_url": "https://api.openai.com/v1",
  "api_key": "your-api-key-here",
  "model": "gpt-4o"
}
```
