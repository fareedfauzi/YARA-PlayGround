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

### YARA Scanner

Scan files or folders using collected thousands of YARA rules.

- **Fast Scanning**: Choose a folder and see threats instantly.
- **Smart View**: Click a match to see the exact code that found the threat.

<img width="1920" height="1032" alt="image" src="https://github.com/user-attachments/assets/36c4c6f9-19c1-48b8-ada8-bb845386c9ec" />


### YARA Editor and Tester (Lab)

Write and test your rules in one place.

- **Live Check**: Tells you if your code has mistakes.
- **Batch Test**: Run your rule against many files at once to see if the detection works.
- **AI Fix**: Uses AI to automatically fix broken rules.

<img width="1402" height="932" alt="image" src="https://github.com/user-attachments/assets/7e8ee304-db29-4b89-9bcc-9d2d39976e5e" />


### YARA Collector

Keep your rules organized and up to date.

- **Auto-Download**: Gets rules from over 50 sources automatically.
- **Rule Cleanup**: Finds broken rules and moves them so they don't stop the scanner.
- **AI Repair**: Uses AI to fix entire folders of broken rules.

<img width="1402" height="932" alt="image" src="https://github.com/user-attachments/assets/c04acd2f-5317-4cdc-92f2-9b6ab094e29a" />

### YARA Generator

Create new rules automatically using yarGen-Go by Neo23x0.

Refer https://github.com/Neo23x0/yarGen-Go/tree/main for installation of the tool.

- **Auto-Rule**: Point it at a malware folder, and it will write a rule for you.

<img width="1402" height="932" alt="image" src="https://github.com/user-attachments/assets/893d6388-00ed-4861-8593-92119c478b66" />

### YARA Search

Find any rule in your library instantly.

- **Fast Search**: Search by name, author, or any text inside the rules.
- **Quick Preview**: See the rule code without opening the file.

<img width="1402" height="932" alt="image" src="https://github.com/user-attachments/assets/53b9674e-b966-494f-b9e4-af3d03f71fbe" />

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
