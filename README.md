# YARA Playground: The Forensic Artisan's Toolkit

[![YARA](https://img.shields.io/badge/YARA-v4.x-red.svg)](https://virustotal.github.io/yara/)
[![UI](https://img.shields.io/badge/UI-CustomTkinter-blue.svg)](https://github.com/TomSchimansky/CustomTkinter)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A high-fidelity, production-grade YARA toolkit for modern threat researchers. The YARA Playground provides a unified, glassmorphic interface for collecting global rules, drafting precision signatures, and executing large-scale scans with clinical accuracy.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Core Modules](#core-modules)
  - [Rule Collector & Intelligence](#rule-collector--intelligence)
  - [YARA Lab (IDE)](#yara-lab-ide)
  - [Deep Search Engine](#deep-search-engine)
  - [File Scanner](#file-scanner)
  - [YARA Generator](#yara-generator)
- [Data Architecture](#data-architecture)
- [Installation](#installation)
- [Deduplication Logic](#deduplication-logic)
- [Security & AI](#security--ai)

---

## Quick Start

To launch the primary dashboard:

```powershell
python Scripts/yara_playground.py
```

Need a standalone version? Use the provided `build.bat` to compile a single-file executable.

---

## Core Modules

### Rule Collector & Intelligence

Centrally manage threat intelligence from over 50+ global sources. The collector uses a **Smart Tiered Sorting Engine**:

- **Master Rulebase**: Automatically compiles verified, safe-for-all-environments rules into `public_master_rules.yara`.
- **Environment-Specific**: Rules requiring missing modules (e.g., `dotnet`, `lnk`, `magic`) are isolated to prevent repository corruption.
- **Automatic Promotion**: The "Fix Problematic Rules" engine now validates rules **first**. If you manually fix a rule in the folder, the engine recognizes it instantly and promotes it to Master.
- **AI Rule Repair**:
  - **Single-Pass Precision**: High-speed AI repair attempts focused on surgical accuracy.
  - **Context-Aware**: The AI receives the **exact YARA compilation error** to ensure the fix addresses the root cause.

### YARA Lab (IDE)

A sophisticated IDE for professional signature development.

- **Workspace Toggle**: A new header switcher allows seamless flipping between **Split View**, **Editor Only**, and **Result Only** modes.
- **Deep Syntax Highlighting**: Premium coloring for YARA keywords, strings, regex, numeric literals, and hex-byte arrays.
- **Live Validation**: Instant compilation checks with auto-injection of modules like `pe`, `elf`, `math`, `hash`, and `dotnet`.
- **Advanced File Ingest**: Support for **Drag-and-Drop** for both binary samples and existing YARA signatures.

### Deep Search Engine

A discovery module capable of indexing thousands of labels and patterns in seconds.

- **Global Indexing**: Searches across the Master file, Downloaded repositories, and even the Quarantine.
- **Full-Text Discovery**: Search by rule name, author, or specific string constants.
- **Duplicate Filtering**: Smart hashing prevents seeing the same rule name twice during a search.

### File Scanner (Triage Engine)

The primary scanning engine for rapid sample analysis.

- **Batch Triage**: Supports surgical **Single File** analysis or **Entire Folder** bulk scans.
- **Snippet Isolation**: Clicking a detection result instantly extracts and displays **only** the relevant rule block, even from 100MB+ master files.

### YARA Generator

Deep integration with **yarGen** for automated rule creation.

- **Smart Blueprinting**: Produce complex opcode and string-based signatures from binary samples automatically.
- **Clean Output**: Rules flow directly into the Lab for immediate refinement.

---

## Data Architecture

| Directory | Purpose |
| :--- | :--- |
| **`Master Rules/`** | The "Golden Image" rulebase, optimized and 100% valid for your machine. |
| **`Problematic Rules/`** | Repository for broken rules awaiting repair or manual audit. |
| **`Fixed Rules/`** | Repaired rules that have passed validation. |
| **`Environment-specific/`** | Valid rules that require modules not present in your local environment. |
| **`problematic_rules.txt`** | A living manifest documenting every failure and its specific error. |
| **`config/AI.cfg`** | Configuration for the AI repair engine. |

---

## Installation

### 1. Requirements

- **Python 3.11+**
- **Visual C++ Redistributable** (Required for `yara-python`)

### 2. Setup

Clone the repository and install dependencies:

```powershell
pip install -r requirements.txt
```

### 3. Build Executable (Optional)

Run `build.bat` to generate a portable `YARA_Playground.exe` in the root directory.

---

## Deduplication Logic

The Playground implements a **Global Deduplication Engine**. When running a deduplication sweep:

1. It indexes every rule name in the `Master Rules` folder.
2. If a name conflict is found across different files, it keeps the first occurrence and strips the others.
3. This ensures your master rulebase remains clean and free of "Duplicate Identifier" errors while preserving all unique logic.

---

## Security & AI

> [!WARNING]
> **API Key Safety**: Your `config/AI.cfg` contains your OpenAI API key. This file is included in `.gitignore` to prevent accidental public disclosure. **NEVER** commit this file to a public repository.

### Configuring AI Repair

The application includes an automated repair engine, but your private API key is required.

1. Navigate to the `config/` directory.
2. Duplicate the `AI.cfg.example` file and rename the copy to `AI.cfg`.
3. Open `AI.cfg` and enter your OpenAI (or compatible) details:

```json
{
  "base_url": "https://api.openai.com/v1",
  "api_key": "sk-your-key-here",
  "model": "gpt-4o"
}
```

*Note: The `AI.cfg` file is automatically ignored by Git to keep your keys safe.*

---

*Developed for the Forensic Community by Researchers.*
