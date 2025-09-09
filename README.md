# PyRedact-MV 🛡️

A professional, installable command-line tool to detect and de-identify Personally Identifiable Information (PII) from CSV files. Built for performance, security, and ease of use.

## Features

- **Comprehensive PII Detection**: Detects a wide range of global and Indian-specific PII types.
- **Flexible Input**: Scan a single `.csv` file or an entire directory of them.
- **Selective Scanning**: Choose to scan for all PII types or only for specific ones.
- **Professional CLI**: A user-friendly interface with a startup banner, progress bars, a self-documenting `--help` menu, and clear error messages.
- **Secure and Robust**: Handles various file encodings, permission errors, and is designed with security best practices in mind.

---

## Installation & First-Time Setup

This guide will walk you through the professional, recommended way to set up a clean workspace for using `pyredact-mv`.

#### **Step 1: Create Your Workspace**

First, create a main folder where you will run the tool and store your data files.

- **Action:** Open PowerShell and run these commands.

  ```powershell
  # Create a main folder for your scanning projects and go inside it
  mkdir My-PII-Scans
  cd My-PII-Scans

  # Create a sub-folder to hold your CSV files
  mkdir sample_files
  ```

- You should now have a structure like `My-PII-Scans/sample_files/`. Place any CSV files you want to scan inside the `sample_files` folder.

#### **Step 2: Set Up the Python Environment**

It is highly recommended to use a virtual environment. This keeps your system clean and ensures the tool runs perfectly.

- **Action:** From inside your `My-PII-Scans` folder, run these commands.

  ```powershell
  # Create the virtual environment
  python -m venv venv

  # Activate the virtual environment
  .\venv\Scripts\Activate.ps1
  ```

- You will see `(venv)` appear in your terminal prompt.

#### **Step 3: Install `pyredact-mv`**

Now, install the tool from the Python Package Index (PyPI).

- **Action:** With your `(venv)` active, run:
  `powershell
    pip install pyredact-mv
    `
  Your setup is now complete. The `pyredact-mv` command is active and ready to use.

---

## Usage Guide

All commands should be run from your main workspace folder (e.g., `My-PII-Scans`) with your `(venv)` active.

### **Getting Help**

To see a full list of all available commands and options at any time, run:

```bash
pyredact-mv --help
```

### **Example Scenarios**

#### **Basic Scan of a Single File**

This will scan one file and save the results to a default folder named `output`.

```bash
pyredact-mv --input sample_files/your_data.csv
```

#### **Scanning an Entire Directory**

This will find and process every `.csv` file inside the `sample_files` folder.

```bash
pyredact-mv --input-dir sample_files
```

#### **Advanced Scan (Combining Multiple Options)**

Here is an example of a more complex command that combines multiple flags.

**Command:**

```bash
pyredact-mv --input sample_files/your_data.csv --types "EMAIL,PAN_CARD,AADHAAR" --output "C:\Users\YourName\Desktop\Secure_Results" --verbose --force
```

**Breakdown of this command:**

| Command Part                         | What It Does                                                                                 |
| :----------------------------------- | :------------------------------------------------------------------------------------------- |
| `pyredact-mv`                        | Runs the application.                                                                        |
| `--input sample_files/your_data.csv` | Specifies the single file to scan.                                                           |
| `--types "EMAIL,PAN_CARD,AADHAAR"`   | Narrows the scan to look **only** for these three PII types.                                 |
| `--output "C:\... \Secure_Results"`  | Saves the output files to a specific folder on the Desktop.                                  |
| `--verbose`                          | Prints detailed, line-by-line logs to the screen as it works.                                |
| `--force`                            | If the output files already exist, this will overwrite them without asking for confirmation. |
