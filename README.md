# Git Leak Detector (`git-leak-detector`)

Git Leak Detector is a lightweight Python CLI designed to prevent accidental secret exposure before code reaches version control. It is intended for local development, pre-commit validation, and CI/CD pipelines where catching leaked credentials early is important.

The project targets developers and security-conscious teams who want a fast, easy-to-run check for hardcoded secrets in files and repositories. The goal is to provide a simple shift-left security control that reduces the risk of AWS keys, GitHub tokens, private keys, and other sensitive values being committed by mistake. This is a personal project and I have previously worked in teams with other developers and wanted to try to develop a lightweight scanner to identify leaks before making updates official.

## Features

- Detects common secrets using regex:
  - AWS keys
  - GitHub PATs
  - private keys
  - API tokens
- Checks for high-entropy values using Shannon entropy
- Masks detected secrets in output to avoid leaking them in logs
- Supports use as a Git pre-commit check
- Can be used in CI/CD workflows with JSON output
- Covered by pytest-based tests

## Project Structure

```text
git-leak-detector/
├── main.py
├── README.md
├── requirements.txt
├── src/
│   ├── cli.py
│   └── scanner.py
├── tests/
│   └── tests_secrets.txt
└── .gitignore
```

## Quick Start

### Install

```bash
git clone <repository-url>
cd git-leak-detector
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

### Run

```bash
python main.py .
```

This scans the selected path and reports matching secrets or suspicious high-entropy values.

## Usage Examples

### Standard scan

```bash
python main.py .
```

### JSON output

```bash
python main.py . --format json --output report.json
```

### Run tests

```bash
pytest -q
```

## Why this matters

This is a lightweight shift-left security control. The goal is to catch leaked credentials early, before code is committed or pushed. It helps reduce the risk of secrets ending up in repositories, logs, or CI artifacts.

The scanner combines two approaches:

- Pattern-based detection for known secret formats
- Entropy analysis to catch unusual or unstructured tokens

This gives better coverage than regex alone, while still staying lightweight and easy to run locally.

## Security Notes

- Do not rely on this as a replacement for proper secret management.
- Prefer environment variables or secret stores for production credentials.
- If a secret is detected, rotate it immediately.
- Keep this tool in local development and CI checks to catch issues early.

