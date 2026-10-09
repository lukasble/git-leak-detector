import argparse
import sys
from pathlib import Path
from src.scanner import SecretScanner


def main():
    parser = argparse.ArgumentParser(
        description="Git Leak Detector - Scan files for leaked API keys and secrets."
    )
    parser.add_argument(
        "path",
        type=str,
        nargs="?",
        default=".",
        help="Path to file or directory to scan (default: current directory)",
    )

    args = parser.parse_args()
    target_path = Path(args.path)

    if not target_path.exists():
        print(f"Error: Path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning target: {target_path.resolve()}\n")

    scanner = SecretScanner(target_path)
    findings = scanner.scan_directory()

    if not findings:
        print("No secrets detected. Great job!")
        sys.exit(0)

    print(f"ALERT: Found {len(findings)} potential secret(s):\n")
    for finding in findings:
        print(
            f"  [!] Type: {finding['type']}\n"
            f"      File: {finding['file']}:{finding['line']}\n"
            f"      Match: {finding['match']}\n"
        )

    # Exit with non-zero code if secrets are found (ideal for CI/CD pipelines)
    sys.exit(1)


if __name__ == "__main__":
    main()