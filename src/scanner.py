import re
from pathlib import Path

# Dictionary of secret types and their corresponding regex patterns
PATTERNS = {
    "AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "Generic Private Key": r"-----BEGIN (RSA|OPENSSH|EC|PGP)? PRIVATE KEY-----",
    "Generic API Key / Token": r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
}


class SecretScanner:

    def __init__(self, target_path: Path):
        self.target_path = target_path

    def scan_file(self, file_path: Path) -> list[dict]:
        """Scans a single file for known secret patterns."""
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    for secret_type, pattern in PATTERNS.items():
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            findings.append(
                                {
                                    "file": str(file_path),
                                    "line": line_num,
                                    "type": secret_type,
                                    "match": match.group(
                                        0
                                    ),  # Matched secret string
                                }
                            )
        except Exception as e:
            # Ignores files that cannot be opened (e.g., binary files)
            pass

        return findings

    def scan_directory(self) -> list[dict]:
        """Recursively scans all files in the target directory."""
        results = []

        # Ignore common non-source directories
        ignored_dirs = {".git", ".venv", "venv", "__pycache__", "node_modules"}

        if self.target_path.is_file():
            return self.scan_file(self.target_path)

        for path in self.target_path.rglob("*"):
            # Skip ignored directories and non-file paths
            if any(ignored in path.parts for ignored in ignored_dirs):
                continue
            if path.is_file():
                results.extend(self.scan_file(path))

        return results