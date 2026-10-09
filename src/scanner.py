import math
import re
from pathlib import Path

PATTERNS = {
    "AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "Generic Private Key": r"-----BEGIN (RSA|OPENSSH|EC|PGP)? PRIVATE KEY-----",
    "Generic API Key / Token": r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
}


def calculate_entropy(data: str) -> float:
    """Calculates Shannon Entropy (randomness) of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy


def mask_secret(secret: str) -> str:
    """Redacts secrets so they are not leaked in plain text in logs."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


class SecretScanner:

    def __init__(self, target_path: Path, entropy_threshold: float = 4.8):
        self.target_path = target_path
        self.entropy_threshold = entropy_threshold

    def scan_file(self, file_path: Path) -> list[dict]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    # Skip lines containing PATTERNS dictionary definition to avoid self-flagging
                    if "PATTERNS = {" in line or "Generic API Key" in line:
                        continue

                    # 1. Regex Match
                    for secret_type, pattern in PATTERNS.items():
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            matched_str = match.group(0)
                            findings.append(
                                {
                                    "file": str(file_path),
                                    "line": line_num,
                                    "type": secret_type,
                                    "raw_match": matched_str,
                                    "masked_match": mask_secret(matched_str),
                                    "entropy": round(
                                        calculate_entropy(matched_str), 2
                                    ),
                                }
                            )

                    # 2. High Entropy Token Check for standalone words
                    words = line.strip().split()
                    for word in words:
                        clean_word = word.strip("'\"=:,;")
                        if (
                            len(clean_word) >= 20
                            and not any(
                                f["raw_match"] == clean_word for f in findings
                            )
                        ):
                            entropy = calculate_entropy(clean_word)
                            if entropy >= self.entropy_threshold:
                                findings.append(
                                    {
                                        "file": str(file_path),
                                        "line": line_num,
                                        "type": f"High Entropy String (Score: {round(entropy, 2)})",
                                        "raw_match": clean_word,
                                        "masked_match": mask_secret(clean_word),
                                        "entropy": round(entropy, 2),
                                    }
                                )
        except Exception:
            pass

        return findings

    def scan_directory(self) -> list[dict]:
        """Recursively scans all files in the target directory."""
        ignored_dirs = {
            ".git",
            ".venv",
            "venv",
            "__pycache__",
            "node_modules",
            ".pytest_cache",
            "tests",
        }

        if self.target_path.is_file():
            return self.scan_file(self.target_path)

        results = []
        for path in self.target_path.rglob("*"):
            if any(ignored in path.parts for ignored in ignored_dirs):
                continue
            if path.is_file():
                results.extend(self.scan_file(path))

        return results