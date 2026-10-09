import sys
from pathlib import Path

# Add the current directory to Python's module search path
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from src.cli import main

    if __name__ == "__main__":
        main()
except Exception as e:
    print(f"Error running CLI: {e}", file=sys.stderr)
    sys.exit(1)