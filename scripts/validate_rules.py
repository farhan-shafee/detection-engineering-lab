"""Compatibility entry point for the original repository command."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection_lab.__main__ import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["validate"]))
