from __future__ import annotations

import sys
from pathlib import Path


def find_repo(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / "legal_workbench").is_dir():
            return candidate
    raise RuntimeError("korean-legal-workbench 저장소를 찾지 못했습니다.")


repo = find_repo(Path(__file__).resolve())
sys.path.insert(0, str(repo))

from legal_workbench.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())

