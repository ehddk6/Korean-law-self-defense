#!/usr/bin/env python3
"""사용자가 직접 내려받은 공식 법원 양식을 로컬 미러에 등록한다.

이 스크립트는 네트워크 다운로드나 전자소송 제출을 수행하지 않는다.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from legal_workbench.court_forms import default_court_forms_home, register_court_form


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="공식 법원 양식의 사용자-다운로드 로컬 미러 등록")
    parser.add_argument("--source", type=Path, required=True, help="사용자가 직접 내려받은 공식 양식 파일")
    parser.add_argument("--form-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--official-url", required=True)
    parser.add_argument("--effective-from")
    parser.add_argument("--mirror-root", type=Path, default=default_court_forms_home())
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = register_court_form(
        args.source,
        form_id=args.form_id,
        title=args.title,
        version=args.version,
        official_url=args.official_url,
        effective_from=args.effective_from,
        mirror_root=args.mirror_root,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
