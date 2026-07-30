from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(slots=True)
class SecurityFinding:
    category: str
    matched_text: str
    start: int
    end: int
    rule: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PII_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "RESIDENT_ID",
        "resident-registration-number",
        re.compile(r"(?<!\d)\d{6}\s*[- ]?\s*[1-8]\d{6}(?!\d)"),
    ),
    (
        "PHONE",
        "mobile-or-landline-number",
        re.compile(r"(?<!\d)(?:01[016789]|0[2-6][1-5]?)\s*[-.) ]?\s*\d{3,4}\s*[- ]?\s*\d{4}(?!\d)"),
    ),
    (
        "EMAIL",
        "email-address",
        re.compile(r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![A-Z0-9.-])"),
    ),
    (
        "BIRTH_DATE",
        "birth-date-with-birth-marker",
        re.compile(
            r"(?<!\d)(?:(?:19|20)\d{2}\s*년생|"
            r"(?:19|20)\d{2}\s*[.년-]\s*\d{1,2}\s*[.월-]\s*\d{1,2}\s*\.?(?=.{0,30}출생)|"
            r"(?:19|20)\d{2}\s*[.년-]\s*\d{1,2}\s*[.월-]\s*\d{1,2}\s*\.?\s*(?:일\s*)?생)"
        ),
    ),
    (
        "CASE_NUMBER",
        "korean-case-number",
        re.compile(
            r"(?<!\d)(?:19|20)\d{2}\s*"
            r"(?:가단|가합|가소|나|다|도|노|고단|고합|고정|형제|형상|카단|카합|카기|카명|"
            r"타채|타경|타인|즈단|즈합|드단|드합|르|므|브|스|아|재노|재도|재다|누|두|"
            r"구단|구합|헌가|헌나|헌다|헌라|헌마|헌바|헌사|헌아)\s*\d{1,10}(?!\d)"
        ),
    ),
    (
        "ACCOUNT",
        "probable-account-number",
        re.compile(r"(?<!\d)(?:\d{2,6}[- ]?){2,4}\d{2,6}(?!\d)"),
    ),
    (
        "ADDRESS",
        "probable-korean-address",
        re.compile(
            r"(?:(?:서울특별시|부산광역시|대구광역시|인천광역시|광주광역시|대전광역시|"
            r"울산광역시|세종특별자치시|[가-힣]{2,}(?:특별자치도|도))\s+)?"
            r"[가-힣]{1,}(?:시|군|구)\s+[가-힣0-9·.-]{2,}(?:로|길|동|읍|면|리)"
            r"\s+\d{1,5}(?:-\d{1,5})?(?!\d)"
        ),
    ),
)


INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "override-instructions",
        re.compile(
            r"(?i)(?:ignore|disregard|override|forget).{0,40}(?:instruction|prompt|policy|rule)"
        ),
    ),
    (
        "korean-override-instructions",
        re.compile(r"(?:이전|위의|기존).{0,20}(?:지시|규칙|명령).{0,20}(?:무시|잊|폐기)"),
    ),
    (
        "role-escalation",
        re.compile(r"(?i)(?:system prompt|developer message|you are now|act as root|sudo|관리자 권한)"),
    ),
    (
        "tool-execution-request",
        re.compile(
            r"(?i)(?:(?:run|execute|invoke|호출|실행).{0,30}(?:powershell|cmd\.exe|bash|python|tool|도구|명령)"
            r"|(?:powershell|cmd\.exe|bash|python|tool|도구|명령).{0,30}(?:run|execute|invoke|호출|실행))"
        ),
    ),
    (
        "secret-exfiltration",
        re.compile(r"(?i)(?:reveal|print|send|upload|노출|출력|전송).{0,30}(?:secret|token|key|password|비밀|인증키)"),
    ),
)

SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9가-힣][A-Za-z0-9가-힣._-]{0,79}$")
WINDOWS_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def validate_safe_identifier(value: str, *, field: str) -> str:
    candidate = str(value).strip()
    if not SAFE_IDENTIFIER_PATTERN.fullmatch(candidate) or ".." in candidate:
        raise ValueError(f"{field}는 1~80자의 한글·영문·숫자·점·밑줄·하이픈만 사용할 수 있습니다.")
    if candidate.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
        raise ValueError(f"{field}에 Windows 예약 이름을 사용할 수 없습니다.")
    return candidate


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_within(path: Path, parent: Path) -> bool:
    try:
        Path(path).resolve().relative_to(Path(parent).resolve())
        return True
    except ValueError:
        return False


def onedrive_roots() -> list[Path]:
    roots: list[Path] = []
    for name in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value).expanduser().resolve())
    fallback = Path.home() / "OneDrive"
    if fallback.exists():
        roots.append(fallback.resolve())
    unique: list[Path] = []
    for root in roots:
        if root not in unique:
            unique.append(root)
    return unique


def path_is_synced(path: Path) -> bool:
    return any(is_within(path, root) for root in onedrive_roots())


def _next_token(category: str, mapping: dict[str, str]) -> str:
    prefix = category.upper().replace("-", "_")
    used = [token for token in mapping.values() if token.startswith(f"[{prefix}_")]
    return f"[{prefix}_{len(used) + 1:03d}]"


def redact_text(
    text: str,
    *,
    existing_mapping: dict[str, str] | None = None,
    custom_entities: dict[str, Iterable[str]] | None = None,
) -> tuple[str, dict[str, str], list[SecurityFinding]]:
    mapping = dict(existing_mapping or {})
    findings: list[SecurityFinding] = []
    replacements: list[tuple[int, int, str, str, str]] = []
    for category, values in (custom_entities or {}).items():
        for value in sorted({str(item) for item in values if str(item)}, key=len, reverse=True):
            for match in re.finditer(re.escape(value), text):
                token = mapping.setdefault(value, _next_token(category, mapping))
                replacements.append((match.start(), match.end(), token, category, "custom-entity"))
    for category, rule, pattern in PII_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if category == "ACCOUNT" and re.fullmatch(r"(?:19|20)\d{2}-\d{2}-\d{2}", value.strip()):
                continue
            token = mapping.setdefault(value, _next_token(category, mapping))
            replacements.append((match.start(), match.end(), token, category, rule))
    replacements.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    accepted: list[tuple[int, int, str, str, str]] = []
    last_end = -1
    for item in replacements:
        if item[0] < last_end:
            continue
        accepted.append(item)
        last_end = item[1]
    output: list[str] = []
    cursor = 0
    for start, end, token, category, rule in accepted:
        output.append(text[cursor:start])
        output.append(token)
        findings.append(SecurityFinding(category, "<redacted>", start, end, rule))
        cursor = end
    output.append(text[cursor:])
    return "".join(output), mapping, findings


def scan_residual_pii(text: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for category, rule, pattern in PII_PATTERNS:
        for match in pattern.finditer(text):
            if category == "ACCOUNT" and re.fullmatch(
                r"(?:19|20)\d{2}-\d{2}-\d{2}", match.group(0).strip()
            ):
                continue
            findings.append(
                SecurityFinding(category, "<redacted-in-report>", match.start(), match.end(), rule)
            )
    return findings


def scan_prompt_injection(text: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for rule, pattern in INJECTION_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                SecurityFinding(
                    "PROMPT_INJECTION",
                    "<instruction-like-text>",
                    match.start(),
                    match.end(),
                    rule,
                )
            )
    return findings


def rehydrate_text(text: str, mapping: dict[str, str]) -> str:
    reverse = sorted(((token, original) for original, token in mapping.items()), key=lambda item: -len(item[0]))
    restored = text
    for token, original in reverse:
        restored = restored.replace(token, original)
    return restored


def load_mapping(path: Path) -> dict[str, str]:
    if not Path(path).exists():
        return {}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("format") != "legal-workbench-redaction-map-v1":
        raise ValueError("지원하지 않는 비식별 매핑 형식입니다.")
    mapping = payload.get("mapping")
    if not isinstance(mapping, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in mapping.items()
    ):
        raise ValueError("비식별 매핑이 손상되었습니다.")
    return mapping


def save_mapping(path: Path, mapping: dict[str, str], *, case_id: str) -> None:
    payload = {
        "format": "legal-workbench-redaction-map-v1",
        "case_id": case_id,
        "mapping": mapping,
    }
    atomic_json_write(path, payload)


def atomic_json_write(path: Path, payload: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
