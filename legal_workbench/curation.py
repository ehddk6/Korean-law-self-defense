from __future__ import annotations

import html
import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from .evaluation import load_manifest
from .models import utc_now
from .security import atomic_json_write, redact_text, scan_residual_pii, sha256_file


BRIDGE = Path(__file__).resolve().parents[1] / "scripts" / "law-api-bridge.mjs"
MCP_VERSION = "4.7.4"

DOMAIN_QUERIES: dict[str, tuple[str, ...]] = {
    "civil-contract-tort": ("손해배상", "계약해제", "부당이득"),
    "insurance-consumer-damages": ("보험금", "소비자", "손해배상"),
    "real-estate-lease-registration": ("임대차", "소유권이전등기", "보증금"),
    "commercial-corporate-finance-trust": ("주주총회", "신탁", "대여금"),
    "criminal-investigation-procedure": ("사기", "횡령", "압수수색"),
    "family-inheritance-guardianship": ("이혼", "유류분", "상속재산분할"),
    "labor-industrial-accident-social-security": ("부당해고", "임금", "산업재해"),
    "administrative-constitutional-state-liability": ("처분취소", "국가배상", "행정처분"),
    "tax-customs": ("부과처분취소", "법인세", "관세"),
    "rehabilitation-bankruptcy-enforcement": ("개인회생", "파산", "강제집행"),
    "privacy-it-intellectual-property": ("개인정보", "저작권", "특허"),
    "immigration-education-health-regulation": ("난민불인정", "학교", "의료"),
}

DOMAIN_ADVERSE: dict[str, str] = {
    "civil-contract-tort": "채무불이행·불법행위 요건 또는 인과관계의 흠결",
    "insurance-consumer-damages": "면책사유·고지의무 위반 또는 손해액 다툼",
    "real-estate-lease-registration": "대항력·우선변제권·등기요건의 흠결",
    "commercial-corporate-finance-trust": "회사기관 결의·대표권·신탁재산 귀속의 반대 논리",
    "criminal-investigation-procedure": "구성요건 고의·위법수집증거·합리적 의심의 반대 논리",
    "family-inheritance-guardianship": "특별수익·기여분·신분관계 요건의 반대 논리",
    "labor-industrial-accident-social-security": "근로자성·해고사유·업무관련성의 반대 논리",
    "administrative-constitutional-state-liability": "처분성·원고적격·재량권 일탈남용의 반대 논리",
    "tax-customs": "과세요건·실질과세·입증책임의 반대 논리",
    "rehabilitation-bankruptcy-enforcement": "채권 확정·면책 제외·집행요건의 반대 논리",
    "privacy-it-intellectual-property": "적법한 처리근거·공정이용·권리범위의 반대 논리",
    "immigration-education-health-regulation": "재량·비례·절차상 하자의 반대 논리",
}


@dataclass(frozen=True)
class CollectionResult:
    completed: int
    skipped: int
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"completed": self.completed, "skipped": self.skipped, "errors": list(self.errors)}


def _bridge(command: str, payload: dict[str, Any], timeout: int = 45) -> dict[str, Any]:
    env = os.environ.copy()
    if not env.get("LAW_OC"):
        raise RuntimeError("LAW_OC 환경변수가 현재 프로세스에 없습니다. Codex를 다시 시작하거나 환경변수를 상속하십시오.")
    completed = subprocess.run(
        ["node", str(BRIDGE), command],
        input=json.dumps(payload, ensure_ascii=False),
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=timeout,
        env=env,
        check=False,
    )
    if completed.returncode:
        message = completed.stderr.strip() or "법제처 MCP bridge 실행 실패"
        raise RuntimeError(message.replace(env["LAW_OC"], "[LAW_OC]"))
    data = json.loads(completed.stdout)
    if not isinstance(data, dict):
        raise RuntimeError("법제처 MCP bridge가 JSON 객체를 반환하지 않았습니다.")
    return data


def collect_official_decisions(
    manifest_path: Path,
    *,
    workers: int = 4,
    replace: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    manifest_path = Path(manifest_path).resolve()
    manifest = load_manifest(manifest_path)
    root = manifest_path.parent
    targets = [item for item in manifest["scenarios"] if item["kind"] == "masked-official-decision"]
    if not replace:
        targets = [item for item in targets if item.get("curation_status") != "complete"]
    if limit is not None:
        targets = targets[: max(limit, 0)]
    by_domain: dict[str, list[dict[str, Any]]] = {}
    for item in targets:
        by_domain.setdefault(item["domain"], []).append(item)

    already_used = {
        str(item.get("source_id"))
        for item in manifest["scenarios"]
        if item.get("source_id") and item not in targets
    }
    already_used.update(
        str(source_id)
        for item in manifest["scenarios"]
        for source_id in (item.get("rejected_source_ids") or [])
    )
    assignments: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for domain, slots in by_domain.items():
        candidates: list[dict[str, Any]] = []
        seen: set[str] = set()
        for query in DOMAIN_QUERIES[domain]:
            for page in range(1, 7):
                result = _bridge(
                    "precedent-search",
                    {"query": query, "search": 1, "display": 40, "page": page},
                )
                for hit in result.get("hits") or []:
                    source_id = str(hit.get("id") or "")
                    # 국세법령정보시스템으로 우회되는 항목은 PrecService JSON이 없을 수 있으므로
                    # 법원명과 표준 사건번호가 함께 있는 법원 공개 판례만 잠금 평가에 사용한다.
                    if (
                        source_id
                        and hit.get("court")
                        and hit.get("caseNumber")
                        and source_id not in seen
                        and source_id not in already_used
                    ):
                        seen.add(source_id)
                        candidates.append(hit)
                if len(candidates) >= len(slots) * 2:
                    break
            if len(candidates) >= len(slots) * 2:
                break
        if len(candidates) < len(slots):
            raise RuntimeError(f"{domain}: 공식 판례 후보가 {len(candidates)}건뿐입니다.")
        for slot, hit in zip(slots, candidates, strict=False):
            assignments.append((slot, hit))
            already_used.add(str(hit["id"]))

    errors: list[str] = []
    completed = 0
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 6))) as executor:
        futures = {
            executor.submit(_bridge, "precedent-detail", {"id": str(hit["id"])}, 60): (slot, hit)
            for slot, hit in assignments
        }
        for future in as_completed(futures):
            slot, hit = futures[future]
            try:
                detail = future.result()
                _write_official_case(root, slot, detail)
                completed += 1
            except Exception as exc:  # collection continues and reports exact failed slot
                rejected = list(slot.get("rejected_source_ids") or [])
                rejected.append(str(hit.get("id") or ""))
                slot["rejected_source_ids"] = sorted(set(filter(None, rejected)))
                slot["curation_status"] = "pending-official-source"
                errors.append(f"{slot['scenario_id']}: {exc}")

    atomic_json_write(manifest_path, manifest)
    return CollectionResult(completed, len(targets) - completed, tuple(errors)).to_dict()


def refresh_cached_official_decisions(manifest_path: Path, scenario_ids: list[str]) -> dict[str, Any]:
    manifest_path = Path(manifest_path).resolve()
    manifest = load_manifest(manifest_path)
    root = manifest_path.parent
    by_id = {item["scenario_id"]: item for item in manifest["scenarios"]}
    if not scenario_ids:
        scenario_ids = [
            item["scenario_id"] for item in manifest["scenarios"]
            if item["kind"] == "masked-official-decision"
        ]
    refreshed: list[str] = []
    for scenario_id in scenario_ids:
        item = by_id.get(scenario_id)
        if not item or item.get("kind") != "masked-official-decision":
            raise ValueError(f"공식 판결 시나리오가 아닙니다: {scenario_id}")
        source_path = (root / str(item.get("source_path") or "")).resolve()
        if not source_path.is_relative_to(root) or not source_path.is_file():
            raise FileNotFoundError(f"공식 원문 캐시가 없습니다: {scenario_id}")
        detail = json.loads(source_path.read_text(encoding="utf-8"))
        _write_official_case(root, item, detail)
        item["gold_review_status"] = "pending"
        item.pop("gold_review_path", None)
        item.pop("gold_review_sha256", None)
        refreshed.append(scenario_id)
    atomic_json_write(manifest_path, manifest)
    return {"refreshed": refreshed}


def _write_official_case(root: Path, slot: dict[str, Any], detail: dict[str, Any]) -> None:
    required = ("id", "case_number", "source_url", "full_text")
    if any(not str(detail.get(key) or "").strip() for key in required):
        raise ValueError("사건번호·전문·공식 URL 중 누락된 값이 있습니다.")
    scenario_id = slot["scenario_id"]
    source_path = root / "sources" / "official-decisions" / f"{scenario_id}.json"
    fixture_path = root / "fixtures" / "official-decisions" / f"{scenario_id}.json"
    expected_path = root / "expected" / "official-decisions" / f"{scenario_id}.json"
    source = {
        "format": "legal-workbench-official-decision-source-v1",
        "retrieved_at": utc_now(),
        "mcp_server": "korean-law-mcp",
        "mcp_version": MCP_VERSION,
        "mcp_tool": "get_precedent_text",
        **detail,
    }
    atomic_json_write(source_path, source)
    source_hash = sha256_file(source_path)
    issues = _issue_gold(str(detail.get("issues") or ""), str(detail.get("holding_summary") or ""))
    masked_record = _masked_record(detail)
    if _fixture_label_leak(masked_record):
        raise ValueError("결론 표지어가 남아 blind fixture로 사용할 수 없습니다.")
    if len(masked_record) < 300:
        raise ValueError("결론 제거 후 사실 기록이 300자 미만이라 평가 입력으로 부족합니다.")
    outcome = _classify_outcome(str(detail.get("full_text") or ""))
    if outcome == "unknown":
        raise ValueError("공식 주문을 결정론적으로 분류하지 못했습니다.")
    fixture = {
        "format": "legal-workbench-masked-decision-input-v1",
        "scenario_id": scenario_id,
        "domain": slot["domain"],
        "as_of_date": _iso_ymd(str(detail.get("decision_date") or "")),
        "court_level": str(detail.get("court") or "미상"),
        "task": "결론이 제거된 기록으로 쟁점·불리한 논리·예상 결론과 판단 보류 여부를 분석하라.",
        "record": masked_record,
        "output_contract": {
            "decision_status": "ready|conditional|abstain",
            "outcome": "affirmed|reversed-remanded|dismissed|granted|mixed|unknown",
            "issues": "핵심 법률쟁점 문구 배열",
            "adverse_points": "반대 결론을 지지하는 중요 논리 배열",
        },
    }
    expected = {
        "format": "legal-workbench-masked-decision-expected-v1",
        "scenario_id": scenario_id,
        "decision_status": "conditional",
        "outcome": outcome,
        "expected_issues": issues,
        "expected_adverse_points": [_adverse_gold(slot["domain"], detail)],
        "official_case_number": detail["case_number"],
        "source_sha256": source_hash,
    }
    atomic_json_write(fixture_path, fixture)
    atomic_json_write(expected_path, expected)
    slot.update(
        {
            "source_url": detail["source_url"],
            "source_id": str(detail["id"]),
            "official_case_number": detail["case_number"],
            "source_path": source_path.relative_to(root).as_posix(),
            "source_sha256": source_hash,
            "fixture_path": fixture_path.relative_to(root).as_posix(),
            "fixture_sha256": sha256_file(fixture_path),
            "expected_path": expected_path.relative_to(root).as_posix(),
            "expected_sha256": sha256_file(expected_path),
            "curation_status": "complete",
            "curation_note": "공식 P1 원문에서 사건번호·판결요지·주문·직접 결론 문장을 제거한 잠금 입력",
        }
    )


def _fixture_label_leak(text: str) -> bool:
    return bool(
        re.search(
            r"(^\s*(?:【\s*)?주\s*문(?:\s*】)?\s*$|환송\s*후|파기\s*사유|파기의\s*범위|파기하여야\s*한다|"
            r"위법하다고\s*볼\s*수\s*없|(?:지급|배상|반환)할\s*의무가\s*(?:있|없)|"
            r"(?:원심(?:의)?\s*(?:판단|결론)|결론).{0,60}정당|그런데도\s*원심|"
            r"이를\s*지적하는.{0,40}(?:주장|상고이유).{0,20}정당|"
            r"^\s*\d*\.?\s*(?:소\s*)?결\s*론\s*$|"
            r"판결에\s*영향을\s*미친\s*잘못|원심.{0,120}(?:법리.{0,20}오해|수긍할\s*수\s*없))",
            text,
            flags=re.M,
        )
    )


def _clean(value: str) -> str:
    text = html.unescape(value or "")
    text = re.sub(r"<\s*br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"[ \t]+", " ", text).replace("\r", "").strip()


def _masked_record(detail: dict[str, Any]) -> str:
    text = _clean(str(detail.get("full_text") or ""))
    case_number = str(detail.get("case_number") or "")
    if case_number:
        text = text.replace(case_number, "[사건번호 비공개]")
    # 독립 blind 검토에서 확인된 공식 판례 본문 내 실명은 fixture에 남기지 않는다.
    text = text.replace("최계월", "[PERSON_001]")
    text = re.sub(r"【\s*주\s*문\s*】[\s\S]*?(?=【\s*(?:이\s*유|청\s*구\s*취\s*지)\s*】)", "", text)
    text = re.sub(r"(?im)^\s*(?:주\s*문|결\s*론)\s*$[\s\S]*?(?=^\s*(?:이\s*유|청\s*구\s*취\s*지|\d+\.)\s*$)", "", text)
    reason_match = re.search(r"【\s*이\s*유\s*】", text)
    if reason_match:
        text = text[reason_match.end() :]
    court = str(detail.get("court") or "")
    if "대법원" in court:
        text = _supreme_blind_context(text)
    else:
        facts_heading = re.search(
            r"(?im)^\s*(?:\d+\.?\s*)?(?:기초\s*사실|인정\s*사실|사건의\s*개요|전제\s*사실)\s*$",
            text,
        )
        if facts_heading:
            text = text[facts_heading.start() :]
            next_decision = re.search(
                r"(?im)^\s*(?:\d+\.?\s*)?.{0,40}(?:판단|소결론)\s*$",
                text[300:],
            )
            if next_decision:
                text = text[: 300 + next_decision.start()]
        else:
            target_heading = re.search(
                r"(?im)^\s*(?:\d+\.?\s*)?(?:이\s*법원의\s*판단|당심의\s*판단|법원의\s*판단)\s*$",
                text,
            )
            if target_heading and target_heading.start() >= 300:
                text = text[: target_heading.start()]
    # 복합 사건의 뒤쪽 쟁점까지 남겨야 전체 주문을 예측할 수 있다. 주문과 직접
    # 결론을 드러내는 문장만 제거하고 사실관계·원심 판단·법리는 보존한다.
    decisive = re.compile(
        r"(주문과 같이|파기(?:하고|한다|하여야|사유|의\s*범위|할\s*수)|환송(?:한다|하기로|\s*후)|"
        r"상고를 기각|청구를 기각|소를 각하|처분을 취소|이유 있(?:다|어)|이유 없(?:다|어)|"
        r"판결에\s*영향을\s*미친|원심.{0,160}(?:잘못|위법|수긍할\s*수|법리.{0,20}오해)|"
        r"받아들이기\s*어렵|받아들일\s*수\s*없|잘못이\s*(?:있|없)|"
        r"위법하다고\s*볼\s*수\s*없|(?:지급|배상|반환)할\s*의무가\s*(?:있|없)|"
        r"(?:원심(?:의)?\s*(?:판단|결론)|결론).{0,60}정당|그런데도\s*원심|"
        r"이를\s*지적하는.{0,40}(?:주장|상고이유).{0,20}정당|"
        r"따라서.{0,180}(?:청구|상고|항소|이혼|책임|의무).{0,100}(?:있|없|한다|기각|인용))"
    )
    paragraphs: list[str] = []
    total = 0
    for paragraph in re.split(r"\n{1,}", text):
        paragraph = paragraph.strip()
        if not paragraph:
            continue
        if re.fullmatch(r"(?:\d+\.?\s*)?(?:파기의\s*범위|결\s*론)", paragraph):
            break
        kept_sentences = []
        for sentence in re.split(r"(?<!\d)(?<=\.)\s+", paragraph):
            sentence = sentence.strip()
            if not sentence or decisive.search(sentence):
                continue
            kept_sentences.append(sentence)
        if kept_sentences:
            cleaned_paragraph = " ".join(kept_sentences)
            paragraphs.append(cleaned_paragraph)
            total += len(cleaned_paragraph)
        if total >= 12000:
            break
    masked = "\n".join(paragraphs)[:12000]
    if re.search(r"(?:19|20)\d{2}\.\s*\d{1,2}\.\s*$", masked):
        masked = masked.rsplit("\n", 1)[0]
    masked, _, _ = redact_text(masked)
    residual = scan_residual_pii(masked)
    if residual:
        raise ValueError(f"fixture 비식별 후 PII가 {len(residual)}건 남았습니다.")
    return masked or "공식 원문에서 결론을 제거한 뒤 분석 가능한 사실 부분이 부족함"


def _supreme_blind_context(text: str) -> str:
    # 대법원 판단부는 사건별 직접 결론을 포함하는 경우가 많다. 첫 사실관계 구획 뒤의
    # 다음 본문 항목부터는 제외해, 잠금 입력에는 분석 가능한 사실만 남긴다.
    next_main = re.search(r"(?m)^\s*2\.\s+", text[300:])
    if next_main:
        return text[: 300 + next_main.start()]

    target_heading = re.search(
        r"(?im)^\s*(?:(?:\d+|[가-하])\.?\s*)?(?:대법원의\s*판단|대법원\s*판단|상고이유.{0,30}에\s*관한\s*판단)\s*$",
        text,
    )
    if target_heading and target_heading.start() >= 300:
        return text[: target_heading.start()]

    overview = re.search(
        r"(?im)^\s*(?:1\.?\s*)?(?:이\s*사건|사건|사안).{0,18}(?:개요|경위|사실관계|쟁점)\s*$",
        text,
    )
    if overview:
        following = text[overview.end() :]
        next_main = re.search(r"(?m)^\s*[2-9]\.?\s+", following[300:])
        if next_main:
            return text[: overview.end() + 300 + next_main.start()]

    facts_intro = re.search(
        r"(?im)^\s*(?:(?:\d+|[가-하])\.?\s*)?원심(?:판결)?(?:의)?\s*이유와.{0,80}(?:다음|아래).{0,30}(?:사실|사정).{0,30}알\s*수\s*있다\.\s*$",
        text,
    )
    if facts_intro:
        following = text[facts_intro.end() :]
        next_analysis = re.search(r"(?m)^\s*(?:[다-하]|[2-9])\.?\s+", following[300:])
        if next_analysis:
            return text[facts_intro.start() : facts_intro.end() + 300 + next_analysis.start()]
    return text


def _iso_ymd(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 8:
        return f"{digits[:4]}-{digits[4:6]}-{digits[6:8]}"
    return value


def _classify_outcome(full_text: str) -> str:
    cleaned = _clean(full_text)
    match = re.search(r"【\s*주\s*문\s*】([\s\S]*?)(?=【)", cleaned)
    order = (match.group(1) if match else cleaned.split("이 유", 1)[0])[:2500]
    has_dismissal = bool(
        re.search(
            r"(?:나머지|그\s*밖의).{0,80}(?:기각|각하)|소송.{0,80}종료|"
            r"(?:원고|피고|신청인|피고인)(?:들)?의?\s*(?:상고|항소|항고)를\s*(?:모두\s*)?기각",
            order,
            flags=re.S,
        )
    )
    if re.search(r"(?:원고|신청인|청구인)(?:들)?의.{0,60}청구를\s*모두\s*기각", order, flags=re.S):
        return "dismissed"
    if re.search(r"파기.{0,80}환송", order, flags=re.S):
        return "mixed" if has_dismissal else "reversed-remanded"
    if "파기" in order:
        return "mixed"
    affirmative = bool(
        re.search(
            r"(지급하라|지급한다|이행하라|이행한다|명의개서|이혼한다|친권자|양육비|"
            r"처분을\s*취소|제1심판결을\s*취소|무죄|벌금\s*\d|징역\s*\d)",
            order,
        )
    )
    if affirmative:
        return "mixed" if (has_dismissal or "나머지" in order) else "granted"
    if "취소" in order and ("기각" in order or "각하" in order):
        return "mixed"
    if re.search(r"(?:상고|항소|재항고|항고)(?:를|를\s*모두|를\s*각각)?\s*기각", order):
        return "affirmed"
    if "각하" in order or re.search(r"(?:청구|소송|소)(?:를|를\s*모두)?\s*기각", order):
        return "dismissed"
    if "취소한다" in order or "인용한다" in order:
        return "granted"
    return "affirmed" if "상고" in order else "unknown"


def _issue_gold(issues_text: str, holding: str) -> list[str]:
    text = _clean(issues_text) or _clean(holding)
    chunks = re.split(r"(?:\[\d+\]|\n+|(?<=[?？다])\s+(?=[가-힣A-Z]))", text)
    result: list[str] = []
    for chunk in chunks:
        item = re.sub(r"\s+", " ", chunk).strip(" -·")
        if len(item) >= 12 and item not in result:
            result.append(item[:240])
        if len(result) == 5:
            break
    if not result:
        raise ValueError("판시사항·판결요지에서 issue gold를 추출할 수 없습니다.")
    return result


def _adverse_gold(domain: str, detail: dict[str, Any]) -> str:
    text = _clean(str(detail.get("full_text") or ""))
    match = re.search(r"(?:원고|피고|피고인|검사)의\s*주장\s*[:：]?\s*([^\n]{20,300})", text)
    if match:
        return match.group(1).strip()
    authority_text = _clean(
        "\n".join(
            [str(detail.get("holding_summary") or ""), str(detail.get("issues") or "")]
        )
    )
    sentences = [item.strip() for item in re.split(r"(?<=[.다?])\s+|\n+", authority_text) if len(item.strip()) >= 15]
    for sentence in sentences:
        if re.search(r"(다만|그러나|반면|예외|아니|없|제외|특별한\s*사정|요건)", sentence):
            return sentence[:300]
    if sentences:
        raise ValueError(f"{domain}: 공식 원문에 반대 논리·예외 문장이 없습니다.")
    raise ValueError(f"{domain}: 반대 논리 gold를 공식 원문에서 추출할 수 없습니다.")


TEMPORAL_SPECS: dict[str, tuple[dict[str, Any], ...]] = {
    "applicable-law": tuple(
        {
            "law": "행정기본법",
            "article": "제14조",
            "status": status,
            "rule_answer": "article-14-fact-dependent",
            "question": question,
            "facts": facts,
            "issue": "법령등의 시간적 적용 범위와 특별규정·신청처분·제재처분 예외",
        }
        for question, facts, status in (
            ("법 개정 전 시작해 개정 후 계속되는 법률관계에 어느 법이 적용되는가?", {"relation_continues_after_effective_date": True}, "conditional"),
            ("신청 후 처분 전에 법이 바뀐 신청처분에 어느 법이 적용되는가?", {"party_application": True, "law_changed_before_disposition": True}, "conditional"),
            ("신청처분에 신법 적용이 현저히 곤란한 사정이 있으면 어떻게 판단하는가?", {"party_application": True, "new_law_application_difficult": True}, "conditional"),
            ("위반행위 후 제재처분 전에 법이 바뀌면 어느 법을 기준으로 하는가?", {"sanction": True, "law_changed_after_violation": True}, "conditional"),
            ("위반 후 신법이 제재를 가볍게 바꾼 경우 예외까지 무엇을 확인해야 하는가?", {"sanction": True, "later_law_lighter": True}, "conditional"),
            ("시간적 적용에 관한 특별규정이 있다는 주장만 있고 원문이 없을 때 결론 가능한가?", {"special_rule_claimed_but_missing": True}, "abstain"),
        )
    ),
    "transitional-provision": tuple(
        {
            "law": law,
            "article": "부칙",
            "status": "abstain",
            "rule_answer": "verify-specific-addendum",
            "question": f"{law} 개정 전 사실에 개정법을 적용할 수 있는가?",
            "facts": {"amendment_date_known": False, "addendum_text_provided": False},
            "issue": "해당 개정법률 부칙의 시행일·적용례·경과조치 원문 확인",
        }
        for law in ("민법", "상법", "형법", "근로기준법", "국세기본법", "개인정보 보호법")
    ),
    "service": (
        {"law": "민사소송법", "article": "제178조", "status": "ready", "rule_answer": "personal-delivery-required", "question": "특별규정이 없을 때 서류 송달의 원칙은 무엇인가?", "facts": {"copy_delivered_to_recipient": True}, "issue": "등본·부본 교부송달 원칙"},
        {"law": "민사소송법", "article": "제183조", "status": "ready", "rule_answer": "address-or-workplace-service", "question": "주소·거소·영업소·사무소에서 한 송달의 장소 요건은 무엇인가?", "facts": {"place": "recipient_address"}, "issue": "송달장소와 근무장소 예외"},
        {"law": "민사소송법", "article": "제186조", "status": "abstain", "rule_answer": "substitute-service-needs-capable-recipient", "question": "부재중 동거인에게 교부한 보충송달이 유효한가?", "facts": {"recipient_absent": True, "delivered_to_housemate": True, "capacity_confirmed": False}, "issue": "보충송달 수령인의 사리분별 능력"},
        {"law": "민사소송법", "article": "제187조", "status": "conditional", "rule_answer": "postal-service-after-article-186-failure", "question": "보충·유치송달을 할 수 없을 때 우편송달 요건은 무엇인가?", "facts": {"article_186_service_impossible": True}, "issue": "우편송달의 선행요건과 법원사무관의 발송"},
        {"law": "민사소송법", "article": "제189조", "status": "ready", "rule_answer": "effective-upon-dispatch", "question": "제187조 우편송달은 언제 송달된 것으로 보는가?", "facts": {"sent_under_article_187": True, "dispatch_date": "2025-08-03"}, "issue": "발신주의에 따른 효력 발생 시점"},
        {"law": "민사소송법", "article": "제194조", "status": "ready", "rule_answer": "public-service-requires-statutory-ground", "question": "주소를 알 수 없다는 주장만으로 공시송달이 가능한가?", "facts": {"address_unknown_claimed": True, "supporting_evidence_provided": False}, "issue": "공시송달 요건과 사유 소명"},
    ),
    "limitation": (
        {"law": "민법", "article": "제162조", "supporting_articles": ["제157조", "제160조", "제166조"], "status": "ready", "rule_answer": "ten-year-ordinary-claim", "question": "일반 채권의 10년 소멸시효 만료일은 언제인가?", "facts": {"right_exercisable_date": "2026-04-10", "ordinary_claim": True, "interruption": False}, "issue": "일반 채권 10년 소멸시효와 기간 계산", "deadline_date": "2036-04-10"},
        {"law": "민법", "article": "제163조", "supporting_articles": ["제157조", "제160조", "제166조"], "status": "ready", "rule_answer": "three-year-interest-claim", "question": "1년 이내 정기 지급 이자의 소멸시효 만료일은 언제인가?", "facts": {"right_exercisable_date": "2026-05-10", "interest_due_within_one_year": True, "interruption": False}, "issue": "이자 등 3년 단기소멸시효와 기간 계산", "deadline_date": "2029-05-10"},
        {"law": "민법", "article": "제164조", "supporting_articles": ["제157조", "제160조", "제166조"], "status": "ready", "rule_answer": "one-year-lodging-claim", "question": "숙박료 채권의 소멸시효 만료일은 언제인가?", "facts": {"right_exercisable_date": "2026-06-10", "lodging_charge": True, "interruption": False}, "issue": "숙박료 등 1년 단기소멸시효와 기간 계산", "deadline_date": "2027-06-10"},
        {"law": "민법", "article": "제166조", "status": "abstain", "rule_answer": "starts-when-right-exercisable", "question": "계약일만 알고 권리행사 가능일을 모르면 시효 기산일을 확정할 수 있는가?", "facts": {"contract_date": "2025-04-10", "right_exercisable_date": None}, "issue": "권리를 행사할 수 있는 때라는 기산점", "deadline_date": None},
        {"law": "민법", "article": "제766조", "supporting_articles": ["제157조", "제160조"], "status": "ready", "rule_answer": "three-year-tort-knowledge-period", "question": "피해자와 가해자를 안 날 기준 불법행위 단기시효 만료일은 언제인가?", "facts": {"knowledge_date": "2026-04-10", "tort_date": "2026-04-01", "interruption": False}, "issue": "손해·가해자를 안 날부터 3년과 기간 계산", "deadline_date": "2029-04-10"},
        {"law": "민법", "article": "제766조", "status": "abstain", "rule_answer": "knowledge-date-required", "question": "불법행위일만 있고 손해와 가해자를 안 날이 없으면 단기시효를 확정할 수 있는가?", "facts": {"tort_date": "2025-06-01", "knowledge_date": None}, "issue": "주관적 기산점과 객관적 10년 기간의 구별", "deadline_date": None},
    ),
    "jurisdiction": (
        {"law": "민사소송법", "article": "제2조", "status": "conditional", "rule_answer": "defendant-general-forum", "question": "특별재판적 사실이 없을 때 기본 관할은 무엇인가?", "facts": {"defendant_general_forum_known": True}, "issue": "피고 보통재판적 법원의 기본 관할"},
        {"law": "민사소송법", "article": "제3조", "status": "ready", "rule_answer": "individual-address-forum", "question": "대한민국 내 개인 피고의 보통재판적 기준은 무엇인가?", "facts": {"defendant_type": "individual", "address_known": True}, "issue": "사람의 주소에 따른 보통재판적"},
        {"law": "민사소송법", "article": "제8조", "status": "ready", "rule_answer": "place-of-performance-special-forum", "question": "재산권 청구를 의무이행지 법원에 제기할 수 있는가?", "facts": {"property_claim": True, "place_of_performance_known": True}, "issue": "거소지·의무이행지 특별재판적"},
        {"law": "민사소송법", "article": "제18조", "status": "ready", "rule_answer": "tort-place-special-forum", "question": "불법행위지 법원에 손해배상소송을 제기할 수 있는가?", "facts": {"tort_claim": True, "tort_place_known": True}, "issue": "불법행위지 특별재판적"},
        {"law": "민사소송법", "article": "제20조", "status": "ready", "rule_answer": "real-estate-location-special-forum", "question": "부동산 소재지 법원에 부동산 관련 소를 제기할 수 있는가?", "facts": {"real_estate_claim": True, "property_location_known": True}, "issue": "부동산 소재지 특별재판적"},
        {"law": "민사소송법", "article": "제24조", "status": "conditional", "rule_answer": "ip-special-forum-subject-to-statute", "question": "지식재산권 소송의 특별재판적을 판단하려면 무엇을 확인해야 하는가?", "facts": {"intellectual_property_claim": True, "specific_court_facts_complete": False}, "issue": "지식재산권 특별재판적과 전속관할 확인"},
    ),
}


def collect_temporal_rules(manifest_path: Path, *, replace: bool = False) -> dict[str, Any]:
    manifest_path = Path(manifest_path).resolve()
    manifest = load_manifest(manifest_path)
    root = manifest_path.parent
    targets = [item for item in manifest["scenarios"] if item["kind"] in TEMPORAL_SPECS]
    completed = 0
    law_cache: dict[str, dict[str, Any]] = {}
    seen_by_kind: dict[str, int] = {kind: 0 for kind in TEMPORAL_SPECS}
    for item in targets:
        spec_index = seen_by_kind[item["kind"]]
        seen_by_kind[item["kind"]] += 1
        if item.get("curation_status") == "complete" and not replace:
            continue
        spec = TEMPORAL_SPECS[item["kind"]][spec_index]
        law_name = str(spec["law"])
        if law_name not in law_cache:
            search = _bridge("law-search", {"query": law_name, "max": 10})
            exact = next((law for law in search.get("laws", []) if law.get("lawName") == law_name), None)
            if not exact:
                raise RuntimeError(f"공식 법령을 찾지 못했습니다: {law_name}")
            law_cache[law_name] = _bridge("law-detail", {"mst": exact["mst"]}, 60)
        detail = law_cache[law_name]
        _write_temporal_case(root, item, detail, spec)
        completed += 1
    atomic_json_write(manifest_path, manifest)
    return {"completed": completed, "skipped": len(targets) - completed}


def refresh_cached_temporal_rules(manifest_path: Path, scenario_ids: list[str]) -> dict[str, Any]:
    manifest_path = Path(manifest_path).resolve()
    manifest = load_manifest(manifest_path)
    root = manifest_path.parent
    wanted = set(scenario_ids) or {
        item["scenario_id"] for item in manifest["scenarios"] if item["kind"] in TEMPORAL_SPECS
    }
    seen_by_kind: dict[str, int] = {kind: 0 for kind in TEMPORAL_SPECS}
    refreshed: list[str] = []
    for item in manifest["scenarios"]:
        if item["kind"] not in TEMPORAL_SPECS:
            continue
        index = seen_by_kind[item["kind"]]
        seen_by_kind[item["kind"]] += 1
        if item["scenario_id"] not in wanted:
            continue
        source_path = (root / str(item.get("source_path") or "")).resolve()
        if not source_path.is_relative_to(root) or not source_path.is_file():
            raise FileNotFoundError(f"공식 규정 캐시가 없습니다: {item['scenario_id']}")
        cached = json.loads(source_path.read_text(encoding="utf-8"))
        _write_temporal_case(root, item, cached, TEMPORAL_SPECS[item["kind"]][index])
        item["gold_review_status"] = "pending"
        item.pop("gold_review_path", None)
        item.pop("gold_review_sha256", None)
        refreshed.append(item["scenario_id"])
    if set(refreshed) != wanted:
        raise ValueError(f"temporal 시나리오를 찾지 못했습니다: {sorted(wanted-set(refreshed))}")
    atomic_json_write(manifest_path, manifest)
    return {"refreshed": refreshed}


def _write_temporal_case(
    root: Path,
    item: dict[str, Any],
    law_detail: dict[str, Any],
    spec: dict[str, Any],
) -> None:
    scenario_id = item["scenario_id"]
    source_path = root / "sources" / "official-rules" / f"{scenario_id}.json"
    fixture_path = root / "fixtures" / "temporal" / f"{scenario_id}.json"
    expected_path = root / "expected" / "temporal" / f"{scenario_id}.json"
    article = str(spec["article"])
    selected_article = _selected_article(law_detail.get("payload"), article)
    if article != "부칙" and not selected_article:
        raise ValueError(f"공식 법령 원문에서 {spec['law']} {article}를 찾지 못했습니다.")
    supporting_articles = {
        supporting: _selected_article(law_detail.get("payload"), supporting)
        for supporting in spec.get("supporting_articles", [])
    }
    if any(value is None for value in supporting_articles.values()):
        raise ValueError(f"공식 법령 원문에서 보조 조문을 찾지 못했습니다: {list(supporting_articles)}")
    source = {
        "format": "legal-workbench-official-rule-source-v1",
        "retrieved_at": utc_now(),
        "mcp_server": "korean-law-mcp",
        "mcp_version": MCP_VERSION,
        "mcp_tool": "get_law_text",
        "law_name": spec["law"],
        "article": article,
        "selected_article": selected_article,
        "supporting_articles": supporting_articles,
        **law_detail,
    }
    atomic_json_write(source_path, source)
    article_text = _flatten_article(selected_article) if selected_article else ""
    if supporting_articles:
        article_text += "\n" + "\n".join(_flatten_article(value) for value in supporting_articles.values())
    article_text, _, article_redactions = redact_text(article_text)
    fixture = {
        "format": "legal-workbench-temporal-input-v1",
        "scenario_id": scenario_id,
        "kind": item["kind"],
        "domain": item["domain"],
        "official_rule": {
            "law_name": spec["law"],
            "article": article,
            "article_text": article_text or None,
            "local_redaction_categories": sorted({finding.category for finding in article_redactions}),
        },
        "facts": spec["facts"],
        "question": spec["question"],
        "task": "제시된 공식 조문과 사실만으로 판단하고 필요한 사실·특별규정이 빠졌으면 보류하라.",
        "answer_contract": {
            "rule_answer": "아래 선택지 중 하나",
            "rule_answer_options": sorted(
                {
                    entry["rule_answer"]
                    for entries in TEMPORAL_SPECS.values()
                    for entry in entries
                }
            ),
            "decision_status": "ready|conditional|abstain",
            "deadline_date": "계산 가능한 경우 YYYY-MM-DD, 아니면 null",
        },
    }
    expected = {
        "format": "legal-workbench-temporal-expected-v1",
        "scenario_id": scenario_id,
        "decision_status": spec["status"],
        "rule_answer": spec["rule_answer"],
        "expected_issues": [spec["issue"]],
        "expected_adverse_points": ["특별규정·예외요건·기산점 또는 관할 사실의 누락이 결론을 바꿀 수 있음"],
        "source_sha256": sha256_file(source_path),
    }
    if "deadline_date" in spec:
        expected["deadline_date"] = spec["deadline_date"]
    atomic_json_write(fixture_path, fixture)
    atomic_json_write(expected_path, expected)
    item.update(
        {
            "source_url": law_detail["source_url"],
            "official_case_number": None,
            "source_path": source_path.relative_to(root).as_posix(),
            "source_sha256": sha256_file(source_path),
            "fixture_path": fixture_path.relative_to(root).as_posix(),
            "fixture_sha256": sha256_file(fixture_path),
            "expected_path": expected_path.relative_to(root).as_posix(),
            "expected_sha256": sha256_file(expected_path),
            "curation_status": "complete",
            "curation_note": "공식 법령 원문과 결정론적 날짜·절차 사실로 구성",
        }
    )


def _selected_article(payload: Any, article: str) -> dict[str, Any] | None:
    match = re.search(r"\d+", article)
    if not match:
        return None
    number = str(int(match.group(0)))

    def visit(value: Any) -> dict[str, Any] | None:
        if isinstance(value, dict):
            if str(value.get("조문번호") or "") == number and value.get("조문제목"):
                return value
            for child in value.values():
                found = visit(child)
                if found:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = visit(child)
                if found:
                    return found
        return None

    return visit(payload)


def _flatten_article(article: dict[str, Any] | None) -> str:
    if not article:
        return ""
    values: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
        elif isinstance(value, dict):
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(article)
    return "\n".join(dict.fromkeys(values))[:6000]
