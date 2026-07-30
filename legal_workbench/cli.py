from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .documents import rehydrate_document
from .evaluation import (
    approve_gold_reviews,
    create_evaluation_v2,
    curate_scenario,
    manifest_status,
    refresh_adversarial_corpus,
    reset_v2_gold_cycle,
    score_results,
    seal_manifest_integrity,
    write_manifest,
)
from .consultation import consultation_status, finish_consultation, start_consultation
from .curation import (
    collect_official_decisions,
    collect_temporal_rules,
    refresh_cached_official_decisions,
    refresh_cached_temporal_rules,
)
from .evaluation_runner import run_evaluation, run_probe, shadow_policy_report, summarize_probe_results
from .gold_review_runner import run_gold_review
from .gold_distill_runner import apply_gold_distillations, run_gold_distillation
from .models import RiskLevel
from .services import build_service_bundle, list_services
from .security import load_mapping
from .workflow import (
    DOMAIN_PACKS,
    add_authority,
    add_deadline,
    add_fact,
    add_issue,
    build_analysis_bundles,
    build_research_bundle,
    complete_research,
    default_mapping_home,
    default_worksets_home,
    draft_case,
    export_case,
    import_opinion,
    ingest_document,
    import_analysis_result,
    import_visual_review,
    intake_case,
    mapping_path_for,
    run_audit,
    store_for,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="legal",
        description="한국법 자가소송 워크벤치 - 비식별, 근거 추적, 판단 보류와 배포 게이트",
    )
    parser.add_argument("--mapping-home", type=Path, default=default_mapping_home())
    parser.add_argument("--worksets-home", type=Path, default=default_worksets_home())
    subparsers = parser.add_subparsers(dest="command", required=True)

    intake = subparsers.add_parser("intake", help="사건 접수")
    intake.add_argument("--case", required=True)
    intake.add_argument("--title", required=True)
    intake.add_argument("--domain", choices=DOMAIN_PACKS, required=True)
    intake.add_argument("--goal", required=True)
    intake.add_argument("--forum")
    intake.add_argument("--action-date")
    intake.add_argument("--as-of-date")
    intake.add_argument("--risk", choices=[item.value for item in RiskLevel], default="routine")

    ingest = subparsers.add_parser("ingest", help="로컬 원본을 추출·비식별")
    ingest.add_argument("--case", required=True)
    ingest.add_argument("--source", type=Path, required=True)
    ingest.add_argument("--provenance", required=True)
    ingest.add_argument("--acquired-at", required=True, help="YYYY-MM-DD")
    ingest.add_argument("--entities", type=Path, required=True, help="이름·기관명 등 사용자 지정 비식별 JSON")

    fact = subparsers.add_parser("fact", help="사실 레코드 추가")
    fact.add_argument("--case", required=True)
    fact.add_argument("--file", type=Path, required=True)

    authority = subparsers.add_parser("authority", help="법적 근거 레코드 추가")
    authority.add_argument("--case", required=True)
    authority.add_argument("--file", type=Path, required=True)

    issue = subparsers.add_parser("issue", help="쟁점 레코드 추가")
    issue.add_argument("--case", required=True)
    issue.add_argument("--file", type=Path, required=True)

    deadline = subparsers.add_parser("deadline", help="기한 레코드 추가")
    deadline.add_argument("--case", required=True)
    deadline.add_argument("--file", type=Path, required=True)

    research = subparsers.add_parser("research", help="법률조사 입력 묶음 고정")
    research.add_argument("--case", required=True)
    research.add_argument("--complete", action="store_true", help="공식 근거·행위시법·양측 근거 검증 후 조사 완료")

    analyze = subparsers.add_parser("analyze", help="분석 묶음 생성 또는 의견 가져오기")
    analyze.add_argument("--case", required=True)
    analyze.add_argument("--opinion", type=Path, help="1차·독립 분석을 결합한 OpinionRecord JSON")
    analyze.add_argument("--result", type=Path, help="1차 또는 독립 분석 결과 JSON")
    analyze.add_argument("--role", choices=["primary", "independent"], help="--result의 분석 역할")

    draft = subparsers.add_parser("draft", help="서면 초안 생성")
    draft.add_argument("--case", required=True)
    draft.add_argument("--type", required=True, dest="document_type")
    draft.add_argument("--format", action="append", choices=["md", "docx", "pdf", "hwpx"], default=[])

    visual_review = subparsers.add_parser("visual-review", help="렌더 이미지와 문서 해시를 시각검토 기록으로 고정")
    visual_review.add_argument("--case", required=True)
    visual_review.add_argument("--file", type=Path, required=True)

    audit = subparsers.add_parser("audit", help="결정론적 최종 감사")
    audit.add_argument("--case", required=True)

    export = subparsers.add_parser("export", help="감사 통과 패키지 배포")
    export.add_argument("--case", required=True)

    rehydrate = subparsers.add_parser("rehydrate", help="로컬 대응표로 비식별 토큰을 실명으로 복원")
    rehydrate.add_argument("--case", required=True)
    rehydrate.add_argument("--source", type=Path, required=True)
    rehydrate.add_argument("--name", required=True, help="복원본 파일명")

    status = subparsers.add_parser("status", help="사건 상태와 감사 게이트 조회")
    status.add_argument("--case", required=True)

    consult = subparsers.add_parser("consult", help="공식 근거 기반 한국법 상담")
    consult_sub = consult.add_subparsers(dest="consult_command", required=True)
    consult_start = consult_sub.add_parser("start", help="비식별 상담 접수와 조사 묶음 생성")
    consult_start.add_argument("--file", type=Path, required=True)
    consult_start.add_argument("--id")
    consult_start.add_argument("--entities", type=Path)
    consult_start.add_argument("--dry-run", action="store_true", help="파일 저장 없이 비식별·질문 게이트 검증")
    consult_finish = consult_sub.add_parser("finish", help="상담 결과 검증·저장")
    consult_finish.add_argument("--id", required=True)
    consult_finish.add_argument("--result", type=Path, required=True)
    consult_status_parser = consult_sub.add_parser("status", help="상담 상태 조회")
    consult_status_parser.add_argument("--id", required=True)

    service = subparsers.add_parser("service", help="변호사 업무 전 과정 묶음")
    service_sub = service.add_subparsers(dest="service_command", required=True)
    service_sub.add_parser("list", help="지원하는 변호사 업무 목록")
    service_plan = service_sub.add_parser("plan", help="사건자료 기반 업무 묶음 생성")
    service_plan.add_argument("--case", required=True)
    service_plan.add_argument("--type", required=True, dest="service_type")

    evaluation = subparsers.add_parser("eval", help="180건 잠금 평가셋 관리")
    eval_sub = evaluation.add_subparsers(dest="eval_command", required=True)
    eval_bootstrap = eval_sub.add_parser("bootstrap", help="180건 manifest 생성")
    eval_bootstrap.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_bootstrap.add_argument("--replace", action="store_true")
    eval_init_v2 = eval_sub.add_parser("init-v2", help="기존 봉인 코퍼스를 결과 없이 evaluation v2로 복제")
    eval_init_v2.add_argument("--source-manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_init_v2.add_argument("--destination", type=Path, default=Path("evaluation/v2"))
    eval_init_v2.add_argument("--replace", action="store_true")
    eval_reset_v2 = eval_sub.add_parser("reset-v2-gold", help="v2에서 상속된 v1 gold 승인을 제거")
    eval_reset_v2.add_argument("--manifest", type=Path, default=Path("evaluation/v2/manifest.json"))
    eval_status = eval_sub.add_parser("status", help="평가셋 완성도 확인")
    eval_status.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_curate = eval_sub.add_parser("curate", help="공식 원문과 잠금 fixture를 평가 슬롯에 연결")
    eval_curate.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_curate.add_argument("--scenario", required=True)
    eval_curate.add_argument("--record", type=Path, required=True)
    eval_collect = eval_sub.add_parser("collect", help="공식 판례 120건과 공식 규정 30건 수집")
    eval_collect.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_collect.add_argument("--part", choices=("all", "decisions", "temporal"), default="all")
    eval_collect.add_argument("--workers", type=int, default=4)
    eval_collect.add_argument("--replace", action="store_true")
    eval_collect.add_argument("--limit", type=int)
    eval_run = eval_sub.add_parser("run", help="격리된 Codex로 180건을 동일 설정 3회 실행")
    eval_run.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_run.add_argument("--runs", type=int, default=3)
    eval_run.add_argument("--batch-size", type=int, default=12)
    eval_run.add_argument("--model", default="gpt-5.6-terra")
    eval_run.add_argument("--output-dir", type=Path)
    eval_run.add_argument("--no-resume", action="store_true")
    eval_run.add_argument("--limit", type=int, help="smoke test용 앞쪽 시나리오 제한")
    eval_probe = eval_sub.add_parser("probe", help="development만 종류별 표본으로 실행하는 비인증 평가")
    eval_probe.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_probe.add_argument("--per-kind", type=int, default=2)
    eval_probe.add_argument("--runs", type=int, default=1)
    eval_probe.add_argument("--batch-size", type=int, default=6)
    eval_probe.add_argument("--model", default="gpt-5.6-terra")
    eval_probe.add_argument("--output-dir", type=Path, required=True)
    eval_probe.add_argument("--no-resume", action="store_true")
    eval_probe_score = eval_sub.add_parser("probe-report", help="개발 probe를 비인증 지표로 요약")
    eval_probe_score.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_probe_score.add_argument("--results", type=Path, required=True)
    eval_probe_score.add_argument("--output", type=Path, required=True)
    eval_shadow = eval_sub.add_parser("shadow-policy", help="기존 결과에 현재 정책을 비인증 방식으로 투영")
    eval_shadow.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_shadow.add_argument("--results", type=Path, required=True)
    eval_shadow.add_argument("--output", type=Path, required=True)
    eval_seal = eval_sub.add_parser("seal", help="평가 source·fixture·expected 해시 봉인")
    eval_seal.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_approve = eval_sub.add_parser("approve-gold", help="독립 gold review 보고서 승인")
    eval_approve.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_approve.add_argument("--report", type=Path, action="append", required=True)
    eval_review = eval_sub.add_parser("review-gold", help="평가 모델과 분리된 Codex로 gold 구간 독립 검토")
    eval_review.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_review.add_argument("--start", type=int, required=True)
    eval_review.add_argument("--end", type=int, required=True)
    eval_review.add_argument("--reviewer-id", required=True)
    eval_review.add_argument("--model", default="gpt-5.6-sol")
    eval_review.add_argument("--output", type=Path, required=True)
    eval_distill = eval_sub.add_parser("distill-gold", help="fixture 근거만으로 판례 쟁점·반론 gold를 독립 증류")
    eval_distill.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_distill.add_argument("--start", type=int, required=True)
    eval_distill.add_argument("--end", type=int, required=True)
    eval_distill.add_argument("--model", default="gpt-5.6-sol")
    eval_distill.add_argument("--output", type=Path, required=True)
    eval_apply_distill = eval_sub.add_parser("apply-distilled-gold", help="120건 독립 증류 보고서를 expected gold에 적용")
    eval_apply_distill.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_apply_distill.add_argument("--report", type=Path, action="append", required=True)
    eval_refresh = eval_sub.add_parser("refresh-official", help="캐시된 공식 판결에서 선택 시나리오 gold 재생성")
    eval_refresh.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_refresh.add_argument("--scenario", action="append", default=[])
    eval_refresh.add_argument("--all", action="store_true", help="캐시된 공식 판결 120건 전체 재생성")
    eval_refresh_temporal = eval_sub.add_parser("refresh-temporal", help="캐시된 공식 규정에서 선택 temporal gold 재생성")
    eval_refresh_temporal.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_refresh_temporal.add_argument("--scenario", action="append", default=[])
    eval_refresh_temporal.add_argument("--all", action="store_true", help="캐시된 공식 규정 30건 전체 재생성")
    eval_refresh_adversarial = eval_sub.add_parser("refresh-adversarial", help="합성 공격 30건을 현재 규칙으로 재생성")
    eval_refresh_adversarial.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_score = eval_sub.add_parser("score", help="3회 실행 결과 합격 기준 채점")
    eval_score.add_argument("--manifest", type=Path, default=Path("evaluation/manifest.json"))
    eval_score.add_argument("--results", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        payload = dispatch(args)
    except (ValueError, KeyError, FileNotFoundError, FileExistsError, PermissionError, RuntimeError) as exc:
        print_json({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        return 2
    print_json({"ok": True, "result": payload})
    return 0


def dispatch(args: argparse.Namespace) -> Any:
    worksets = args.worksets_home.expanduser().resolve()
    mapping_home = args.mapping_home.expanduser().resolve()
    if args.command == "intake":
        record = intake_case(
            case_id=args.case,
            title=args.title,
            domain=args.domain,
            goal=args.goal,
            forum=args.forum,
            action_date=args.action_date,
            as_of_date=args.as_of_date,
            risk_level=RiskLevel(args.risk),
            worksets_home=worksets,
        )
        return record.to_dict()
    if args.command == "ingest":
        return ingest_document(
            case_id=args.case,
            source=args.source,
            provenance=args.provenance,
            acquired_at=args.acquired_at,
            entities_file=args.entities,
            mapping_home=mapping_home,
            worksets_home=worksets,
        )
    if args.command in {"fact", "authority", "issue", "deadline"}:
        payload = load_json(args.file)
        function = {
            "fact": add_fact,
            "authority": add_authority,
            "issue": add_issue,
            "deadline": add_deadline,
        }[args.command]
        return function(args.case, payload, worksets_home=worksets).to_dict()
    if args.command == "research":
        if args.complete:
            return complete_research(args.case, worksets_home=worksets)
        return {"bundle": str(build_research_bundle(args.case, worksets_home=worksets))}
    if args.command == "analyze":
        if args.opinion:
            return import_opinion(args.case, load_json(args.opinion), worksets_home=worksets).to_dict()
        if args.result:
            if not args.role:
                raise ValueError("--result에는 --role primary|independent가 필요합니다.")
            return import_analysis_result(args.case, args.role, load_json(args.result), worksets_home=worksets)
        if args.role:
            raise ValueError("--role은 --result와 함께 사용해야 합니다.")
        return {key: str(value) for key, value in build_analysis_bundles(args.case, worksets_home=worksets).items()}
    if args.command == "draft":
        formats = args.format or ["md"]
        return {
            key: str(value)
            for key, value in draft_case(
                args.case,
                document_type=args.document_type,
                formats=formats,
                worksets_home=worksets,
            ).items()
        }
    if args.command == "visual-review":
        return import_visual_review(args.case, load_json(args.file), worksets_home=worksets)
    if args.command == "audit":
        return run_audit(args.case, worksets_home=worksets)
    if args.command == "export":
        return {"export_dir": str(export_case(args.case, worksets_home=worksets))}
    if args.command == "rehydrate":
        source = args.source.expanduser().resolve()
        if not source.is_file() or worksets not in source.parents:
            raise PermissionError("복원 입력은 비식별 LegalWorksets 안에 있어야 합니다.")
        mapping_path = mapping_path_for(args.case, mapping_home, worksets)
        mapping = load_mapping(mapping_path)
        if not mapping:
            raise FileNotFoundError("해당 사건의 실명 대응표를 찾을 수 없습니다.")
        destination = mapping_path.parents[1] / "rehydrated" / args.case / Path(args.name).name
        return {"output": str(rehydrate_document(source, destination, mapping))}
    if args.command == "status":
        store = store_for(args.case, worksets)
        return {
            "case": store.get_case(),
            "counts": {
                "documents": len(store.list_documents()),
                "evidence": len(store.list_payloads("evidence")),
                "facts": len(store.list_payloads("facts")),
                "authorities": len(store.list_payloads("authorities")),
                "issues": len(store.list_payloads("issues")),
                "deadlines": len(store.list_payloads("deadlines")),
                "opinions": len(store.list_payloads("opinions")),
            },
            "latest_audit": store.latest_audit(),
            "event_chain_valid": store.verify_event_chain(),
        }
    if args.command == "consult":
        if args.consult_command == "start":
            entities = load_json(args.entities) if args.entities else None
            return start_consultation(
                load_json(args.file),
                consultation_id=args.id,
                entities=entities,
                mapping_home=mapping_home,
                worksets_home=worksets,
                dry_run=args.dry_run,
            )
        if args.consult_command == "finish":
            return finish_consultation(args.id, load_json(args.result), worksets_home=worksets)
        if args.consult_command == "status":
            return consultation_status(args.id, worksets_home=worksets)
    if args.command == "service":
        if args.service_command == "list":
            return list_services()
        if args.service_command == "plan":
            return {"bundle": str(build_service_bundle(args.case, args.service_type, worksets_home=worksets))}
    if args.command == "eval":
        if args.eval_command == "bootstrap":
            payload = write_manifest(args.manifest, replace=args.replace)
            return {"manifest": str(args.manifest), "scenario_count": len(payload["scenarios"])}
        if args.eval_command == "init-v2":
            return create_evaluation_v2(
                args.source_manifest,
                args.destination,
                replace=args.replace,
            )
        if args.eval_command == "reset-v2-gold":
            return reset_v2_gold_cycle(args.manifest)
        if args.eval_command == "status":
            return manifest_status(args.manifest)
        if args.eval_command == "curate":
            return curate_scenario(args.manifest, args.scenario, args.record)
        if args.eval_command == "collect":
            result: dict[str, Any] = {}
            if args.part in {"all", "decisions"}:
                result["decisions"] = collect_official_decisions(
                    args.manifest,
                    workers=args.workers,
                    replace=args.replace,
                    limit=args.limit,
                )
            if args.part in {"all", "temporal"}:
                result["temporal"] = collect_temporal_rules(args.manifest, replace=args.replace)
            return result
        if args.eval_command == "run":
            return run_evaluation(
                args.manifest,
                runs=args.runs,
                batch_size=args.batch_size,
                model=args.model,
                output_dir=args.output_dir,
                resume=not args.no_resume,
                scenario_limit=args.limit,
            )
        if args.eval_command == "probe":
            return run_probe(
                args.manifest,
                per_kind=args.per_kind,
                runs=args.runs,
                batch_size=args.batch_size,
                model=args.model,
                output_dir=args.output_dir,
                resume=not args.no_resume,
            )
        if args.eval_command == "probe-report":
            return summarize_probe_results(args.manifest, args.results, args.output)
        if args.eval_command == "shadow-policy":
            return shadow_policy_report(args.manifest, args.results, args.output)
        if args.eval_command == "seal":
            return seal_manifest_integrity(args.manifest)
        if args.eval_command == "approve-gold":
            return approve_gold_reviews(args.manifest, args.report)
        if args.eval_command == "review-gold":
            return run_gold_review(
                args.manifest,
                start=args.start,
                end=args.end,
                reviewer_id=args.reviewer_id,
                model=args.model,
                output_path=args.output,
            )
        if args.eval_command == "distill-gold":
            return run_gold_distillation(
                args.manifest,
                start=args.start,
                end=args.end,
                model=args.model,
                output_path=args.output,
            )
        if args.eval_command == "apply-distilled-gold":
            return apply_gold_distillations(args.manifest, args.report)
        if args.eval_command == "refresh-official":
            if not args.all and not args.scenario:
                raise ValueError("--all 또는 하나 이상의 --scenario가 필요합니다.")
            return refresh_cached_official_decisions(args.manifest, args.scenario)
        if args.eval_command == "refresh-temporal":
            if not args.all and not args.scenario:
                raise ValueError("--all 또는 하나 이상의 --scenario가 필요합니다.")
            return refresh_cached_temporal_rules(args.manifest, args.scenario)
        if args.eval_command == "refresh-adversarial":
            return refresh_adversarial_corpus(args.manifest)
        if args.eval_command == "score":
            return score_results(args.manifest, args.results)
    raise ValueError(f"지원하지 않는 명령입니다: {args.command}")


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("입력 JSON은 객체여야 합니다.")
    return payload


def print_json(payload: Any) -> None:
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, default=str)
    sys.stdout.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
