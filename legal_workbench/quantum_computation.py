from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .models import new_id, utc_now
from .security import atomic_json_write
from .workflow import store_for


@dataclass(slots=True)
class QuantumResult:
    base_claim: float
    mitigation_ratio: float
    offset_amount: float
    final_expected_amount: float
    calculation_formula: str
    basis_note: str = ""


@dataclass(slots=True)
class QuantumRecord:
    quantum_id: str
    case_id: str
    result: QuantumResult
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def calculate_quantum(
    case_id: str,
    claim_amount: float,
    *,
    mitigation_ratio: float | None = None,
    offset_amount: float = 0.0,
    worksets_home: Path | None = None,
) -> dict[str, Any]:
    if claim_amount <= 0:
        raise ValueError("청구 금액은 0보다 커야 합니다.")
    if offset_amount < 0:
        raise ValueError("공제액은 0 이상이어야 합니다.")
    if mitigation_ratio is not None and not (0.0 <= mitigation_ratio <= 1.0):
        raise ValueError("과실상계율은 0 이상 1 이하여야 합니다.")

    store = store_for(case_id, worksets_home)
    store.get_case()

    if mitigation_ratio is None:
        basis_note = (
            "과실상계율 미적용(근거 미확인): 사건 기록에 검증된 과실비율 근거가 없으므로 임의 비율을 적용하지 않습니다. "
            "사용자가 법원·상대방 주장에서 확인한 비율을 --mitigation으로 전달하면 재산정됩니다."
        )
    else:
        basis_note = f"과실상계율 {mitigation_ratio * 100:.0f}%는 사용자가 확인한 값을 그대로 반영한 계산이며, 공식 근거 검증은 별도로 필요합니다."
    if offset_amount:
        basis_note += f" 공제액 {offset_amount:,.0f}원은 사용자가 확인한 값을 반영합니다."

    final_amount = max(0.0, claim_amount * (1.0 - (mitigation_ratio or 0.0)) - offset_amount)
    mitigation_text = (
        f"{mitigation_ratio * 100:.0f}%" if mitigation_ratio is not None else "0% (근거 미확인, 미적용)"
    )
    formula = (
        f"청구액({claim_amount:,.0f}원) × (1 - 과실상계율 {mitigation_text}) - "
        f"공제액({offset_amount:,.0f}원) = {final_amount:,.0f}원"
    )

    result = QuantumResult(
        base_claim=claim_amount,
        mitigation_ratio=mitigation_ratio or 0.0,
        offset_amount=offset_amount,
        final_expected_amount=final_amount,
        calculation_formula=formula,
        basis_note=basis_note,
    )

    record = QuantumRecord(
        quantum_id=new_id("qt"),
        case_id=case_id,
        result=result,
    )

    qt_dir = store.case_dir / "quantums"
    qt_dir.mkdir(parents=True, exist_ok=True)
    atomic_json_write(qt_dir / f"{record.quantum_id}.json", record.to_dict())
    store.add_quantum(record)
    return {
        "quantum_id": record.quantum_id,
        "final_expected_amount": final_amount,
        "formula": formula,
        "basis_note": basis_note,
    }
