#requires -Version 5.1

[CmdletBinding()]
param(
    [string] $Manifest = 'evaluation\v2\manifest.json',

    [string] $Model = 'gpt-5.6-sol'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot
$env:PYTHONUTF8 = '1'
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "프로젝트 Python을 찾을 수 없습니다: $python"
}

$initialStatus = & $python -m legal_workbench eval status --manifest $Manifest | ConvertFrom-Json
if (-not $initialStatus.ok -or $initialStatus.result.evaluation_version -ne 2) {
    throw '독립 gold 준비는 evaluation v2 manifest에서만 실행할 수 있습니다.'
}
if ($initialStatus.result.corpus_ready -and $initialStatus.result.gold_review_cycle -eq 'v2-approved') {
    $initialStatus | ConvertTo-Json -Depth 8
    return
}
if ($initialStatus.result.gold_review_cycle -notin @('v2-pending', 'v2-sealed-pending-review')) {
    throw "알 수 없는 v2 gold review cycle입니다: $($initialStatus.result.gold_review_cycle)"
}
$manifestPayload = Get-Content -Raw -Encoding UTF8 -LiteralPath $Manifest | ConvertFrom-Json
$manifestRoot = Split-Path -Parent (Resolve-Path -LiteralPath $Manifest)
$scenarioById = @{}
foreach ($scenario in $manifestPayload.scenarios) {
    $scenarioById[$scenario.scenario_id] = $scenario
}

$distillReports = @()
for ($start = 1; $start -le 120; $start += 5) {
    $end = $start + 4
    $path = 'evaluation\v2\reviews\distill-v2-{0:D3}-{1:D3}.json' -f $start, $end
    $distillReports += $path
    $needsDistill = -not (Test-Path -LiteralPath $path -PathType Leaf)
    if (-not $needsDistill) {
        try {
            $existingDistill = Get-Content -Raw -Encoding UTF8 -LiteralPath $path | ConvertFrom-Json
            $needsDistill = (
                $existingDistill.model -ne $Model `
                -or @($existingDistill.cases.PSObject.Properties.Value).Count -ne 5
            )
        } catch {
            $needsDistill = $true
        }
    }
    if (-not $needsDistill) {
        for ($scenarioNumber = $start; $scenarioNumber -le $end; $scenarioNumber++) {
            $scenarioId = 'case-{0:D3}' -f $scenarioNumber
            $scenario = $scenarioById[$scenarioId]
            $expectedPath = Join-Path $manifestRoot $scenario.expected_path
            try {
                $expected = Get-Content -Raw -Encoding UTF8 -LiteralPath $expectedPath | ConvertFrom-Json
                if ($null -eq $expected.gold_evidence) {
                    $needsDistill = $true
                    break
                }
            } catch {
                $needsDistill = $true
                break
            }
        }
    }
    if (-not $needsDistill) {
        $reviewPath = 'evaluation\v2\reviews\gold-v2-{0:D3}-{1:D3}.json' -f $start, $end
        if (Test-Path -LiteralPath $reviewPath -PathType Leaf) {
            try {
                $existingReview = Get-Content -Raw -Encoding UTF8 -LiteralPath $reviewPath | ConvertFrom-Json
                for ($scenarioNumber = $start; $scenarioNumber -le $end; $scenarioNumber++) {
                    $scenarioId = 'case-{0:D3}' -f $scenarioNumber
                    $scenario = $scenarioById[$scenarioId]
                    $reviewProperty = $existingReview.reviews.PSObject.Properties[$scenarioId]
                    if ($null -eq $reviewProperty) {
                        continue
                    }
                    $review = $reviewProperty.Value
                    $reviewIsCurrent = (
                        $review.source_sha256 -eq $scenario.source_sha256 `
                        -and $review.fixture_sha256 -eq $scenario.fixture_sha256 `
                        -and $review.expected_sha256 -eq $scenario.expected_sha256
                    )
                    if ($reviewIsCurrent -and $review.checks.gold_supported -ne $true) {
                        $needsDistill = $true
                        break
                    }
                }
            } catch {
                # The review loop below will regenerate malformed reports.
            }
        }
    }
    if ($needsDistill) {
        & $python -m legal_workbench eval distill-gold `
            --manifest $Manifest `
            --start $start `
            --end $end `
            --model $Model `
            --output $path
        if ($LASTEXITCODE -ne 0) {
            throw "gold 증류가 실패했습니다: $start-$end"
        }
    }
}

$applyArgs = @('-m', 'legal_workbench', 'eval', 'apply-distilled-gold', '--manifest', $Manifest)
foreach ($path in $distillReports) {
    $applyArgs += @('--report', $path)
}
& $python @applyArgs
if ($LASTEXITCODE -ne 0) {
    throw '120건 gold 증류 결과 적용에 실패했습니다.'
}

& $python -m legal_workbench eval seal --manifest $Manifest
if ($LASTEXITCODE -ne 0) {
    throw '평가 v2 입력·기대결과 봉인에 실패했습니다.'
}
$manifestPayload = Get-Content -Raw -Encoding UTF8 -LiteralPath $Manifest | ConvertFrom-Json
$scenarioById = @{}
foreach ($scenario in $manifestPayload.scenarios) {
    $scenarioById[$scenario.scenario_id] = $scenario
}

$reviewReports = @()
for ($start = 1; $start -le 180; $start += 5) {
    $end = [Math]::Min($start + 4, 180)
    $path = 'evaluation\v2\reviews\gold-v2-{0:D3}-{1:D3}.json' -f $start, $end
    $reviewReports += $path
    $reviewedCount = $end - $start + 1
    $needsReview = -not (Test-Path -LiteralPath $path -PathType Leaf)
    if (-not $needsReview) {
        try {
            $existingReview = Get-Content -Raw -Encoding UTF8 -LiteralPath $path | ConvertFrom-Json
            $existingRecords = @($existingReview.reviews.PSObject.Properties.Value)
            $existingRejected = @($existingRecords | Where-Object { $_.approved -ne $true })
            $hashMismatch = @($existingReview.reviews.PSObject.Properties | Where-Object {
                $scenario = $scenarioById[$_.Name]
                if (-not $scenario) { return $true }
                if ($_.Value.fixture_sha256 -ne $scenario.fixture_sha256 -or $_.Value.expected_sha256 -ne $scenario.expected_sha256) { return $true }
                $adversarial = $scenario.kind -in @('fabricated-citation', 'prompt-injection', 'ocr-corruption', 'pii-leakage', 'conflicting-evidence')
                return (-not $adversarial -and $_.Value.source_sha256 -ne $scenario.source_sha256)
            })
            $needsReview = (
                $existingRecords.Count -ne $reviewedCount `
                -or $existingRejected.Count -gt 0 `
                -or $hashMismatch.Count -gt 0 `
                -or $existingReview.reviewer_model -ne $Model
            )
            if ($hashMismatch.Count -gt 0) {
                $needsReview = $true
            }
        } catch {
            $needsReview = $true
        }
    }
    if ($needsReview) {
        $reviewer = if ($end -le 75) { 'reviewer-a-v2' } else { 'reviewer-b-v2' }
        & $python -m legal_workbench eval review-gold `
            --manifest $Manifest `
            --start $start `
            --end $end `
            --reviewer-id $reviewer `
            --model $Model `
            --output $path
        if ($LASTEXITCODE -ne 0) {
            throw "gold 독립 검토가 실패했습니다: $start-$end"
        }
    }
}

$approveArgs = @('-m', 'legal_workbench', 'eval', 'approve-gold', '--manifest', $Manifest)
foreach ($path in $reviewReports) {
    $approveArgs += @('--report', $path)
}
& $python @approveArgs
if ($LASTEXITCODE -ne 0) {
    throw '180건 gold 독립 검토 승인에 실패했습니다.'
}

& $python -m legal_workbench eval status --manifest $Manifest
