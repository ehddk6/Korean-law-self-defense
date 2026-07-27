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

$reviewReports = @()
for ($start = 1; $start -le 150; $start += 5) {
    $end = [Math]::Min($start + 4, 150)
    $path = 'evaluation\v2\reviews\gold-v2-{0:D3}-{1:D3}.json' -f $start, $end
    $reviewReports += $path
    $reviewedCount = $end - $start + 1
    $needsReview = -not (Test-Path -LiteralPath $path -PathType Leaf)
    if (-not $needsReview) {
        try {
            $existingReview = Get-Content -Raw -Encoding UTF8 -LiteralPath $path | ConvertFrom-Json
            $existingRecords = @($existingReview.reviews.PSObject.Properties.Value)
            $existingRejected = @($existingRecords | Where-Object { $_.approved -ne $true })
            $needsReview = (
                $existingRecords.Count -ne $reviewedCount `
                -or $existingRejected.Count -gt 0 `
                -or $existingReview.reviewer_model -ne $Model
            )
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
    throw '150건 gold 독립 검토 승인에 실패했습니다.'
}

& $python -m legal_workbench eval status --manifest $Manifest
