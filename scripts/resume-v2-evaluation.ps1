#requires -Version 5.1

[CmdletBinding()]
param(
    [string] $Manifest = 'evaluation\v2\manifest.json',

    [string] $Model = 'gpt-5.6-terra',

    [ValidateRange(1, 100)]
    [int] $BatchSize = 6,

    [string] $OutputDirectory = 'evaluation\v2\results\v2-blind-v6-gpt56terra-20260728'
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

$status = & $python -m legal_workbench eval status --manifest $Manifest | ConvertFrom-Json
if (
    -not $status.ok `
    -or $status.result.evaluation_version -ne 2 `
    -or -not $status.result.corpus_ready `
    -or -not $status.result.v2_cycle_valid `
    -or $status.result.gold_review_cycle -ne 'v2-approved'
) {
    throw '평가 v2 코퍼스가 준비되지 않았습니다. gold 증류·재검토·봉인을 먼저 완료하십시오.'
}

$resultDirectoryPath = Join-Path $projectRoot $OutputDirectory
& $python -m legal_workbench eval run `
    --manifest $Manifest `
    --runs 3 `
    --model $Model `
    --batch-size $BatchSize `
    --output-dir $OutputDirectory

if ($LASTEXITCODE -ne 0) {
    throw '잠금평가 v2 실행이 완료되지 않았습니다. 기존 결과는 보존되며 다음 실행에서 재개됩니다.'
}

$resultsPath = Join-Path $resultDirectoryPath 'results.jsonl'
if (-not (Test-Path -LiteralPath $resultsPath -PathType Leaf)) {
    throw "평가 결과 파일을 찾을 수 없습니다: $resultsPath"
}

$scoreJson = (
    & $python -m legal_workbench eval score --manifest $Manifest --results $resultsPath |
    Out-String
)
if ($LASTEXITCODE -ne 0) {
    throw '평가 v2 점수 산출 명령이 실패했습니다.'
}
$score = $scoreJson | ConvertFrom-Json
$scoreJson.Trim() | Write-Output
$failures = @($score.result.failures)
$certificationPath = if ($null -ne $score.result.PSObject.Properties['certification_path']) {
    [string] $score.result.certification_path
} else {
    ''
}
if (
    -not $score.ok `
    -or -not $score.result.v1_certified `
    -or $failures.Count -ne 0 `
    -or [string]::IsNullOrWhiteSpace($certificationPath) `
    -or -not (Test-Path -LiteralPath $certificationPath -PathType Leaf)
) {
    throw ("평가 v2 인증에 실패했습니다. failures={0}" -f ($failures -join '; '))
}

$finalStatusJson = (
    & $python -m legal_workbench eval status --manifest $Manifest |
    Out-String
)
if ($LASTEXITCODE -ne 0) {
    throw '평가 v2 최종 인증 상태 확인이 실패했습니다.'
}
$finalStatus = $finalStatusJson | ConvertFrom-Json
$finalStatusJson.Trim() | Write-Output
if (
    -not $finalStatus.ok `
    -or -not $finalStatus.result.corpus_ready `
    -or -not $finalStatus.result.v2_cycle_valid `
    -or -not $finalStatus.result.v1_certified
) {
    throw '최종 상태에서 평가 v2 잠금평가 인증을 확인하지 못했습니다.'
}
