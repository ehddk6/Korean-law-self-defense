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

& $python -m legal_workbench eval score --manifest $Manifest --results $resultsPath
if ($LASTEXITCODE -ne 0) {
    throw '평가 v2 점수 산출 또는 인증에 실패했습니다. 인증 파일은 생성되지 않았습니다.'
}
