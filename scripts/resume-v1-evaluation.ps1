#requires -Version 5.1

[CmdletBinding()]
param(
    [string] $Model = 'gpt-5.5',

    [ValidateRange(1, 100)]
    [int] $BatchSize = 12,

    [string] $OutputDirectory = 'evaluation\results\v1-local-mapping-20260726'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot
$env:PYTHONUTF8 = '1'

$status = python -m legal_workbench eval status | ConvertFrom-Json
if (-not $status.ok -or -not $status.result.corpus_ready) {
    throw '평가 코퍼스가 준비되지 않았습니다. legal eval status의 오류를 먼저 해결하십시오.'
}

$resultDirectoryPath = Join-Path $projectRoot $OutputDirectory
python -m legal_workbench eval run `
    --manifest evaluation\manifest.json `
    --runs 3 `
    --model $Model `
    --batch-size $BatchSize `
    --output-dir $OutputDirectory

if ($LASTEXITCODE -ne 0) {
    throw '잠금평가 실행이 완료되지 않았습니다. 기존 결과는 보존되며 다음 실행에서 재개됩니다.'
}

$resultsPath = Join-Path $resultDirectoryPath 'results.jsonl'
if (-not (Test-Path -LiteralPath $resultsPath -PathType Leaf)) {
    throw "평가 결과 파일을 찾을 수 없습니다: $resultsPath"
}

python -m legal_workbench eval score --manifest evaluation\manifest.json --results $resultsPath
if ($LASTEXITCODE -ne 0) {
    throw '평가 점수 산출 또는 v1 인증에 실패했습니다. 인증 파일은 생성되지 않았습니다.'
}
