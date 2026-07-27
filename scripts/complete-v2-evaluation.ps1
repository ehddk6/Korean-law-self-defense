#requires -Version 5.1

[CmdletBinding()]
param(
    [string] $Manifest = 'evaluation\v2\manifest.json',

    [string] $GoldModel = 'gpt-5.6-sol',

    [string] $EvaluationModel = 'gpt-5.5',

    [ValidateRange(1, 100)]
    [int] $BatchSize = 6,

    [string] $OutputDirectory = 'evaluation\v2\results\v2-blind-v6-gpt55-20260726'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$prepareScript = Join-Path $PSScriptRoot 'prepare-v2-gold.ps1'
$evaluationScript = Join-Path $PSScriptRoot 'resume-v2-evaluation.ps1'

& $prepareScript -Manifest $Manifest -Model $GoldModel
if ($LASTEXITCODE -ne 0) {
    throw '평가 v2 독립 gold 준비가 완료되지 않았습니다.'
}

& $evaluationScript `
    -Manifest $Manifest `
    -Model $EvaluationModel `
    -BatchSize $BatchSize `
    -OutputDirectory $OutputDirectory
if ($LASTEXITCODE -ne 0) {
    throw '평가 v2 잠금평가 또는 채점이 완료되지 않았습니다.'
}
