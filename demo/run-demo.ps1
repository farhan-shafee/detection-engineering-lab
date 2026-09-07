[CmdletBinding()]
param([switch]$Check)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $repositoryRoot '.venv\Scripts\python.exe'
$pythonCommand = if (Test-Path -LiteralPath $venvPython) { $venvPython } else { 'python' }
Push-Location -LiteralPath $repositoryRoot
try {
    $arguments = @('-m', 'detection_lab', 'demo')
    if ($Check) { $arguments += '--check' }
    & $pythonCommand @arguments
    if ($LASTEXITCODE -ne 0) { throw "Detection demo failed with exit code $LASTEXITCODE" }
}
finally { Pop-Location }
