#Requires -Version 5.1
[CmdletBinding()]
param([string]$Python, [switch]$Help)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Help) {
    Write-Output 'Interactive test-only deployment or offline packaging; no action before explicit confirmation.'
    Write-Output 'Usage: .\Deploy-MockSas-Wizard.ps1 [-Python PATH_TO_PYTHON] [-Help]'
    Write-Output 'Requires Python with deploy/mock-sas/requirements.txt, OpenSSH for deployment, and tar.'
    exit 0
}
if (-not $Python) {
    $localPython = Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
    $Python = if (Test-Path -LiteralPath $localPython) { $localPython } else { 'python' }
}
$command = Get-Command $Python -CommandType Application -ErrorAction SilentlyContinue
if (-not $command) { Write-Error 'Python missing; create the documented local environment first.'; exit 1 }
$program = $command.Source
$plan = & $program (Join-Path $PSScriptRoot 'deployment_wizard.py') --plan
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$request = ($plan -join "`n") | ConvertFrom-Json
$parameters = @{}
foreach ($property in $request.PSObject.Properties) { $parameters[$property.Name] = $property.Value }
& (Join-Path $PSScriptRoot 'Deploy-MockSas.ps1') @parameters
