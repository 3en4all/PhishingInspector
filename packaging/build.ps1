# Builds PhishingInspector PL and EN executables into .\dist
# Usage (from the repository root):  powershell -ExecutionPolicy Bypass -File packaging\build.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not (Test-Path .venv)) { py -3 -m venv .venv }
$py = ".\.venv\Scripts\python.exe"
& $py -m pip install --upgrade pip
& $py -m pip install -e ".[msg,dns,dev]"

$env:QT_QPA_PLATFORM = "offscreen"
& $py -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed - build stopped." }
Remove-Item Env:QT_QPA_PLATFORM

& $py -m PyInstaller --noconfirm --clean packaging\phishing_inspector.spec
Get-ChildItem dist\*.exe | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    "{0}  {1}" -f $hash, $_.Name
} | Set-Content dist\SHA256SUMS.txt
Get-Content dist\SHA256SUMS.txt
