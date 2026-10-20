# Builds the Microsoft Store package: dist\PhishingInspector-<version>-x64.msix
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File packaging\msix\build_msix.ps1 [-Test]
#     [-IdentityName <from Partner Center>] [-Publisher "CN=..."] [-PublisherDisplayName <name>]
# Without the Partner Center values the package gets test placeholders; it still builds,
# but only a package built with the real identity can be uploaded to the Store.
# -Test registers the built app on this PC (needs Windows "Developer Mode"), so you can start it from the Start menu.
param(
    [string]$IdentityName = "3en4all.PhishingInspector",
    [string]$Publisher = "CN=3en4all-test",
    [string]$PublisherDisplayName = "3en4all",
    [switch]$Test
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root

# 1. Tools
$makeappx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $makeappx) {
    throw "makeappx.exe not found. Install the Windows SDK (winget install Microsoft.WindowsSDK.10.0.26100) and run again."
}

# 2. Python environment and tests
if (-not (Test-Path .venv)) { py -3 -m venv .venv }
$py = ".\.venv\Scripts\python.exe"
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet -e ".[msg,dns,dev]"
$env:QT_QPA_PLATFORM = "offscreen"
& $py -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed - build stopped." }
Remove-Item Env:QT_QPA_PLATFORM

# 3. PyInstaller onedir build
& $py -m PyInstaller --noconfirm --clean --distpath build\store\dist --workpath build\store\work packaging\msix\phishing_inspector_store.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

# 4. Package layout + manifest
$init = Get-Content src\phishing_inspector\__init__.py -Raw
$appVersion = [regex]::Match($init, '__version__\s*=\s*"([^"]+)"').Groups[1].Value
$nums = [regex]::Matches($appVersion, '\d+') | Select-Object -First 3 | ForEach-Object { $_.Value }
$msixVersion = (($nums + @("0", "0", "0")) | Select-Object -First 3) -join "."
$msixVersion = "$msixVersion.0"   # the Store requires the 4th number to be 0

$layout = "build\store\layout"
if (Test-Path $layout) { Remove-Item $layout -Recurse -Force }
New-Item -ItemType Directory $layout | Out-Null
Copy-Item build\store\dist\PhishingInspector "$layout\PhishingInspector" -Recurse
Copy-Item packaging\msix\Assets "$layout\Assets" -Recurse
Copy-Item LICENSE "$layout\LICENSE.txt"
(Get-Content packaging\msix\AppxManifest.template.xml -Raw).
    Replace("{{IDENTITY_NAME}}", $IdentityName).
    Replace("{{PUBLISHER}}", [Security.SecurityElement]::Escape($Publisher)).
    Replace("{{PUBLISHER_DISPLAY_NAME}}", [Security.SecurityElement]::Escape($PublisherDisplayName)).
    Replace("{{VERSION}}", $msixVersion) |
    Set-Content "$layout\AppxManifest.xml" -Encoding UTF8

# 5. Pack (unsigned: the Store signs packages itself)
New-Item -ItemType Directory dist -Force | Out-Null
$msix = "dist\PhishingInspector-$appVersion-x64.msix"
& $makeappx.FullName pack /d $layout /p $msix /o
if ($LASTEXITCODE -ne 0) { throw "makeappx failed." }
"{0}  {1}" -f (Get-FileHash $msix -Algorithm SHA256).Hash, (Split-Path $msix -Leaf) | Set-Content "$msix.sha256.txt"
Write-Host "OK: $msix (version $msixVersion, identity $IdentityName, publisher $Publisher)"

# 6. Optional local test without a certificate: register the unpacked layout
if ($Test) {
    $dev = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -ErrorAction SilentlyContinue
    if (-not $dev -or $dev.AllowDevelopmentWithoutDevLicense -ne 1) {
        Write-Warning "Developer Mode is off: Settings > System > For developers > Developer Mode. Then run with -Test again."
    } else {
        Add-AppxPackage -Register "$layout\AppxManifest.xml" -ForceApplicationShutdown
        Write-Host "Installed for testing. Start 'Phishing Inspector' from the Start menu."
        Write-Host "Remove later with: Get-AppxPackage *PhishingInspector* | Remove-AppxPackage"
    }
}
