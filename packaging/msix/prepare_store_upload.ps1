# Prepare a Store upload archive from an existing MSIX (PowerShell 5.1+).
# Does not modify the MSIX, install certificates, or submit to Partner Center.
param(
    [string]$MsixPath = "D:\Projects\PhishingInspector_store\dist\PhishingInspector-0.3.0-beta-x64.msix"
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$msix = (Resolve-Path -LiteralPath $MsixPath -ErrorAction Stop).Path
$z = [System.IO.Compression.ZipFile]::OpenRead($msix)
try {
    $entry = $z.GetEntry("AppxManifest.xml")
    if (-not $entry) { throw "MSIX is missing AppxManifest.xml" }
    $reader = [IO.StreamReader]::new($entry.Open())
    try { [xml]$xml = $reader.ReadToEnd() } finally { $reader.Dispose() }
    $id = $xml.Package.Identity
    $display = [string]$xml.Package.Properties.DisplayName
    if ($id.Name -ne "3en4All.PhishingInspector") { throw "Unexpected identity: $($id.Name)" }
    if ($id.Publisher -ne "CN=2DDDF943-1FAB-494A-9D19-ED6BDCEE268B") { throw "Unexpected publisher: $($id.Publisher)" }
    if ($display -notin @("PhishingInspector","Phishing Inspector")) { throw "Unexpected display name: $display" }
    if (-not $z.GetEntry("AppxBlockMap.xml")) { throw "Missing AppxBlockMap.xml" }
    Write-Host "Identity: $($id.Name) | $($id.Version) | $($id.ProcessorArchitecture)"
    Write-Host "DisplayName: $display"
    Write-Host "Signature embedded: $([bool]$z.GetEntry('AppxSignature.p7x'))"
} finally { $z.Dispose() }
$destination = [IO.Path]::ChangeExtension($msix, ".msixupload")
if (Test-Path -LiteralPath $destination) { throw "Output exists; refusing to overwrite: $destination" }
$archive = [System.IO.Compression.ZipFile]::Open($destination, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $archive, $msix, [IO.Path]::GetFileName($msix),
        [System.IO.Compression.CompressionLevel]::NoCompression
    ) | Out-Null
} finally { $archive.Dispose() }
Write-Host "Ready for Partner Center: $destination"
Get-FileHash -LiteralPath $destination -Algorithm SHA256 | Format-List
