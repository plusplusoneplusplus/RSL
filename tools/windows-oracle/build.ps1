[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string] $Configuration = "Debug",

    [ValidateSet("x64", "arm64")]
    [string] $Platform = "x64",

    [switch] $Rebuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
. (Join-Path $repoRoot "ossbuild\ossbuild.ps1") -Platform $Platform

$target = if ($Rebuild) { "Rebuild" } else { "Build" }
$project = Join-Path $PSScriptRoot "RSLWindowsOracle.vcxproj"

& msbuild $project /m /nologo /v:minimal "/t:$target" "/p:Configuration=$Configuration" "/p:Platform=$Platform" | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE."
}

$buildType = if ($Configuration -eq "Release") { "retail" } else { "debug" }
$buildArch = if ($Platform -eq "x64") { "amd64" } else { "arm64" }
Write-Output (Join-Path $repoRoot "out\$buildType-$buildArch\RSLWindowsOracle\RSLWindowsOracle.exe")
