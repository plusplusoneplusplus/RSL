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

$repoRoot = $PSScriptRoot
. (Join-Path $repoRoot "ossbuild\ossbuild.ps1") -Platform $Platform

$target = if ($Rebuild) { "Rebuild" } else { "Build" }
$project = Join-Path $repoRoot "src\RSL\src\dll\RSL.vcxproj"

& msbuild $project /m /nologo /v:minimal "/t:$target" "/p:Configuration=$Configuration" "/p:Platform=$Platform"
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE."
}
