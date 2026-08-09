[CmdletBinding()]
param(
    [ValidateSet("x64", "arm64")]
    [string] $Platform = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -PathType Leaf $vswhere)) {
    throw "Visual Studio Installer was not found. Install Visual Studio with the Desktop development with C++ workload."
}

$requiredComponents = @(
    "Microsoft.Component.MSBuild",
    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
)
$vsInstallPath = & $vswhere -latest -products * -requires $requiredComponents -property installationPath
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsInstallPath)) {
    throw "Visual Studio with MSBuild and the Desktop development with C++ workload was not found."
}

$devShellModule = Join-Path $vsInstallPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
if (-not (Test-Path -PathType Leaf $devShellModule)) {
    throw "Visual Studio Developer PowerShell module was not found at '$devShellModule'."
}

$vswhereDirectory = Split-Path -Parent $vswhere
if (($env:PATH -split ";" -notcontains $vswhereDirectory)) {
    $env:PATH = "$vswhereDirectory;$env:PATH"
}

Import-Module $devShellModule

# The DevShell module's -Arch/-HostArch parameters expect MSVC arch names
# (amd64/arm64), not MSBuild platform names (x64/arm64). Map accordingly.
$devShellArch = switch ($Platform) {
    "x64"   { "amd64" }
    "arm64" { "arm64" }
    default { throw "Unsupported platform '$Platform'." }
}
Enter-VsDevShell -VsInstallPath $vsInstallPath -SkipAutomaticLocation -Arch $devShellArch -HostArch amd64 | Out-Null

. (Join-Path $PSScriptRoot "ossbuildenv.ps1")
