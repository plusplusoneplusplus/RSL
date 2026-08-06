[CmdletBinding()]
param(
    [switch] $Release
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = $PSScriptRoot
$cargo = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
if (-not (Test-Path -PathType Leaf $cargo)) {
    throw "Rust is not installed. Run 'winget install Rustlang.Rustup'."
}

. (Join-Path $repoRoot "ossbuild\ossbuild.ps1")

$arguments = @("build", "--workspace", "--all-targets", "--all-features", "--locked")
if ($Release) {
    $arguments += "--release"
}

$env:CARGO_INCREMENTAL = "0"
Push-Location (Join-Path $repoRoot "rust")
try {
    & $cargo @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
