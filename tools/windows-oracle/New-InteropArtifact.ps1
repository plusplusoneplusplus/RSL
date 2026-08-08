[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $OraclePath,

    [Parameter(Mandatory)]
    [string] $OutputDirectory,

    [ValidateSet("Release")]
    [string] $Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
. (Join-Path $repoRoot "ossbuild\ossbuild.ps1") -Platform x64
if (-not (Test-Path -PathType Leaf $OraclePath)) {
    throw "Oracle executable '$OraclePath' does not exist."
}
$oracle = (Resolve-Path $OraclePath).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if ($output -eq $repoRoot -or $output -eq [IO.Path]::GetPathRoot($output)) {
    throw "Refusing to replace unsafe artifact path '$output'."
}
if (Test-Path $output) {
    Remove-Item -LiteralPath $output -Recurse -Force
}
$wireDirectory = New-Item -ItemType Directory -Force (Join-Path $output "wire")
$storageDirectory = New-Item -ItemType Directory -Force (Join-Path $output "storage")
$logsDirectory = New-Item -ItemType Directory -Force (Join-Path $output "logs")

function Invoke-Oracle {
    param(
        [string[]] $Arguments,
        [string] $LogName,
        [int[]] $ExpectedExitCodes = @(0)
    )

    $log = Join-Path $logsDirectory $LogName
    & $oracle @Arguments *>&1 | Tee-Object -FilePath $log
    $exitCode = $LASTEXITCODE
    if ($exitCode -notin $ExpectedExitCodes) {
        throw "Oracle command '$Arguments' exited $exitCode; see '$log'."
    }
}

$identityText = & $oracle --identity
if ($LASTEXITCODE -ne 0) {
    throw "Oracle identity command failed with exit code $LASTEXITCODE."
}
$identity = $identityText | ConvertFrom-Json
$identityText | Set-Content -Encoding utf8NoBOM (Join-Path $output "identity.json")

Invoke-Oracle @("--self-test") "self-test.log"
Invoke-Oracle @("--wire", (Join-Path $wireDirectory "wire.txt")) "wire-generation.log"
Invoke-Oracle @("--storage-full", $storageDirectory) "storage-generation.log"
Invoke-Oracle @("--verify-storage", $storageDirectory) "storage-verification.jsonl" @(3)

$sourceRevision = (& git -C $repoRoot rev-parse HEAD).Trim()
$sourceDirty = [bool](& git -C $repoRoot status --porcelain --untracked-files=no)
$generatorHash = (Get-FileHash -Algorithm SHA256 $oracle).Hash.ToLowerInvariant()
$cargoPath = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
$rustcPath = Join-Path $env:USERPROFILE ".cargo\bin\rustc.exe"

function Native-Version([string] $command, [string[]] $arguments) {
    try {
        return ((& $command @arguments 2>&1) -join "`n").Trim()
    }
    catch {
        return "unavailable: $($_.Exception.Message)"
    }
}

$files = Get-ChildItem -LiteralPath $output -Recurse -File |
    Sort-Object FullName |
    ForEach-Object {
        [ordered]@{
            path = [IO.Path]::GetRelativePath($output, $_.FullName).Replace("\", "/")
            size = $_.Length
            sha256 = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant()
        }
    }

$manifest = [ordered]@{
    artifactSchemaVersion = 1
    generator = [ordered]@{
        identity = $identity.identity
        executableSha256 = $generatorHash
        command = "RSLWindowsOracle --wire; --storage-full; --verify-storage"
    }
    provenance = [ordered]@{
        sourceRevision = $sourceRevision
        sourceDirty = $sourceDirty
        architecture = $identity.architecture
        configuration = $Configuration
        generatedAtUtc = [DateTime]::UtcNow.ToString("o")
        runner = [ordered]@{
            os = $env:OS
            image = $env:ImageOS
            imageVersion = $env:ImageVersion
        }
        tools = [ordered]@{
            msbuild = Native-Version "msbuild" @("-version", "-nologo")
            compiler = Native-Version "cl" @()
            rustc = Native-Version $rustcPath @("--version", "--verbose")
            cargo = Native-Version $cargoPath @("--version", "--verbose")
        }
    }
    corpora = [ordered]@{
        wire = "wire/wire.txt"
        wireManifest = "wire/wire.txt.manifest.json"
        storage = "storage"
        storageManifest = "storage/MANIFEST.json"
    }
    files = @($files)
}

$manifest |
    ConvertTo-Json -Depth 8 |
    Set-Content -Encoding utf8NoBOM (Join-Path $output "artifact-manifest.json")

Write-Output $output
