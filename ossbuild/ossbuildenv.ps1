#Requires -version 3.0
Set-StrictMode -version latest

function SetEnv
{
    # Get the root directory
    $repoRoot = Join-Path -Resolve $PSScriptRoot ".."
    $srcRoot = Join-Path -Resolve $repoRoot "src"
    $outRoot = Join-Path $repoRoot "out"
    $buildPropsRoot = Join-Path -Resolve $PSScriptRoot "ossbuildenv.props"
    $confRoot = Join-Path -Resolve $repoRoot ".config"
    $verPath = Join-Path -Resolve $confRoot ".inc"
    $asmVerDefFile = Join-Path -Resolve $verPath "versions.xml"

    $verXml = [XML](Get-Content $asmVerDefFile)
    $ver = $verXml.root.versions.version.value
    
    $env:REPOROOT =         $repoRoot
    $env:BaseDir =          $repoRoot
    $env:EnlistmentRoot =   $repoRoot
    $env:INETROOT =         $repoRoot
    $env:OBJECT_ROOT =      $repoRoot
    $env:ROOT =             $repoRoot
    $env:_NTTREE =          $repoRoot
    
    $env:SRCROOT =          $srcRoot
    $env:OUTPUTROOT =       $outRoot

    $env:EnvironmentConfig =                $buildPropsRoot
    $env:CONFROOT =                         $confRoot
    $env:AssemblyVersionDefinitionFile =    $asmVerDefFile

    $env:OSSBUILD =         "1"
    $env:BUILD_COREXT =     "0"
    $env:NOTQBUILD =        "1"
    $env:MsBuildArgs =      "/consoleloggerparameters:Summary;ForceNoAlign;Verbosity=minimal"
    $env:BUILDNUMBER =      $ver
}

SetEnv
