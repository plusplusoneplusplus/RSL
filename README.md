# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# How to build

## Prerequisites

Install [Git for Windows](https://git-scm.com/download/win), Rust stable, and
Visual Studio 2022 or newer. In the Visual Studio Installer, select **Desktop
development with C++** and a Windows 10 or Windows 11 SDK.

CI uses the x64 `windows-2022` image, Visual Studio 2022's default C++ toolset,
and the installed Windows SDK. `ossbuild\ossbuild.ps1` locates the latest
compatible Visual Studio installation through `vswhere`; no VS 2017 developer
prompt is required.

## Build the native library

Run the build from a PowerShell prompt at the repository root:

    .\build.ps1

The script locates Visual Studio, initializes its C++ build environment, and builds the 64-bit Debug native DLL and
static libraries. Outputs are written under `out\debug-amd64`.

Choose a Release build or rebuild all native outputs with:

    .\build.ps1 -Configuration Release
    .\build.ps1 -Rebuild

## Use MSBuild directly

Initialize the repository and Visual Studio environment in the current PowerShell process:

    . .\ossbuild\ossbuild.ps1

The leading dot and space keep the initialized environment in the current prompt. You can then build an individual
native project with MSBuild:

    msbuild .\src\RSL\src\dll\RSL.vcxproj /m /p:Configuration=Debug /p:Platform=x64

The native projects use the default C++ platform toolset and Windows SDK installed by Visual Studio.

## Build the Rust workspace

Install Rust once:

    winget install Rustlang.Rustup

Then run:

    .\build-rust.ps1

Use `.\build-rust.ps1 -Release` for an optimized build. The script builds the entire workspace with all targets and
features.

## CI and interoperability artifacts

The Windows authority job builds native RSL and Rust in Debug and Release. Its
Release leg runs the production Windows oracle and publishes a schema-versioned
wire/storage artifact containing source revision, toolchain provenance, and a
SHA-256 for every file. Linux Rust CI downloads and validates that same-run
artifact before testing the portable implementation against it.

The Linux `rsl-linux-proxy` build remains a supplemental proxy for portable
marshaling, POSIX filesystem behavior, OpenSSL interoperability, and fuzzing.
It does not replace the production Windows storage, IOCP, learn-port, or
SChannel authority.
