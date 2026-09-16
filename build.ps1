# Builds notifymatrix.exe for local use and hand-carry testing.
#
# This is the DEVELOPER path. Releases are built and signed by
# .github/workflows/release.yml, which authenticates to Azure with federated
# credentials and has no long-lived secret; this script signs with whatever
# `az login` identity you happen to be holding. The two must not drift, so the
# build flags here are the same ones the workflow uses.
#
#   .\build.ps1              build and sign
#   .\build.ps1 -NoSign      skip signing (fast inner loop)
#   .\build.ps1 -SkipTests   skip the test gate (use sparingly)
#   .\build.ps1 -All         also cross-compile the Linux targets
param(
    [switch]$NoSign,
    [switch]$SkipTests,
    [switch]$All
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

if (-not (Get-Command go   -ErrorAction SilentlyContinue)) { $env:PATH += ";C:\Program Files\Go\bin" }
if (-not (Get-Command sign -ErrorAction SilentlyContinue)) { $env:PATH += ";$env:USERPROFILE\.dotnet\tools" }
if (-not (Get-Command az   -ErrorAction SilentlyContinue)) { $env:PATH += ";C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin" }

# Version: the current tag if HEAD is tagged, else <last tag>-dev-<short sha>.
# A local build must never claim to be a release -- if a support case arrives
# quoting a version, it has to be possible to tell which binary they ran.
$ver = "0.0.0-dev"
try {
    $exact = git describe --tags --exact-match HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $exact) {
        $ver = $exact -replace '^v', ''
    } else {
        $desc = git describe --tags --always --dirty 2>$null
        if ($LASTEXITCODE -eq 0 -and $desc) { $ver = "$($desc -replace '^v','')-dev" }
    }
} catch { }

Push-Location $root
try {
    # The shipping constraint, not a convenience: static binaries, reproducible
    # output, and no cgo-linked dependency creeping into the module graph.
    # Building with cgo merely AVAILABLE on this machine would silently produce
    # a binary with a libc dependency the target may not have.
    $env:CGO_ENABLED = "0"

    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw "go vet failed" }

    if (-not $SkipTests) {
        go test ./...
        if ($LASTEXITCODE -ne 0) { throw "tests failed" }
    }

    # Same flags as the release workflow, so a local binary and a released one
    # differ only by their version string.
    $ldflags = "-s -w -buildid= -X main.version=$ver"
    go build -trimpath -ldflags $ldflags -o notifymatrix.exe .\cmd\notifymatrix
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
    Write-Host "built notifymatrix.exe $ver" -ForegroundColor Green

    if ($All) {
        New-Item -ItemType Directory -Force dist | Out-Null
        foreach ($t in @(@("linux","amd64"), @("linux","arm64"))) {
            $env:GOOS = $t[0]; $env:GOARCH = $t[1]
            go build -trimpath -ldflags $ldflags -o "dist/notifymatrix-$($t[0])-$($t[1])" .\cmd\notifymatrix
            if ($LASTEXITCODE -ne 0) { throw "build failed for $($t[0])/$($t[1])" }
            Write-Host "built dist/notifymatrix-$($t[0])-$($t[1])" -ForegroundColor Green
        }
        Remove-Item Env:GOOS, Env:GOARCH
    }

    # ---- Authenticode signing ----
    # An unsigned exe on a customer machine means a SmartScreen argument with
    # them watching, so signing is the difference between a test that starts in
    # ten seconds and one that starts in ten minutes.
    $cfgPath = Join-Path $root "signing.json"
    if ($NoSign) {
        Write-Host "signing skipped (-NoSign)" -ForegroundColor Yellow
    }
    elseif (-not (Test-Path $cfgPath)) {
        Write-Host "WARNING: UNSIGNED build (no signing.json; copy signing.example.json)" -ForegroundColor Yellow
    }
    else {
        $sc = Get-Content $cfgPath -Raw | ConvertFrom-Json
        if ($sc.account -like "<*" -or $sc.profile -like "<*") {
            Write-Host "WARNING: UNSIGNED build (signing.json still has placeholders)" -ForegroundColor Yellow
        }
        else {
            if (-not (Get-Command sign -ErrorAction SilentlyContinue)) {
                throw "signing configured but the 'sign' tool is missing; install with: dotnet tool install -g --prerelease sign"
            }
            Write-Host "signing via Azure Artifact Signing ($($sc.account)/$($sc.profile))..."
            # Skip the managed-identity probe (VM-only) so auth falls through
            # to the az login credential.
            $env:AZURE_TOKEN_CREDENTIALS = "dev"
            sign code artifact-signing `
                --verbosity warning `
                --timestamp-url $sc.timestamp_url `
                --azure-endpoint $sc.endpoint `
                --account $sc.account `
                --certificate-profile $sc.profile `
                notifymatrix.exe
            if ($LASTEXITCODE -ne 0) { throw "signing failed" }

            $sig = Get-AuthenticodeSignature notifymatrix.exe
            if ($sig.Status -ne 'Valid') { throw "Authenticode status is $($sig.Status)" }
            if (-not $sig.TimeStamperCertificate) { throw "signature is not timestamped" }
            Write-Host "signed and timestamped" -ForegroundColor Green
        }
    }
}
finally {
    Pop-Location
}
