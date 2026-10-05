# Newtype installer for Windows (amd64, arm64). Windows PowerShell 5.1 or later.
#
#   irm https://lic.newtype-ai.com/install.ps1 | iex
#
# Reads /v1/releases/latest.txt (key=value lines from the signed release
# manifest; the server verified its Ed25519 signature), downloads
# /v1/releases/files/<sha256> and checks the size and SHA-256 with
# Get-FileHash BEFORE installing to
#   %LOCALAPPDATA%\Newtype\bin\newtype-<version>.exe
# plus newtype.exe, a plain copy of it (a copy, not a .cmd shim: no cmd.exe
# argument re-parsing, Ctrl+C works, and `newtype update` can swap a real
# exe). That folder is added to the USER Path; no administrator rights.
# Nothing downloaded is evaluated: the only code run is the verified exe
# (`newtype.exe --version`).
#
# Trust: this first install trusts HTTPS plus the SHA-256 from the signed
# manifest. Later updates (`newtype update`, TUI /update) are verified inside
# the newtype client by the Ed25519 release signature with its pinned key.
#
# Windows builds are Authenticode-unsigned: the trust anchor is the Ed25519
# release manifest, as on macOS and Linux. Smart App Control may block
# newtype.exe (it judges unsigned files by cloud reputation); SmartScreen may
# warn. This script does not bypass, disable or work around those protections.
#
# NEWTYPE_INSTALL_ORIGIN overrides the origin (https://..., or http:// on
# 127.0.0.1/localhost for tests).
& {
    Set-StrictMode -Version 2
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    # Windows PowerShell 5.1 may default to TLS 1.0/1.1.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {
    }

    $Origin = 'https://lic.newtype-ai.com'
    if ($env:NEWTYPE_INSTALL_ORIGIN) {
        $Origin = $env:NEWTYPE_INSTALL_ORIGIN
    }
    if (-not ($Origin -cmatch '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$' -or $Origin -cmatch '^http://(127\.0\.0\.1|localhost):[0-9]{1,5}$')) {
        throw "newtype install: NEWTYPE_INSTALL_ORIGIN must be an https:// origin"
    }

    $procArch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) {
        $procArch = $env:PROCESSOR_ARCHITEW6432
    }
    switch ($procArch) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { throw "newtype install: unsupported CPU '$procArch' (amd64 and arm64 only)" }
    }
    if (-not $env:USERPROFILE) {
        throw "newtype install: USERPROFILE is not set"
    }

    try {
        $resp = Invoke-WebRequest -UseBasicParsing -Uri ($Origin + '/v1/releases/latest.txt')
    } catch {
        throw "newtype install: no published release found at $Origin (none is published yet, or the service is unreachable)"
    }
    $meta = $resp.Content
    if ($meta -is [byte[]]) {
        $meta = [Text.Encoding]::UTF8.GetString($meta)
    }

    # Plain text only: values are matched against strict patterns, never evaluated.
    $version = $null
    $entry = $null
    foreach ($line in ($meta -split "`r?`n")) {
        if ($null -eq $version -and $line -cmatch '^version=([0-9][0-9A-Za-z.-]{0,63})$') {
            $version = $Matches[1]
        }
        if ($null -eq $entry -and $line.StartsWith("windows-$arch=")) {
            $entry = $line.Substring(("windows-$arch=").Length)
        }
    }
    if ($null -eq $version) {
        throw "newtype install: release information is malformed"
    }
    if ($null -eq $entry) {
        throw "newtype install: release $version has no build for windows/$arch"
    }
    if (-not ($entry -cmatch '^([0-9a-f]{64}) ([1-9][0-9]{0,9})$')) {
        throw "newtype install: release information is malformed"
    }
    $sum = $Matches[1]
    $size = [int64]$Matches[2]

    # The Unix layout (2026-10-05): versioned exes under ~\.local\share\newtype\bin
    # and a stable copy ~\.local\bin\newtype.exe. %LOCALAPPDATA% is not used: a
    # packaged (MSIX) app such as the Claude desktop app virtualizes it, so an
    # installer run inside one would land in the app's private storage.
    $share = Join-Path $env:USERPROFILE '.local\share\newtype\bin'
    $bin = Join-Path $env:USERPROFILE '.local\bin'
    New-Item -ItemType Directory -Force -Path $share | Out-Null
    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    $tmp = Join-Path $share ('.newtype-install-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        Write-Host "Newtype $version (windows/$arch): downloading and checking SHA-256 ..."
        try {
            Invoke-WebRequest -UseBasicParsing -Uri ($Origin + '/v1/releases/files/' + $sum) -OutFile $tmp
        } catch {
            throw "newtype install: download failed"
        }
        $gotSize = (Get-Item -LiteralPath $tmp).Length
        if ($gotSize -ne $size) {
            throw "newtype install: download has $gotSize bytes, the signed manifest says $size; nothing installed"
        }
        $gotSum = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash.ToLowerInvariant()
        if ($gotSum -ne $sum) {
            throw "newtype install: SHA-256 mismatch (got $gotSum, want $sum); nothing installed"
        }
        # Invoke-WebRequest -OutFile adds no Mark-of-the-Web, so no Unblock-File is
        # needed. Smart App Control does not depend on it and is not bypassed here.
        $target = Join-Path $share ("newtype-$version.exe")
        Move-Item -LiteralPath $tmp -Destination $target -Force
    } finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Force
        }
    }

    # newtype.exe is a copy of the versioned exe. A running newtype.exe cannot
    # be overwritten but can be renamed, so an existing one is moved aside first.
    $stable = Join-Path $bin 'newtype.exe'
    $staged = Join-Path $bin 'newtype.exe.new'
    Copy-Item -LiteralPath $target -Destination $staged -Force
    if (Test-Path -LiteralPath $stable) {
        $old = Join-Path $bin 'newtype.exe.old'
        if (Test-Path -LiteralPath $old) {
            try {
                Remove-Item -LiteralPath $old -Force
            } catch {
                $old = Join-Path $bin ('newtype.exe.old-' + [Guid]::NewGuid().ToString('N'))
            }
        }
        Move-Item -LiteralPath $stable -Destination $old
    }
    Move-Item -LiteralPath $staged -Destination $stable
    Write-Host "installed: $target"
    Write-Host "copied:    $stable"

    # USER Path only (HKCU), keeping the value's REG_EXPAND_SZ form.
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    try {
        $userPath = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $parts = @($userPath -split ';' | Where-Object { $_ -ne '' })
        # The old location (%LOCALAPPDATA%\Newtype\bin) leaves the Path; its files stay.
        $stale = $null
        if ($env:LOCALAPPDATA) {
            $stale = (Join-Path $env:LOCALAPPDATA 'Newtype\bin').TrimEnd('\')
        }
        $kept = @()
        $removed = $false
        foreach ($p in $parts) {
            if ($null -ne $stale -and [Environment]::ExpandEnvironmentVariables($p).TrimEnd('\') -ieq $stale) {
                $removed = $true
            } else {
                $kept += $p
            }
        }
        $present = $false
        foreach ($p in $kept) {
            if ([Environment]::ExpandEnvironmentVariables($p).TrimEnd('\') -ieq $bin.TrimEnd('\')) {
                $present = $true
            }
        }
        if (-not $present) {
            $kept += $bin
        }
        if ($removed -or -not $present) {
            $key.SetValue('Path', ($kept -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString)
            # Tell new terminals about the change (a no-op user variable set and removed).
            [Environment]::SetEnvironmentVariable('NEWTYPE_INSTALL_PATH_REFRESH', '1', 'User')
            [Environment]::SetEnvironmentVariable('NEWTYPE_INSTALL_PATH_REFRESH', $null, 'User')
            if (-not $present) {
                Write-Host "added $bin to your user Path (new terminals see it)"
            }
            if ($removed) {
                Write-Host "removed the old $stale entry from your user Path (its files were left in place)"
            }
        }
    } finally {
        $key.Close()
    }
    if (-not (($env:Path -split ';') -contains $bin)) {
        $env:Path = $env:Path + ';' + $bin
    }

    $blocked = $false
    try {
        $ErrorActionPreference = 'Continue'
        $out = (& $stable --version 2>&1 | ForEach-Object { "$_" }) -join ' '
        Write-Host ("check:     " + $out)
    } catch {
        $blocked = $true
    } finally {
        $ErrorActionPreference = 'Stop'
    }
    if ($blocked) {
        Write-Host ""
        Write-Host "Windows did not run newtype.exe (Smart App Control, SmartScreen or another policy)."
        Write-Host "Windows: Authenticode unsigned; Smart App Control may block it (it judges unsigned"
        Write-Host "files by cloud reputation). The download was checked against the Ed25519-signed manifest."
        Write-Host "This installer does not bypass that protection. The file is installed at $stable."
    }

    Write-Host ""
    Write-Host "Next: open a new terminal and run 'newtype'. The first run needs you: e-mail enrolment"
    Write-Host "approval, folder trust and model setup. An AI agent must stop here and hand over to the person."
}
