#Requires -Version 5.1
<#
Windows Shell ZIP acceptance, in a disposable interactive Windows test guest.
The expected IMG hash must come from an independent decoder of this same ZIP.
This tests Shell.Application, not the complete Explorer ribbon/dialog workflow.
No download, disk-device write, registry change or Explorer process termination.
#>
[CmdletBinding()]
param(
    [string]$ZipPath = '',
    [string]$ZipSha256 = '',
    [string]$ImageSha256 = '',
    [string]$WorkRoot = '',
    [ValidateRange(5, 3600)][int]$TimeoutSeconds = 900
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:ImageName = 'DebRescueStick-amd64.img'
$script:ImageSize = [long]8598323200
$script:ExplorerSha256 = ''
if ($PSCommandPath) {
    $script:ExplorerSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Convert-Sha256([string]$Value) {
    if ($Value.Length -ne 64) { throw 'A full SHA256 reference is required.' }
    foreach ($c in $Value.ToCharArray()) {
        if ('0123456789abcdefABCDEF'.IndexOf($c) -lt 0) { throw 'Invalid SHA256 reference.' }
    }
    return $Value.ToLowerInvariant()
}

function Get-StreamSha256([IO.Stream]$Stream) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($algorithm.ComputeHash($Stream)).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

function Assert-NoReparse([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if ([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
            if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Reparse points in the test path are refused.'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function Assert-ZipLayout([IO.Stream]$Stream, [long]$ExpectedBytes) {
    Add-Type -AssemblyName System.IO.Compression
    $zip = [IO.Compression.ZipArchive]::new($Stream, [IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        if ($zip.Entries.Count -ne 1 -or $zip.Entries[0].FullName -cne $script:ImageName -or
            $zip.Entries[0].Length -ne $ExpectedBytes) {
            throw 'Exactly one complete DebRescueStick IMG entry is required.'
        }
    } finally { $zip.Dispose() }
}

function Get-ImageSample([string]$Path, [long]$ExpectedBytes) {
    if (-not [IO.File]::Exists($Path)) { return @{ State = 'missing' } }
    Assert-NoReparse $Path
    $info = [IO.FileInfo]::new($Path)
    if ($info.Length -gt $ExpectedBytes) { throw 'Extracted image exceeds its expected size.' }
    if ($info.Length -lt $ExpectedBytes) { return @{ State = 'short' } }
    $stamp = $info.LastWriteTimeUtc.Ticks.ToString() + ':' + $info.Length.ToString()
    try { $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None) }
    catch [IO.IOException] { return @{ State = 'busy' } }
    try {
        if ($stream.Length -ne $ExpectedBytes) { return @{ State = 'short' } }
        $sha = Get-StreamSha256 $stream
        return @{ State = 'hashed'; Hash = $sha; Stamp = $stamp; Bytes = $stream.Length }
    } finally { $stream.Dispose() }
}

function Wait-ShellImage {
    param([string]$ExpectedHash, [scriptblock]$Observe, [scriptblock]$Expired,
          [scriptblock]$Pause = { Start-Sleep -Milliseconds 250 })
    $attempts = 0
    while (-not (& $Expired)) {
        $sample = & $Observe
        if ($sample.State -eq 'hashed') {
            $attempts++
            if ($sample.Hash -eq $ExpectedHash) {
                if (& $Expired) { break }
                return @{ Hash = $sample.Hash; Bytes = $sample.Bytes; HashAttempts = $attempts }
            }
            if ($attempts -ge 3) { throw ('Three complete unlocked images failed SHA256: ' + $sample.Hash) }
        } elseif ($sample.State -notin @('missing', 'short', 'busy')) {
            throw 'Unknown extraction observation; success refused.'
        }
        & $Pause
    }
    throw 'Shell extraction timed out without a complete matching image.'
}

function Remove-OwnRun([string]$RunRoot, [string]$RunId) {
    if ($RunId.Length -ne 32) { throw 'Exact run ID required for cleanup.' }
    foreach ($c in $RunId.ToCharArray()) {
        if ('0123456789abcdef'.IndexOf($c) -lt 0) { throw 'Invalid cleanup run ID.' }
    }
    $full = [IO.Path]::GetFullPath($RunRoot)
    if ([IO.Path]::GetFileName($full) -cne $RunId) { throw 'Foreign run directory preserved.' }
    Assert-NoReparse $full
    $owner = [IO.File]::ReadAllText([IO.Path]::Combine($full, '.owner')) | ConvertFrom-Json
    if ($owner.schema -ne 'debrescuestick-explorer-v1' -or $owner.id -cne $RunId) {
        throw 'Foreign run marker preserved.'
    }
    $expanded = [IO.Path]::Combine($full, 'expanded')
    $image = [IO.Path]::Combine($expanded, $script:ImageName)
    $archive = [IO.Path]::Combine($full, 'image.zip')
    $allowed = @('.owner', 'image.zip', 'expanded')
    foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($full)) {
        if ([IO.Path]::GetFileName($path) -cnotin $allowed) { throw 'Unexpected run artifact preserved.' }
        Assert-NoReparse $path
        if (([IO.Path]::GetFileName($path) -ceq 'expanded') -ne [IO.Directory]::Exists($path)) {
            throw 'Unexpected artifact type preserved.'
        }
    }
    if ([IO.Directory]::Exists($expanded)) {
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($expanded)) {
            if ($path -cne $image -or -not [IO.File]::Exists($path)) { throw 'Unexpected extracted artifact preserved.' }
            Assert-NoReparse $path
        }
    }
    # Only individual known files and empty own directories; never recursive deletion.
    foreach ($path in @($image, $archive)) {
        if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
    }
    if ([IO.Directory]::Exists($expanded)) { [IO.Directory]::Delete($expanded, $false) }
    [IO.File]::Delete([IO.Path]::Combine($full, '.owner'))
    [IO.Directory]::Delete($full, $false)
}

function Invoke-ExplorerCheck {
    param([string]$ZipPath, [string]$ZipSha256, [string]$ImageSha256,
          [string]$WorkRoot = '', [int]$TimeoutSeconds = 900, [switch]$AsObject)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Native Windows is required.' }
    if (-not [Environment]::UserInteractive -or
        [Threading.Thread]::CurrentThread.ApartmentState -ne [Threading.ApartmentState]::STA) {
        throw 'An interactive Windows STA session is required; use powershell.exe -STA.'
    }
    $zipHash = Convert-Sha256 $ZipSha256
    $imageHash = Convert-Sha256 $ImageSha256
    if (-not $ZipPath) { throw 'An existing completed ZIP download is required.' }
    $sourcePath = [IO.Path]::GetFullPath($ZipPath)
    $sourceInfo = [IO.FileInfo]::new($sourcePath)
    if (-not $sourceInfo.Exists -or $sourceInfo.Length -le 0 -or $sourceInfo.Length -gt 1400MB) {
        throw 'Expected a bounded local ZIP download (at most 1400 MiB).'
    }
    if (-not $WorkRoot) {
        $WorkRoot = [IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'), 'DebRescueStick', 'ExplorerTests')
    }
    $work = [IO.Path]::GetFullPath($WorkRoot)
    Assert-NoReparse $work
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($work))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -notin @('NTFS', 'ReFS', 'exFAT') -or
        $drive.AvailableFreeSpace -lt ($script:ImageSize + $sourceInfo.Length + 1GB)) {
        throw 'A local large-file volume with space for ZIP, IMG and 1 GiB reserve is required.'
    }
    $id = [Guid]::NewGuid().ToString('N')
    [void][IO.Directory]::CreateDirectory($work)
    $run = [IO.Path]::Combine($work, $id)
    $reportPath = [IO.Path]::Combine($work, $id + '.json')
    if ([IO.File]::Exists($reportPath)) { throw 'Existing report preserved.' }
    $null = New-Item -ItemType Directory -Path $run -ErrorAction Stop
    [IO.File]::WriteAllText([IO.Path]::Combine($run, '.owner'), (@{ schema = 'debrescuestick-explorer-v1'; id = $id } | ConvertTo-Json -Compress))
    $report = [ordered]@{ scope = 'windows-shell-zip'; success = $false; runId = $id;
        nativeShellExecuted = $false; explorerUiTested = $false; dataVerified = $false;
        cleanupComplete = $false; mayStillBeCopying = $false; zipSha256 = $zipHash;
        expectedImageSha256 = $imageHash; expectedBytes = $script:ImageSize;
        powershell = $PSVersionTable.PSVersion.ToString(); processBits = [IntPtr]::Size * 8 }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $locked = $null; $shell = $null; $sourceFolder = $null; $targetFolder = $null; $items = $null
    try {
        $registry = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
        try { $report.os = @{ product = $registry.GetValue('ProductName'); build = $registry.GetValue('CurrentBuildNumber'); revision = $registry.GetValue('UBR') } }
        finally { $registry.Dispose() }
        $zipPath = [IO.Path]::Combine($run, 'image.zip')
        $inputStream = [IO.File]::Open($sourcePath, 'Open', 'Read', 'Read')
        try {
            $outputStream = [IO.File]::Open($zipPath, 'CreateNew', 'Write', 'None')
            try { $inputStream.CopyTo($outputStream, 1MB) } finally { $outputStream.Dispose() }
        } finally { $inputStream.Dispose() }
        $locked = [IO.File]::Open($zipPath, 'Open', 'Read', 'Read')
        if ((Get-StreamSha256 $locked) -ne $zipHash) { throw 'Downloaded ZIP SHA256 does not match its reference.' }
        $locked.Position = 0
        Assert-ZipLayout $locked $script:ImageSize
        if ($clock.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw 'Input verification exceeded the deadline.' }
        $expanded = [IO.Path]::Combine($run, 'expanded')
        [void][IO.Directory]::CreateDirectory($expanded)
        $shell = New-Object -ComObject Shell.Application
        $sourceFolder = $shell.NameSpace($zipPath); $targetFolder = $shell.NameSpace($expanded)
        if ($null -eq $sourceFolder -or $null -eq $targetFolder) { throw 'Windows compressed-folder namespace unavailable.' }
        $items = $sourceFolder.Items()
        if ($items.Count -ne 1) { throw 'Shell namespace does not contain exactly one image.' }
        $report.nativeShellExecuted = $true; $report.mayStillBeCopying = $true
        $targetFolder.CopyHere($items, 4 + 16 + 512 + 1024)
        $path = [IO.Path]::Combine($expanded, $script:ImageName)
        $verified = Wait-ShellImage $imageHash { Get-ImageSample $path $script:ImageSize } {
            $clock.Elapsed.TotalSeconds -ge $TimeoutSeconds
        }
        $report.observedImageSha256 = $verified.Hash; $report.observedBytes = $verified.Bytes
        $report.hashAttempts = $verified.HashAttempts; $report.dataVerified = $true
        $report.mayStillBeCopying = $false
    } catch { $report.error = $_.Exception.Message }
    finally {
        foreach ($obj in @($items, $targetFolder, $sourceFolder, $shell)) {
            if ($null -ne $obj -and [Runtime.InteropServices.Marshal]::IsComObject($obj)) {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($obj)
            }
        }
        if ($null -ne $locked) { $locked.Dispose() }
        if (-not $report.mayStillBeCopying) {
            try { Remove-OwnRun $run $id; $report.cleanupComplete = $true }
            catch { $report.cleanupError = $_.Exception.Message }
        }
        $report.success = $report.dataVerified -and $report.cleanupComplete
        $report.elapsedSeconds = $clock.Elapsed.TotalSeconds
        $report.scriptSha256 = $script:ExplorerSha256
        $json = $report | ConvertTo-Json -Depth 6
        $resultFile = [IO.File]::Open($reportPath, 'CreateNew', 'Write', 'None')
        try {
            $encoded = [Text.Encoding]::UTF8.GetBytes($json + [Environment]::NewLine)
            $resultFile.Write($encoded, 0, $encoded.Length)
        } finally { $resultFile.Dispose() }
    }
    if ($AsObject) { return [pscustomobject]$report }
    [Console]::WriteLine($json)
    if (-not $report.success) { return 1 }
    return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    try { exit (Invoke-ExplorerCheck @PSBoundParameters) }
    catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
}
