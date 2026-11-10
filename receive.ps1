#Requires -Version 5.1
<# VM payload entry point. Only this exact manifest's ZIP may be downloaded. #>
[CmdletBinding()]
param([string]$ManifestPath = '', [string]$ManifestSha256 = '',
      [string]$WorkRoot = '', [string]$ReportPath = '')
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:ReceiveSha256 = ''
if ($PSCommandPath) {
    $script:ReceiveSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-HexIdentity([string]$Value, [int]$Length) {
    if ($Value.Length -ne $Length) { throw 'Invalid handoff identity length.' }
    foreach ($c in $Value.ToCharArray()) {
        if ('0123456789abcdef'.IndexOf($c) -lt 0) { throw 'Invalid handoff identity.' }
    }
}

function Assert-Handoff($Manifest, [long]$Now) {
    if ($Manifest.schema -cne 'drs-windows-handoff-v1') { throw 'Unknown handoff schema.' }
    Assert-HexIdentity $Manifest.id 32
    Assert-HexIdentity $Manifest.archive.job 48
    foreach ($sha in @($Manifest.archive.sha256, $Manifest.image.sha256,
                       $Manifest.image.template_sha256, $Manifest.reference_sha256,
                       $Manifest.scripts.'explorer.ps1', $Manifest.scripts.'receive.ps1')) {
        Assert-HexIdentity $sha 64
    }
    $url = 'https://eorls.com/debrescuestick/download/' + $Manifest.archive.job
    if ($Manifest.archive.url -cne $url) { throw 'Only the exact public request URL is accepted.' }
    if ($Manifest.archive.bytes -le 0 -or $Manifest.archive.bytes -ge 1400MB -or
        $Manifest.image.bytes -ne 8598323200 -or $Manifest.image.name -cne 'DebRescueStick-amd64.img') {
        throw 'Archive or IMG bounds differ from the qualified image.'
    }
    if ($Manifest.download_timeout -ne 300 -or $Manifest.check_timeout -ne 900 -or
        $Manifest.created -gt $Now -or $Manifest.expires - $Now -lt 1260) {
        throw 'Handoff is stale or has insufficient remaining download/test time.'
    }
}

function Save-ArchiveResponse {
    param($Response, [string]$Target, [long]$ExpectedBytes, [string]$ExpectedHash,
          [Threading.CancellationToken]$Cancellation = [Threading.CancellationToken]::None,
          [ValidateRange(1, 1048576)][int]$BufferBytes = 1048576)
    if ([int]$Response.StatusCode -ne 200 -or $Response.Content.Headers.ContentLength -ne $ExpectedBytes) {
        throw 'Download status/length does not match the bound archive.'
    }
    $part = $Target + '.part'; $created = $false; $source = $null; $output = $null
    try {
        $Cancellation.ThrowIfCancellationRequested()
        $source = $Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $output = [IO.File]::Open($part, 'CreateNew', 'Write', 'None'); $created = $true
        $buffer = [byte[]]::new($BufferBytes); $count = [long]0
        while ($true) {
            $Cancellation.ThrowIfCancellationRequested()
            $n = $source.ReadAsync($buffer, 0, $buffer.Length, $Cancellation).GetAwaiter().GetResult()
            if ($n -eq 0) { break }
            $count += $n
            if ($count -gt $ExpectedBytes) { throw 'Download exceeds its exact bound.' }
            $output.Write($buffer, 0, $n)
        }
        if ($count -ne $ExpectedBytes) { throw 'Truncated ZIP download.' }
        $output.Dispose(); $output = $null
        $stream = [IO.File]::OpenRead($part)
        try { $observed = Get-StreamSha256 $stream } finally { $stream.Dispose() }
        if ($observed -cne $ExpectedHash) { throw 'Downloaded ZIP SHA256 differs.' }
        [IO.File]::Move($part, $Target)
        $created = $false
        return @{ Bytes = $count; Hash = $observed }
    } finally {
        if ($null -ne $source) { $source.Dispose() }
        if ($null -ne $output) { $output.Dispose() }
        if ($created -and [IO.File]::Exists($part)) { [IO.File]::Delete($part) }
    }
}

function Assert-CheckerResult($Result, $Manifest) {
    foreach ($flag in @('success', 'dataVerified', 'cleanupComplete', 'nativeShellExecuted')) {
        if ($Result.$flag -isnot [bool] -or -not $Result.$flag) { throw 'Incomplete native Shell result.' }
    }
    if ($Result.scope -cne 'windows-shell-zip' -or $Result.explorerUiTested -isnot [bool] -or
        $Result.explorerUiTested -or $Result.scriptSha256 -cne $Manifest.scripts.'explorer.ps1' -or
        $Result.zipSha256 -cne $Manifest.archive.sha256 -or
        $Result.expectedImageSha256 -cne $Manifest.image.sha256 -or
        $Result.observedImageSha256 -cne $Manifest.image.sha256 -or
        $Result.observedBytes -ne $Manifest.image.bytes) {
        throw 'Native result is not bound to this exact request and checker.'
    }
    Assert-HexIdentity $Result.runId 32
}

function Remove-ReceiveRun([string]$RunRoot, [string]$Id, [string]$CheckerId = '') {
    Assert-HexIdentity $Id 32
    $root = [IO.Path]::GetFullPath($RunRoot)
    if ([IO.Path]::GetFileName($root) -cne $Id) { throw 'Foreign receive directory preserved.' }
    Assert-NoReparse $root
    $marker = [IO.Path]::Combine($root, '.owner')
    $owner = [IO.File]::ReadAllText($marker) | ConvertFrom-Json
    if ($owner.schema -cne 'drs-receive-v1' -or $owner.id -cne $Id) { throw 'Foreign receive owner preserved.' }
    $checker = [IO.Path]::Combine($root, 'checker')
    foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($root)) {
        $name = [IO.Path]::GetFileName($path)
        if ($name -cnotin @('.owner', 'image.zip', 'image.zip.part', 'checker')) { throw 'Unknown receive artifact preserved.' }
        Assert-NoReparse $path
        if (($name -ceq 'checker') -ne [IO.Directory]::Exists($path)) { throw 'Unknown receive artifact type preserved.' }
    }
    $nativeReceipt = ''
    if ($CheckerId) {
        Assert-HexIdentity $CheckerId 32
        $nativeReceipt = [IO.Path]::Combine($checker, $CheckerId + '.json')
    }
    if ([IO.Directory]::Exists($checker)) {
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($checker)) {
            if (-not $nativeReceipt -or $path -cne $nativeReceipt -or -not [IO.File]::Exists($path)) {
                throw 'Unfinished checker artifacts preserved.'
            }
            Assert-NoReparse $path
        }
    }
    foreach ($name in @('image.zip', 'image.zip.part')) {
        $path = [IO.Path]::Combine($root, $name)
        if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
    }
    if ($nativeReceipt -and [IO.File]::Exists($nativeReceipt)) { [IO.File]::Delete($nativeReceipt) }
    if ([IO.Directory]::Exists($checker)) { [IO.Directory]::Delete($checker, $false) }
    [IO.File]::Delete($marker); [IO.Directory]::Delete($root, $false)
}

function Invoke-Receive {
    param([string]$ManifestPath, [string]$ManifestSha256, [string]$WorkRoot = '', [string]$ReportPath = '')
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Native Windows guest required.' }
    if (-not [Environment]::UserInteractive -or
        [Threading.Thread]::CurrentThread.ApartmentState -ne [Threading.ApartmentState]::STA) {
        throw 'Interactive Windows STA session required.'
    }
    # Dot-sourcing the checker defines its parameters too; preserve our own options.
    $receiverOptions = @{ WorkRoot = $WorkRoot; ReportPath = $ReportPath }
    Assert-HexIdentity $ManifestSha256 64
    $manifestFile = [IO.Path]::GetFullPath($ManifestPath)
    if (([IO.FileInfo]::new($manifestFile)).Length -gt 16384 -or
        (Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha256) {
        throw 'Manifest bytes do not match the staged launcher.'
    }
    $manifest = [IO.File]::ReadAllText($manifestFile) | ConvertFrom-Json
    Assert-Handoff $manifest ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    if ($script:ReceiveSha256 -cne $manifest.scripts.'receive.ps1') { throw 'Executing receiver differs from the staged manifest.' }
    $stage = [IO.Path]::GetDirectoryName($manifestFile)
    foreach ($name in @('explorer.ps1', 'receive.ps1')) {
        $path = [IO.Path]::Combine($stage, $name)
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.scripts.$name) {
            throw 'Staged script bytes differ from the manifest.'
        }
    }
    . ([IO.Path]::Combine($stage, 'explorer.ps1'))
    $work = $receiverOptions.WorkRoot
    if (-not $work) { $work = [IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'), 'DebRescueStick', 'Receive') }
    $work = [IO.Path]::GetFullPath($work); Assert-NoReparse $work
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($work))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -notin @('NTFS', 'ReFS', 'exFAT') -or
        $drive.AvailableFreeSpace -lt ($manifest.image.bytes + 2 * $manifest.archive.bytes + 1GB)) {
        throw 'Insufficient local large-file test space.'
    }
    [void][IO.Directory]::CreateDirectory($work)
    $reportFile = $receiverOptions.ReportPath
    if (-not $reportFile) { $reportFile = [IO.Path]::Combine($work, $manifest.id + '.json') }
    $reportFile = [IO.Path]::GetFullPath($reportFile)
    if ([IO.File]::Exists($reportFile) -or -not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($reportFile))) {
        throw 'Existing report preserved or report parent missing.'
    }
    $run = [IO.Path]::Combine($work, $manifest.id)
    $null = New-Item -ItemType Directory -Path $run -ErrorAction Stop
    [IO.File]::WriteAllText([IO.Path]::Combine($run, '.owner'), (@{ schema = 'drs-receive-v1'; id = $manifest.id } | ConvertTo-Json))
    $report = [ordered]@{ scope = 'windows-shell-handoff'; success = $false; manifestSha256 = $ManifestSha256;
        handoffId = $manifest.id; nativeWindowsTested = $false; explorerUiTested = $false;
        cleanupComplete = $false; downloadVerified = $false }
    $client = $null; $response = $null; $cancel = $null; $handler = $null
    $nativeStarted = $false; $checkerId = ''
    try {
        Add-Type -AssemblyName System.Net.Http
        $handler = [Net.Http.HttpClientHandler]::new(); $handler.AllowAutoRedirect = $false; $handler.UseProxy = $false
        $client = [Net.Http.HttpClient]::new($handler)
        $cancel = [Threading.CancellationTokenSource]::new(); $cancel.CancelAfter(300000)
        $response = $client.GetAsync($manifest.archive.url, [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
                                     $cancel.Token).GetAwaiter().GetResult()
        $download = [IO.Path]::Combine($run, 'image.zip')
        $copied = Save-ArchiveResponse $response $download $manifest.archive.bytes $manifest.archive.sha256 $cancel.Token
        $report.downloadVerified = $true; $report.downloadBytes = $copied.Bytes
        $response.Dispose(); $response = $null; $client.Dispose(); $client = $null
        if ($manifest.expires - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt 960) {
            throw 'Download finished too close to expiry for checker execution.'
        }
        $nativeStarted = $true
        $native = Invoke-ExplorerCheck -ZipPath $download -ZipSha256 $manifest.archive.sha256 `
            -ImageSha256 $manifest.image.sha256 -WorkRoot ([IO.Path]::Combine($run, 'checker')) `
            -TimeoutSeconds 900 -AsObject
        $report.checker = $native
        Assert-CheckerResult $native $manifest
        $checkerId = $native.runId
        Remove-ReceiveRun $run $manifest.id $checkerId
        $report.cleanupComplete = $true; $report.nativeWindowsTested = $true; $report.success = $true
    } catch { $report.error = $_.Exception.Message }
    finally {
        foreach ($item in @($response, $client, $cancel)) { if ($null -ne $item) { $item.Dispose() } }
        if (-not $nativeStarted -and -not $report.cleanupComplete) {
            try { Remove-ReceiveRun $run $manifest.id; $report.cleanupComplete = $true }
            catch { $report.cleanupError = $_.Exception.Message }
        }
        $json = $report | ConvertTo-Json -Depth 10
        $file = [IO.File]::Open($reportFile, 'CreateNew', 'Write', 'None')
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($json + [Environment]::NewLine)
            $file.Write($bytes, 0, $bytes.Length)
        } finally { $file.Dispose() }
    }
    [Console]::WriteLine($json)
    if (-not $report.success) { return 1 }
    return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    try { exit (Invoke-Receive @PSBoundParameters) }
    catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
}
