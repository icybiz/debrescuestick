#Requires -Version 5.1
param([Parameter(Mandatory = $true)][string]$FixtureRoot)
$ErrorActionPreference = 'Stop'
$receiverCases = [Collections.Generic.List[string]]::new()
function Assert-Check([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw ('Receiver fixture failed: ' + $Name) }
}
function Assert-Throws([scriptblock]$Action, [string]$Name) {
    $thrown = $false
    try { $null = & $Action } catch { $thrown = $true }
    Assert-Check $thrown $Name
}
function New-HandoffFixture {
    return (@{ schema = 'drs-windows-handoff-v1'; id = ('a' * 32); created = 100; expires = 7300;
        download_timeout = 300; check_timeout = 900; reference_sha256 = ('b' * 64);
        archive = @{ job = ('c' * 48); url = ('https://eorls.com/debrescuestick/download/' + 'c' * 48);
                     sha256 = ('d' * 64); bytes = 100 };
        image = @{ name = 'DebRescueStick-amd64.img'; sha256 = ('e' * 64); bytes = [long]8598323200; template_sha256 = ('f' * 64) };
        scripts = @{ 'explorer.ps1' = ('1' * 64); 'receive.ps1' = ('2' * 64) }
    } | ConvertTo-Json -Depth 5 | ConvertFrom-Json)
}
$manifest = New-HandoffFixture; Assert-Handoff $manifest 200
foreach ($bad in @('https://evil.invalid/file', ($manifest.archive.url + '?extra=1'))) {
    $candidate = New-HandoffFixture; $candidate.archive.url = $bad
    Assert-Throws { Assert-Handoff $candidate 200 } 'wrong URL refused'
}
$candidate = New-HandoffFixture; $candidate.expires = 201
Assert-Throws { Assert-Handoff $candidate 200 } 'stale handoff refused'
$candidate = New-HandoffFixture; $candidate.image.bytes = 3
Assert-Throws { Assert-Handoff $candidate 200 } 'tiny fixture cannot be native image'
$candidate = New-HandoffFixture; $candidate.scripts.'receive.ps1' = 'bad'
Assert-Throws { Assert-Handoff $candidate 200 } 'script identity required'
$receiverCases.Add('fresh-bound-handoff')

Add-Type -AssemblyName System.Net.Http
[void][IO.Directory]::CreateDirectory($FixtureRoot)
$target = [IO.Path]::Combine($FixtureRoot, 'download.zip')
$data = [Text.Encoding]::ASCII.GetBytes('abc')
$hash = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
function New-ResponseFixture([int]$Status = 200, [long]$Length = 3) {
    $reply = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]$Status)
    $reply.Content = [Net.Http.ByteArrayContent]::new($data)
    $reply.Content.Headers.ContentLength = $Length
    return $reply
}
$reply = New-ResponseFixture
try { $copied = Save-ArchiveResponse $reply $target 3 $hash -BufferBytes 1 }
finally { $reply.Dispose() }
Assert-Check ($copied.Bytes -eq 3 -and $copied.Hash -eq $hash -and [IO.File]::ReadAllText($target) -ceq 'abc') 'short reads preserve exact download'
[IO.File]::Delete($target)
foreach ($mode in @('redirect', 'bad-header', 'truncated', 'oversized', 'hash', 'cancelled')) {
    $reply = New-ResponseFixture; $expectedLength = [long]3; $expectedHash = $hash
    $cancellation = [Threading.CancellationTokenSource]::new()
    switch ($mode) {
        'redirect' { $reply.StatusCode = [Net.HttpStatusCode]::Redirect }
        'bad-header' { $reply.Content.Headers.ContentLength = 99 }
        'truncated' { $expectedLength = 4; $reply.Content.Headers.ContentLength = 4 }
        'oversized' { $expectedLength = 2; $reply.Content.Headers.ContentLength = 2 }
        'hash' { $expectedHash = '0' * 64 }
        'cancelled' { $cancellation.Cancel() }
    }
    try { Assert-Throws { Save-ArchiveResponse $reply $target $expectedLength $expectedHash $cancellation.Token -BufferBytes 1 } $mode }
    finally { $reply.Dispose(); $cancellation.Dispose() }
    Assert-Check (-not [IO.File]::Exists($target) -and -not [IO.File]::Exists($target + '.part')) 'failed download leaves no own partial'
}
[IO.File]::WriteAllText($target, 'foreign')
$reply = New-ResponseFixture
try { Assert-Throws { Save-ArchiveResponse $reply $target 3 $hash } 'existing target preserved' }
finally { $reply.Dispose() }
Assert-Check ([IO.File]::ReadAllText($target) -ceq 'foreign') 'existing data unchanged'
[IO.File]::Delete($target)
$receiverCases.Add('bounded-download-and-reference-sha')

$native = @{ success = $true; dataVerified = $true; cleanupComplete = $true; nativeShellExecuted = $true;
             scope = 'windows-shell-zip'; explorerUiTested = $false; scriptSha256 = ('1' * 64);
             zipSha256 = ('d' * 64); expectedImageSha256 = ('e' * 64); observedImageSha256 = ('e' * 64);
             observedBytes = [long]8598323200; runId = ('3' * 32) } | ConvertTo-Json | ConvertFrom-Json
Assert-CheckerResult $native $manifest
$native.success = 'true'; Assert-Throws { Assert-CheckerResult $native $manifest } 'string is not proof'; $native.success = $true
$native.observedImageSha256 = '0' * 64; Assert-Throws { Assert-CheckerResult $native $manifest } 'other IMG refused'; $native.observedImageSha256 = 'e' * 64
$native.explorerUiTested = $true; Assert-Throws { Assert-CheckerResult $native $manifest } 'unsupported GUI claim refused'; $native.explorerUiTested = $false
$receiverCases.Add('bound-checker-report')

$own = [IO.Path]::Combine($FixtureRoot, $manifest.id)
[void][IO.Directory]::CreateDirectory($own)
$marker = [IO.Path]::Combine($own, '.owner')
[IO.File]::WriteAllText($marker, (@{ schema = 'drs-receive-v1'; id = $manifest.id } | ConvertTo-Json))
$foreign = [IO.Path]::Combine($own, 'foreign'); [IO.File]::WriteAllText($foreign, 'leave')
Assert-Throws { Remove-ReceiveRun $own $manifest.id } 'foreign artifact refused'
Assert-Check ([IO.File]::ReadAllText($foreign) -ceq 'leave') 'foreign artifact intact'
[IO.File]::Delete($foreign)
Remove-ReceiveRun $own $manifest.id
Assert-Check (-not [IO.Directory]::Exists($own)) 'own receive cleaned'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Assert-Throws { Invoke-Receive } 'no native run on Linux'
}
$receiverCases.Add('receive-owned-cleanup')
[Console]::WriteLine((@{ success = $true; scope = 'portable-powershell-fixtures'; nativeWindowsTested = $false;
    explorerUiTested = $false; powershell = $PSVersionTable.PSVersion.ToString(); cases = @($receiverCases.ToArray()) } | ConvertTo-Json -Compress))
