#Requires -Version 5.1
param([Parameter(Mandatory = $true)][string]$FixtureRoot)
$ErrorActionPreference = 'Stop'
$cases = [Collections.Generic.List[string]]::new()
function Assert-Check([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw ('Fixture failed: ' + $Name) }
}
function Assert-Throws([scriptblock]$Action, [string]$Name) {
    $thrown = $false
    try { $null = & $Action } catch { $thrown = $true }
    Assert-Check $thrown $Name
}
[void][IO.Directory]::CreateDirectory($FixtureRoot)
$file = [IO.Path]::Combine($FixtureRoot, 'sample.bin')
[IO.File]::WriteAllBytes($file, [Text.Encoding]::ASCII.GetBytes('abc'))
$sha = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
Assert-Check ((Convert-Sha256 $sha.ToUpperInvariant()) -ceq $sha) 'hash normalization'
foreach ($bad in @('', 'a', ('g' * 64), ('a' * 63 + '/'))) {
    Assert-Throws { Convert-Sha256 $bad } 'bad reference rejected'
}
$sample = Get-ImageSample $file 3
Assert-Check ($sample.State -eq 'hashed' -and $sample.Hash -eq $sha -and $sample.Bytes -eq 3) 'streaming known SHA'
Assert-Check ((Get-ImageSample $file 4).State -eq 'short') 'short file not complete'
Assert-Check ((Get-ImageSample ([IO.Path]::Combine($FixtureRoot, 'absent')) 3).State -eq 'missing') 'missing file not complete'
Assert-Throws { Get-ImageSample $file 2 } 'oversized file rejected'
$cases.Add('hashes-and-lengths')

$held = [IO.File]::Open($file, 'Open', 'ReadWrite', 'None')
try { Assert-Check ((Get-ImageSample $file 3).State -eq 'busy') 'writer lock prevents false completion' }
finally { $held.Dispose() }
Assert-Check ((Get-ImageSample $file 3).Hash -eq $sha) 'progress after lock release'
[IO.File]::WriteAllBytes($file, [Text.Encoding]::ASCII.GetBytes('bad'))
$fixedTime = [DateTime]::new(2001, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
[IO.File]::SetLastWriteTimeUtc($file, $fixedTime)
$verified = Wait-ShellImage $sha { Get-ImageSample $file 3 } { $false } {
    [IO.File]::WriteAllBytes($file, [Text.Encoding]::ASCII.GetBytes('abc'))
    [IO.File]::SetLastWriteTimeUtc($file, $fixedTime)
}
Assert-Check ($verified.Hash -eq $sha -and $verified.HashAttempts -eq 2) 'same metadata cannot freeze correct progress'
$cases.Add('real-lock-and-unchanged-metadata')

$observations = [Collections.Queue]::new()
foreach ($state in @('missing', 'short', 'busy')) { $observations.Enqueue(@{ State = $state }) }
$observations.Enqueue(@{ State = 'hashed'; Hash = ('0' * 64); Stamp = 'same'; Bytes = 3 })
$observations.Enqueue(@{ State = 'hashed'; Hash = $sha; Stamp = 'same'; Bytes = 3 })
$verified = Wait-ShellImage $sha { $observations.Dequeue() } { $false } { }
Assert-Check ($verified.Hash -eq $sha -and $verified.HashAttempts -eq 2 -and $observations.Count -eq 0) 'progress after asynchronous and unchanged-metadata samples'
$cases.Add('asynchronous-forward-progress')
Assert-Throws { Wait-ShellImage $sha { @{ State = 'busy' } } { $true } { } } 'permanent busy times out'
Assert-Throws { Wait-ShellImage $sha { @{ State = 'hashed'; Hash = ('0' * 64); Bytes = 3 } } { $false } { } } 'persistent mismatch bounded'
Assert-Throws { Wait-ShellImage $sha { @{ State = 'invented-success' } } { $false } { } } 'unknown observation refused'
$deadline = [Collections.Queue]::new(); $deadline.Enqueue($false); $deadline.Enqueue($true)
Assert-Throws { Wait-ShellImage $sha { @{ State = 'hashed'; Hash = $sha; Bytes = 3 } } { $deadline.Dequeue() } { } } 'hash arriving after deadline not passed'
$cases.Add('timeouts-and-false-green-refusal')

$zipPath = [IO.Path]::Combine($FixtureRoot, 'tiny.zip')
function New-TinyZip([string]$EntryName, [bool]$Extra = $false) {
    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::Open($zipPath, 'Create', 'ReadWrite', 'None')
    try {
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            $entry = $archive.CreateEntry($EntryName); $data = $entry.Open()
            try { $data.WriteByte(42) } finally { $data.Dispose() }
            if ($Extra) { $null = $archive.CreateEntry('extra') }
        } finally { $archive.Dispose() }
    } finally { $stream.Dispose() }
}
function Check-TinyZip {
    $stream = [IO.File]::OpenRead($zipPath)
    try { Assert-ZipLayout $stream 1 } finally { $stream.Dispose() }
}
New-TinyZip 'DebRescueStick-amd64.img'; Check-TinyZip
$stream = [IO.File]::OpenRead($zipPath)
try { Assert-Throws { Assert-ZipLayout $stream 2 } 'wrong uncompressed length refused' }
finally { $stream.Dispose() }
New-TinyZip '../DebRescueStick-amd64.img'; Assert-Throws { Check-TinyZip } 'traversal entry refused'
New-TinyZip 'DebRescueStick-amd64.img' $true; Assert-Throws { Check-TinyZip } 'multiple entries refused'
$cases.Add('zip-layout-validation')

$id = 'a' * 32; $own = [IO.Path]::Combine($FixtureRoot, $id)
[void][IO.Directory]::CreateDirectory($own)
$marker = [IO.Path]::Combine($own, '.owner')
[IO.File]::WriteAllText($marker, (@{ schema = 'debrescuestick-explorer-v1'; id = $id } | ConvertTo-Json))
$extra = [IO.Path]::Combine($own, 'foreign.txt'); [IO.File]::WriteAllText($extra, 'preserve me')
Assert-Throws { Remove-OwnRun $own $id } 'foreign child prevents cleanup'
Assert-Check ([IO.File]::ReadAllText($extra) -ceq 'preserve me') 'foreign child unchanged'
foreach ($bad in @('', '..', '/', ('a' * 31), ('a' * 31 + '/'))) {
    Assert-Throws { Remove-OwnRun $own $bad } 'invalid cleanup ID refused'
}
[IO.File]::Delete($extra)
$wrongType = [IO.Path]::Combine($own, 'image.zip')
[void][IO.Directory]::CreateDirectory($wrongType)
Assert-Throws { Remove-OwnRun $own $id } 'unexpected artifact type preserved'
Assert-Check ([IO.File]::Exists($marker)) 'invalid cleanup preserves owner marker'
[IO.Directory]::Delete($wrongType, $false)
Remove-OwnRun $own $id
Assert-Check (-not [IO.Directory]::Exists($own)) 'own empty run cleaned'
$cases.Add('nonrecursive-owned-cleanup')

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    $never = [IO.Path]::Combine($FixtureRoot, 'never-create')
    Assert-Throws { Invoke-ExplorerCheck -WorkRoot $never } 'non-Windows entry refused'
    Assert-Check (-not [IO.Directory]::Exists($never)) 'host refusal precedes disk work'
    $cases.Add('non-windows-refusal')
}
[Console]::WriteLine((@{ success = $true; scope = 'portable-powershell-fixtures';
    nativeWindowsTested = $false; explorerUiTested = $false;
    powershell = $PSVersionTable.PSVersion.ToString(); cases = @($cases.ToArray()) } | ConvertTo-Json -Depth 4 -Compress))
