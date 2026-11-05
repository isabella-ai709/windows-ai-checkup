Set-StrictMode -Version Latest

function Get-BlockedRoots {
    return @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
             (Join-Path $env:SystemRoot 'System32'), "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop")
}

function Test-UnderPath([string]$Child, [string]$Parent) {
    if (-not $Parent) { return $false }
    $c = $Child.TrimEnd('\'); $p = $Parent.TrimEnd('\')
    return $c.Equals($p, [StringComparison]::OrdinalIgnoreCase) -or
           $c.StartsWith($p + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Get-SystemOnlyRoots {
    # Restore targets must never land inside these: no cache cleanup ever legitimately
    # quarantined a file here. Documents/Desktop are allowed, unlike for cleanup targets,
    # because some caches really do live under a user profile.
    return @($env:SystemRoot, ${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:ProgramData,
             (Join-Path $env:SystemRoot 'System32'))
}

function Assert-CleanupTarget([string]$Path, [string]$QuarantineRoot) {
    if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw '路径不是绝对路径。' }
    # GetFullPath also collapses "..": a raw prefix test on "root\..\..\x" would pass while
    # the actual target sits somewhere else entirely. Separators get normalized on the way.
    $Path = [IO.Path]::GetFullPath(($Path -replace '/', '\'))
    $QuarantineRoot = [IO.Path]::GetFullPath(($QuarantineRoot -replace '/', '\'))
    if ($Path.StartsWith('\\')) { throw '拒绝网络路径。' }
    if (-not (Test-Path -LiteralPath $Path)) { throw '路径不存在。' }
    $root = [IO.Path]::GetPathRoot($Path).TrimEnd('\')
    if ($Path.TrimEnd('\').Equals($root, [StringComparison]::OrdinalIgnoreCase)) { throw '拒绝整盘根目录。' }
    foreach ($blocked in (Get-BlockedRoots)) {
        if ($blocked -and (Test-UnderPath $Path $blocked)) { throw '目标位于系统或用户文档目录。' }
    }
    if (Test-UnderPath $QuarantineRoot $Path) { throw '拒绝把父目录移入其自身子目录。' }
    $attrs = [IO.File]::GetAttributes($Path)
    if ((([int]$attrs) -band 0x441400) -ne 0) { throw '目标是联接、符号链接、离线项或云端占位项。' }
    # Callers must use the normalized form for the move, otherwise the path that was
    # checked and the path that is moved can differ.
    return $Path
}

function Test-PathMovable([string]$Path) {
    <#
      INTRUSIVE - not read-only. Opt in with Invoke-Cleanup.ps1 -ProbeMovable only.

      Same-volume rename probe: a move inside one volume *is* a rename, so if the rename
      works the real Move-Item will work too. Sampling file handles inside the folder would
      give false negatives - Windows happily renames a directory whose files are held open.

      The target is renamed and immediately renamed back. While the rename is in flight the
      original path does not exist, so anything that opens it by name can fail for that
      instant. If the revert fails - or the process is killed between the two calls and the
      finally block never runs - the target stays under "<name>.checkup-probe-*". A silent
      leftover would be worse than a loud one, so the result says so explicitly; callers
      must treat that as a manual fix-up request, not as a normal "not movable".
    #>
    if (-not (Test-Path -LiteralPath $Path)) { return @{ movable = $false; reason = '路径已不存在' } }
    $parent = Split-Path -Parent $Path
    if (-not $parent) { return @{ movable = $false; reason = '没有父目录，拒绝探测' } }

    $leaf = Split-Path -Leaf $Path
    $probe = Join-Path $parent ($leaf + '.checkup-probe-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
    $isDir = (Get-Item -LiteralPath $Path -Force).PSIsContainer
    $moved = $false

    try {
        if ($isDir) { [IO.Directory]::Move($Path, $probe) } else { [IO.File]::Move($Path, $probe) }
        $moved = $true
    } catch {
        return @{ movable = $false; reason = ('无法移动：' + $_.Exception.Message) }
    } finally {
        if ($moved) {
            try {
                if ($isDir) { [IO.Directory]::Move($probe, $Path) } else { [IO.File]::Move($probe, $Path) }
            } catch {
                Write-Warning ('探测后无法还原，目录仍叫：' + $probe + '（内容未丢，请手动改回 ' + $leaf + '）')
            }
        }
    }

    if (Test-Path -LiteralPath $probe) {
        # Name did not come back: stop here rather than act on a path that no longer exists.
        return @{ movable = $false; reason = ('探测后无法还原，目录现停留在 ' + $probe + '，请手动改回 ' + $leaf) }
    }
    return @{ movable = $true; reason = $null }
}

function Get-PathSize([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) {
        $sum = (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        return [long]$sum
    }
    return [long]$item.Length
}

function New-CleanupRunId {
    return (Get-Date).ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
}

function Assert-RestorePair([string]$Source, [string]$Destination, [string]$QuarantineRoot) {
    <#
      Undo reads two paths straight out of a manifest, so both ends need a boundary check.
      The source must sit inside the quarantine this run declared - that single rule stops
      a forged or hand-edited manifest from turning "-Undo" into an arbitrary file mover.
      The destination may not be a system directory; Documents/Desktop stay allowed.
    #>
    if (-not $Source -or -not $Destination) { throw '清单条目的路径不完整。' }
    $Source = $Source -replace '/', '\'
    $Destination = $Destination -replace '/', '\'
    $QuarantineRoot = $QuarantineRoot -replace '/', '\'
    if (-not $QuarantineRoot) { throw '清单没有声明隔离区根目录，拒绝撤销。' }
    # Prove both ends are absolute before touching them: GetFullPath on a relative path
    # would quietly resolve it against the current directory and hide the problem.
    foreach ($p in @($Source, $Destination)) {
        if (-not [IO.Path]::IsPathFullyQualified($p)) { throw ('路径不是绝对路径：' + $p) }
        if ($p.StartsWith('\\')) { throw ('拒绝网络路径：' + $p) }
    }
    # "root\..\..\x" passes a plain prefix test while pointing outside the root, so both
    # ends are collapsed before any comparison. The caller moves these exact paths.
    $Source = [IO.Path]::GetFullPath($Source)
    $Destination = [IO.Path]::GetFullPath($Destination)
    # Manifests written before the run directory was recorded store the "{drive}" template
    # verbatim, so expand it the same way the cleaner did, per item.
    if ($QuarantineRoot.Contains('{drive}')) {
        $letter = [IO.Path]::GetPathRoot($Source).TrimEnd('\').TrimEnd(':')
        $QuarantineRoot = $QuarantineRoot.Replace('{drive}', $letter)
    }
    # A bound root of "C:\" would make every path on the volume "inside the quarantine".
    $QuarantineRoot = [IO.Path]::GetFullPath($QuarantineRoot).TrimEnd('\')
    $boundVolume = [IO.Path]::GetPathRoot($QuarantineRoot).TrimEnd('\')
    if ($QuarantineRoot.Equals($boundVolume, [StringComparison]::OrdinalIgnoreCase)) {
        throw '清单声明的隔离区是整盘根目录，拒绝撤销。'
    }
    foreach ($p in @($Source, $Destination)) {
        $root = [IO.Path]::GetPathRoot($p).TrimEnd('\')
        if ($p.TrimEnd('\').Equals($root, [StringComparison]::OrdinalIgnoreCase)) { throw ('拒绝整盘根目录：' + $p) }
    }
    if (-not (Test-UnderPath $Source $QuarantineRoot)) {
        throw ('源不在清单声明的隔离区内，拒绝移动：' + $Source)
    }
    foreach ($blocked in (Get-SystemOnlyRoots)) {
        if ($blocked -and (Test-UnderPath $Destination $blocked)) { throw ('拒绝还原到系统目录：' + $Destination) }
    }
    if (-not (Test-Path -LiteralPath $Source)) { throw ('隔离区里已没有这个文件：' + $Source) }
    return @{ source = $Source; destination = $Destination }
}

function Write-JsonFileAtomic([string]$Path, $Object) {
    # A half-written manifest is worse than a stale one: write beside it, then rename.
    $json = $Object | ConvertTo-Json -Depth 12
    $tmp = $Path + '.tmp'
    [IO.File]::WriteAllText($tmp, $json + "`n", [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Write-JsonFile([string]$Path, $Object) {
    $json = $Object | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($Path, $json + "`n", [Text.UTF8Encoding]::new($false))
}

Export-ModuleMember -Function Get-BlockedRoots, Get-SystemOnlyRoots, Test-UnderPath, Assert-CleanupTarget,
    Assert-RestorePair, Test-PathMovable, Get-PathSize, New-CleanupRunId, Write-JsonFile, Write-JsonFileAtomic
