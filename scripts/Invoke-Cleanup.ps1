#requires -Version 7.2
[CmdletBinding()]
param(
    [string]$PlanPath,
    [string]$QuarantineRoot,
    [string]$ConfigPath,
    [switch]$Apply,
    [string]$Undo,
    [switch]$ProbeMovable,
    [int]$MaxItems = 200,
    [double]$MaxGB = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Checkup.Cleanup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Checkup.Logic.psm1') -Force

if (-not $IsWindows) { throw '此脚本仅支持 Windows。' }
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }
if ($MaxItems -lt 1 -or $MaxItems -gt 5000) { throw 'MaxItems 允许范围 1-5000。' }
if ($MaxGB -le 0 -or $MaxGB -gt 50) { throw 'MaxGB 允许范围 0-50。' }
# The rename probe mutates target names, so it is meaningful only for a dry-run and
# must never be silently mixed into an apply run.
if ($ProbeMovable -and $Apply) { throw '-ProbeMovable 只用于 dry-run，不能与 -Apply 同时使用。' }

function Resolve-Quarantine([string]$Root, [string]$ForPath) {
    if (-not $Root) { throw '需要 -QuarantineRoot 指向隔离区目录。' }
    # {drive} expands to the bare letter (e.g. "C"), so the template keeps its own colon.
    if ($Root.Contains('{drive}')) {
        $letter = [IO.Path]::GetPathRoot($ForPath).TrimEnd('\').TrimEnd(':')
        $Root = $Root.Replace('{drive}', $letter)
    }
    if (-not [IO.Path]::IsPathFullyQualified($Root)) { throw '隔离区必须是绝对路径。' }
    return [IO.Path]::GetFullPath($Root).TrimEnd('\')
}

# ---------------------------------------------------------------------------
# Undo path
# ---------------------------------------------------------------------------
if ($Undo) {
    if (-not (Test-Path -LiteralPath $Undo)) { throw '找不到 manifest 文件。' }
    $manifest = Get-Content -LiteralPath $Undo -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
    if (-not $manifest.Contains('version') -or [int]$manifest.version -ne 1) { throw '清单版本不受支持，拒绝撤销。' }
    if (-not $manifest.Contains('items')) { throw '清单缺少 items，拒绝撤销。' }
    # Newer manifests pin the run directory; older ones only name the template root.
    $pinnedRunRoot = ($manifest.Contains('quarantineRunRoot') -and $manifest.quarantineRunRoot)
    $boundRoot = if ($pinnedRunRoot) { $manifest.quarantineRunRoot }
                 elseif ($manifest.Contains('quarantineRoot')) { $manifest.quarantineRoot }
                 else { $null }
    if (-not $boundRoot) { throw '清单没有声明隔离区根目录，拒绝撤销。' }
    # Bind the declared root to where the manifest physically sits. Without this a forged
    # manifest can name any directory as its own "quarantine" and -Undo becomes a mover.
    $manifestFull = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Undo).Path)
    $manifestDir = (Split-Path -Parent $manifestFull).TrimEnd('\')
    if ($boundRoot.Contains('{drive}')) {
        $mLetter = [IO.Path]::GetPathRoot($manifestFull).TrimEnd('\').TrimEnd(':')
        $boundRoot = $boundRoot.Replace('{drive}', $mLetter)
    }
    if (-not [IO.Path]::IsPathFullyQualified($boundRoot)) { throw '清单声明的隔离区不是绝对路径，拒绝撤销。' }
    $boundFull = [IO.Path]::GetFullPath($boundRoot).TrimEnd('\')
    if ($pinnedRunRoot) {
        # A run manifest lives exactly in the run directory it names.
        if (-not $manifestDir.Equals($boundFull, [StringComparison]::OrdinalIgnoreCase)) {
            throw ('清单不在它声明的运行目录内，拒绝撤销：' + $manifestDir)
        }
    } else {
        # Legacy manifests only name the template root; the run directory must be below it.
        if ($manifestDir.Equals($boundFull, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-UnderPath $manifestDir $boundFull)) {
            throw ('清单不在它声明的隔离区内，拒绝撤销：' + $manifestDir)
        }
    }

    $restored = 0; $skipped = 0
    $failedItems = [Collections.Generic.List[object]]::new()
    foreach ($entry in @($manifest.items)) {
        $src = $entry.quarantinePath
        $dst = $entry.originalPath
        if (-not (Test-Path -LiteralPath $src)) { $skipped++; continue }
        try {
            # Normalized paths come back from the check; the move must use the same ones.
            $pair = Assert-RestorePair $src $dst $boundRoot
            $src = $pair.source
            $dst = $pair.destination
            $expected = [long]0
            if ($entry.Contains('bytes')) { $expected = [long]$entry.bytes }
            if ($expected -gt 0) {
                $actual = Get-PathSize $src
                if ($actual -ne $expected) { throw ('清单记录 ' + $expected + ' 字节，实际 ' + $actual + '，内容已变，拒绝还原') }
            }
            if (Test-Path -LiteralPath $dst) {
                $n = 1
                $candidate = $dst + '.recovered-' + $n
                while (Test-Path -LiteralPath $candidate) { $n++; $candidate = $dst + '.recovered-' + $n }
                $dst = $candidate
            }
            $parent = Split-Path -Parent $dst
            if ($parent -and -not (Test-Path -LiteralPath $parent)) { $null = [IO.Directory]::CreateDirectory($parent) }
            # No -Force: the destination was checked a moment ago, do not overwrite anything
            # that appeared since.
            Move-Item -LiteralPath $src -Destination $dst -ErrorAction Stop
            $restored++
        } catch {
            $failedItems.Add([ordered]@{ path = $src; originalPath = $dst; reason = $_.Exception.Message })
        }
    }
    $status = if ($manifest.Contains('status')) { [string]$manifest.status } else { 'completed' }
    [ordered]@{ mode = 'undo'; restored = $restored; failed = $failedItems.Count; skipped = $skipped
                failedItems = @($failedItems | Select-Object -First 20)
                incomplete = ($status -eq 'in-progress')
                manifestStatus = $status
                manifest = $Undo } | ConvertTo-Json -Depth 6
    return
}

# ---------------------------------------------------------------------------
# Plan execution
# ---------------------------------------------------------------------------
if (-not $PlanPath) { throw '需要 -PlanPath，或使用 -Undo 指定 manifest。' }
if (-not (Test-Path -LiteralPath $PlanPath)) { throw '找不到计划文件。' }
$plan = Get-Content -LiteralPath $PlanPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
if ($plan.version -ne 1) { throw '计划文件版本不受支持。' }
$planFull = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $PlanPath).Path)
# The plan has to sit in the output directory it claims to come from. A plan found (or
# planted) anywhere else is not something this cleaner should execute.
if (-not $plan.Contains('outDirectory') -or -not $plan.outDirectory) {
    throw '计划缺少 outDirectory，无法确认来源，拒绝执行。'
}
$outDir = [IO.Path]::GetFullPath([string]$plan.outDirectory).TrimEnd('\')
if (-not (Test-UnderPath $planFull $outDir)) {
    throw ('计划文件不在其声明的 outDirectory 内，拒绝执行：' + $planFull)
}
if (-not $plan.items -or @($plan.items).Count -eq 0) {
    [ordered]@{ mode = 'noop'; message = '计划中没有可执行条目。'; movedCount = 0; movedBytes = 0 } | ConvertTo-Json
    return
}

# -ConfigPath lets the cleaner re-check every item on its own instead of trusting the plan:
# the path must sit under a root the config allows and outside every protected root. One
# violation rejects the whole plan - a plan that is partly wrong is not partly trustworthy.
$allowedRoots = [Collections.Generic.List[string]]::new()
$protectedRoots = [Collections.Generic.List[string]]::new()
if ($ConfigPath) {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw '找不到 -ConfigPath 指定的配置文件。' }
    $cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
    foreach ($ws in @($cfg.workspaceRoots)) {
        if ($ws) { $allowedRoots.Add(([IO.Path]::GetFullPath([string]$ws)).TrimEnd('\')) }
    }
    foreach ($spec in @($cfg.cacheRoots)) {
        $resolved = Resolve-CacheRootSpec $spec
        # Unknown named roots resolve to $null; they simply contribute nothing.
        if ($resolved.path) {
            $allowedRoots.Add(([IO.Path]::GetFullPath([string]$resolved.path)).TrimEnd('\'))
        }
    }
    foreach ($pr in @($cfg.protectedRoots)) {
        if ($pr) { $protectedRoots.Add(([IO.Path]::GetFullPath([string]$pr)).TrimEnd('\')) }
    }
    if ($allowedRoots.Count -eq 0) { throw '配置里没有任何允许的根目录，拒绝执行。' }
    foreach ($item in @($plan.items)) {
        if (-not $item.path -or -not [IO.Path]::IsPathFullyQualified([string]$item.path)) {
            throw ('计划条目路径不是绝对路径，整单拒绝：' + $item.path)
        }
        $candidate = ([string]$item.path) -replace '/', '\'
        $candidate = [IO.Path]::GetFullPath($candidate)
        $inAllowed = $false
        foreach ($r in $allowedRoots) { if (Test-UnderPath $candidate $r) { $inAllowed = $true; break } }
        if (-not $inAllowed) { throw ('计划条目不在配置允许的根目录内，整单拒绝：' + $candidate) }
        foreach ($r in $protectedRoots) {
            if (Test-UnderPath $candidate $r) { throw ('计划条目位于配置的保护目录内，整单拒绝：' + $candidate) }
        }
    }
}

$quarantineTemplate = $QuarantineRoot
$runId = New-CleanupRunId
$runRoots = [Collections.Generic.List[string]]::new()

$limitBytes = [long]($MaxGB * 1GB)
$moved = [Collections.Generic.List[object]]::new()
$failed = [Collections.Generic.List[object]]::new()
$movedBytes = [long]0
$index = 0
$probeMode = if ($Apply) { 'none' } elseif ($ProbeMovable) { 'rename' } else { 'readonly' }
$startedUtc = (Get-Date).ToUniversalTime().ToString('o')
$journals = @{}

function Write-Journal($Journal, [string]$Status) {
    $payload = [ordered]@{
        version = 1; runId = $runId; status = $Status
        createdAtUtc = $Journal.createdAtUtc; updatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        planPath = $planFull; quarantineRoot = $quarantineTemplate
        quarantineRunRoot = $Journal.dir; retentionDays = 7
        itemCount = $Journal.items.Count
        movedCount = @($Journal.items | Where-Object { $_['state'] -eq 'moved' }).Count
        failedCount = @($Journal.items | Where-Object { $_['state'] -eq 'failed' }).Count
        items = @($Journal.items)
    }
    Write-JsonFileAtomic (Join-Path $Journal.dir 'manifest.json') $payload
}

function Get-Journal([string]$RunRoot) {
    # The journal exists before the first move, so a crash can never leave quarantined
    # files without a record of where they came from.
    if ($journals.ContainsKey($RunRoot)) { return $journals[$RunRoot] }
    $null = [IO.Directory]::CreateDirectory($RunRoot)
    $j = @{ dir = $RunRoot; createdAtUtc = $startedUtc
            items = [Collections.Generic.List[object]]::new() }
    $journals[$RunRoot] = $j
    Write-Journal $j 'in-progress'
    return $j
}

foreach ($item in @($plan.items)) {
    if ($moved.Count -ge $MaxItems) { $failed.Add([ordered]@{ path = $item.path; reason = '超过单次条目上限' }); continue }
    if ($movedBytes -ge $limitBytes) { $failed.Add([ordered]@{ path = $item.path; reason = '超过单次体积上限' }); continue }
    $index++

    try {
        if (-not $item.path -or -not [IO.Path]::IsPathFullyQualified([string]$item.path)) { throw '条目 path 不是绝对路径' }
        # Normalize once, then let every later step work on the same string the check approved.
        $item.path = ([string]$item.path) -replace '/', '\'
        $item.path = [IO.Path]::GetFullPath($item.path)
        if (-not (Test-Path -LiteralPath $item.path)) { throw '路径已不存在' }
        $quarantine = Resolve-Quarantine $quarantineTemplate $item.path
        $item.path = Assert-CleanupTarget $item.path $quarantine

        $srcRoot = [IO.Path]::GetPathRoot($item.path).TrimEnd('\')
        $dstRoot = [IO.Path]::GetPathRoot($quarantine).TrimEnd('\')
        if ($srcRoot -ine $dstRoot) { throw '隔离区与源文件不在同一磁盘，拒绝跨盘移动' }

        $runRoot = Join-Path $quarantine $runId
        if (-not $runRoots.Contains($runRoot)) { $runRoots.Add($runRoot) }

        $currentSize = Get-PathSize $item.path
        $expected = [long]$item.logicalBytes
        $delta = 0.0
        if ($expected -gt 0) {
            $delta = [Math]::Abs($currentSize - $expected) / [double]$expected
            if ($delta -gt 0.05) { throw ('大小与计划不一致（计划 ' + $expected + ' 实际 ' + $currentSize + '）') }
        }

        $slot = Join-Path $runRoot ('{0:D4}' -f $index)
        $leaf = Split-Path -Leaf $item.path
        $target = Join-Path $slot $leaf

        $preview = [ordered]@{
            path = $item.path; category = $item.category; grade = $item.grade
            bytes = $currentSize; sizeDeltaPercent = [Math]::Round($delta * 100, 1)
        }

        if (-not $Apply) {
            # A dry-run must not touch the target. Files can be lock-checked by opening a
            # handle and closing it again; directories cannot be judged that way, so they
            # report movable = null instead of a guess. The rename probe is opt-in because
            # it does rename the target, however briefly.
            if ($ProbeMovable) {
                $probe = Test-PathMovable $item.path
                if (-not $probe.movable) {
                    $failed.Add([ordered]@{ path = $item.path; reason = ('改名探测：' + $probe.reason) })
                    continue
                }
                $movable = $true
                $movableSource = 'rename-probe'
            } else {
                $isDir = (Get-Item -LiteralPath $item.path -Force).PSIsContainer
                if ($isDir) {
                    $movable = $null
                    $movableSource = 'unknown'
                } elseif (Test-FileInUse $item.path) {
                    $failed.Add([ordered]@{ path = $item.path; reason = '文件正被占用（只读句柄探测）' })
                    continue
                } else {
                    $movable = $true
                    $movableSource = 'handle-probe'
                }
            }
            $moved.Add($preview + @{ movable = $movable; movableSource = $movableSource
                                     quarantinePath = '(dry-run)'; dryRun = $true })
            $movedBytes += $currentSize
            continue
        }

        $null = [IO.Directory]::CreateDirectory($slot)
        $journal = Get-Journal $runRoot
        $entry = [ordered]@{
            originalPath = $item.path; quarantinePath = $target; bytes = $currentSize
            category = $item.category; grade = $item.grade; reason = $item.reason
            state = 'pending'; movedAtUtc = $null
        }
        $journal.items.Add($entry)
        Write-Journal $journal 'in-progress'
        try {
            Move-Item -LiteralPath $item.path -Destination $target -ErrorAction Stop
            $entry['state'] = 'moved'
            $entry['movedAtUtc'] = (Get-Date).ToUniversalTime().ToString('o')
        } catch {
            $entry['state'] = 'failed'
            $entry['reason'] = ($entry['reason'] + ' | 移动失败：' + $_.Exception.Message)
            throw
        } finally {
            Write-Journal $journal 'in-progress'
        }
        $record = [ordered]@{
            originalPath = $item.path; quarantinePath = $target; bytes = $currentSize
            category = $item.category; grade = $item.grade; reason = $item.reason
            movedAtUtc = $entry['movedAtUtc']
        }
        $moved.Add($record)
        $movedBytes += $currentSize
    } catch {
        $failed.Add([ordered]@{ path = $item.path; reason = $_.Exception.Message })
    }
}

$manifestPaths = [Collections.Generic.List[string]]::new()
foreach ($j in $journals.Values) {
    $hasFailure = @($j.items | Where-Object { $_['state'] -eq 'failed' }).Count -gt 0
    Write-Journal $j $(if ($hasFailure) { 'completed-with-failures' } else { 'completed' })
    $manifestPaths.Add((Join-Path $j.dir 'manifest.json'))
}
$manifestPath = if ($manifestPaths.Count -gt 0) { $manifestPaths[0] } else { $null }

[ordered]@{
    mode = $(if ($Apply) { 'apply' } else { 'dry-run' })
    # readonly = files lock-checked by handle only, directories left unknown (default).
    # rename   = opt-in Test-PathMovable probe; it does rename each target and rename it back.
    probeMode = $probeMode
    # Kept for compatibility: true only when the intrusive rename probe actually ran.
    movableProbed = ($probeMode -eq 'rename')
    runId = $runId
    movedCount = $moved.Count
    movedBytes = $movedBytes
    failedCount = $failed.Count
    failed = @($failed | Select-Object -First 20)
    # Only report a quarantine root that actually exists (a journal was opened in it).
    quarantineRoot = $(if ($Apply -and $journals.Count -gt 0) { @($journals.Keys)[0] } else { $null })
    manifest = $manifestPath
    manifests = $(if ($manifestPaths.Count -gt 0) { @($manifestPaths) } else { $null })
    undoCommand = $(if ($manifestPath) { "& '<pwsh>' -NoProfile -File '<skill>/scripts/Invoke-Cleanup.ps1' -Undo '" + $manifestPath + "'" } else { $null })
    items = @($moved | Select-Object -First 50)
} | ConvertTo-Json -Depth 8
