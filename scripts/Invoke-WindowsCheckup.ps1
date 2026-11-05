#requires -Version 7.2
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$OutDirectory,
    [switch]$SaveState,
    [switch]$SkipSystemChecks,
    [string]$PwshPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Checkup.Logic.psm1') -Force
. (Join-Path $PSScriptRoot 'Get-ReclaimCandidates.ps1')

if (-not $IsWindows) { throw '此检查器仅支持 Windows。' }
if (-not $ConfigPath) { throw '请使用 -ConfigPath 指定个人配置；不会隐式扫描当前目录。' }
if ($SaveState -and -not $OutDirectory) { throw '-SaveState 需要明确的 -OutDirectory。' }

$utf8 = [Text.UTF8Encoding]::new($false)
try { [Console]::OutputEncoding = $utf8 } catch { }
$capturedAt = [DateTimeOffset]::UtcNow
$coverage = [Collections.Generic.List[object]]::new()
$findings = [Collections.Generic.List[object]]::new()
$changes = [Collections.Generic.List[object]]::new()
$advisories = [Collections.Generic.List[object]]::new()
$snapshots = @{}
$data = [ordered]@{}
$sensitive = '(?i)^(\.git|\.ssh|\.aws|\.azure|\.gnupg|\.env(?:\..*)?|\.npmrc|\.pypirc|\.netrc|auth\.(json|ya?ml)|credentials?(?:\..*)?|secrets?(?:\..*)?|tokens?(?:\..*)?|passwords?(?:\..*)?|id_(rsa|ed25519|ecdsa)(?:\..*)?|.*\.(pem|key|p12|pfx|kdbx)|.*(身份证|护照|银行卡|助记词|private[-_ ]?key|recovery[-_ ]?phrase).*)$'

function Is-Within([string]$Child, [string]$Parent) {
    return $Child.Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or
           $Child.StartsWith($Parent.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}
function Normalize-Path([string]$Value) {
    if (-not $Value -or -not [IO.Path]::IsPathFullyQualified($Value) -or $Value.StartsWith('\\') -or
        $Value -notmatch '^[A-Za-z]:\\' -or $Value.Substring(2).Contains(':')) {
        throw '路径必须是本机磁盘上的绝对路径，不能使用网络路径或设备路径。'
    }
    return [IO.Path]::GetFullPath($Value).TrimEnd('\')
}
function Assert-PathBoundary([string]$Value, [switch]$AllowMissing) {
    $p = Normalize-Path $Value
    $broad = @([IO.Path]::GetPathRoot($Value).TrimEnd('\'), $env:USERPROFILE, $env:APPDATA, $env:LOCALAPPDATA,
               $env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, [IO.Path]::GetTempPath().TrimEnd('\'))
    if ($broad | Where-Object { $_ -and $p.Equals($_.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) }) {
        throw '拒绝整盘、用户主目录或宽泛系统目录。'
    }
    foreach ($root in $script:protected) { if (Is-Within $p $root) { throw '目标位于保护区。' } }
    foreach ($part in ($p -split '\\')) { if ($part -match $script:sensitive) { throw '目标名称属于敏感目录或文件。' } }
    $cursor = $p
    while ($cursor) {
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            if ((([int][IO.File]::GetAttributes($cursor)) -band 0x441400) -ne 0) {
                throw '目标或父目录是联接、符号链接、离线项或云端占位项。'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    if (-not $AllowMissing -and -not (Test-Path -LiteralPath $p)) { throw '目标不存在。' }
    return $p
}
function Add-Coverage([string]$Id, [string]$Status, [string]$Detail) {
    $coverage.Add([ordered]@{ id = $Id; status = $Status; detail = $Detail })
    # Scan limits (partial) are documented gaps, not failures; only real failures raise findings.
    if ($Status -in @('error', 'refused', 'missing')) {
        Add-Finding ('coverage:' + $Id + ':' + $Status) 'warning' $Id ($Id + '：' + $Detail)
    }
}
function Add-Finding([string]$Id, [string]$Severity, [string]$Check, [string]$Message, [string]$Evidence = '') {
    $findings.Add([ordered]@{ id = $Id; severity = $Severity; check = $Check; message = $Message
                              fingerprint = (Hash-Text ($Severity + '|' + $Check + '|' + $Evidence)) })
}
function Hash-Text([string]$Text) {
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes($Text))).ToLowerInvariant()
}
function GiB($Bytes) { return [Math]::Round([double]$Bytes / 1GB, 2) }
function Sum-Allocation($Items) {
    $total = [long]0
    foreach ($i in $Items) { if ($i) { $total += [long]$i.allocationBytes } }
    return $total
}
function Format-Size($Bytes) {
    if ($Bytes -ge 1GB) { return ('{0:N2} GiB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MiB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N1} KiB' -f ($Bytes / 1KB)) }
    return ([string]$Bytes + ' B')
}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
$protected = @()
$configFile = Assert-PathBoundary $ConfigPath
if ((Get-Item -LiteralPath $configFile).Length -gt 1MB) { throw '配置文件超过 1 MiB。' }
$raw = Get-Content -LiteralPath $configFile -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
if ($raw.version -notin @(1, 2)) { throw '仅支持 version=1 或 version=2 的配置。' }

$cfg = [ordered]@{
    version       = 2
    workspaceRoots = @()
    cacheRoots    = @()
    skillRoots    = @()
    protectedRoots = @()
    taskPathPrefixes = @()
    serviceNames  = @()
    outputProbes  = @()
    cleanup       = @{ enabled = $true; recycleMode = 'quarantine'; quarantineRoot = ''; retentionDays = 7
                       maxPerRunGB = 5; maxItemsPerRun = 200; requireConfirm = $true
                       skipObservationCheck = $false; whitelist = @('**\.git\**', '**\.workbuddy\**', '**\.codex\**') }
    rules         = @{ tempOlderThanDays = 3; logOlderThanDays = 7; logFileMB = 50; largeFileMB = 200
                       staleDependencyDays = 90; keepPreviousRuntimes = 1; installLeftoverMinAgeHours = 24
                       minCandidateMB = 1 }
    thresholds    = @{ diskFreePercentWarn = 10; diskDaysToFullWarn = 30; memAvailablePercentWarn = 15; growthWarnGB = 1 }
    system        = @{ eventLogDays = 7; power = @{ enabled = $false; requiresAdmin = $true }; sfc = @{ enabled = $false; requiresAdmin = $true } }
    limits        = @{ maxEntries = 200000; maxDepth = 12; maxSecondsPerRoot = 60 }
}

foreach ($key in @('workspaceRoots', 'cacheRoots', 'skillRoots', 'protectedRoots', 'taskPathPrefixes', 'serviceNames', 'outputProbes')) {
    if ($raw.ContainsKey($key)) {
        if ($raw[$key] -isnot [array]) { throw "配置 $key 必须是数组。" }
        $cfg[$key] = $raw[$key]
    }
}
foreach ($section in @('cleanup', 'rules', 'thresholds', 'system', 'limits')) {
    if ($raw.ContainsKey($section) -and $raw[$section] -is [hashtable]) {
        foreach ($k in $raw[$section].Keys) { $cfg[$section][$k] = $raw[$section][$k] }
    }
}
if ($raw.version -eq 1) {
    $cfg.cacheRoots = @($raw.cacheRoots | ForEach-Object { @{ kind = 'path'; path = $_ } })
} else {
    $cfg.cacheRoots = @($raw.cacheRoots)
}

$protected = @($cfg.protectedRoots | ForEach-Object { Normalize-Path $_ })
$limit = @{ maxEntries = 200000; maxDepth = 12; maxSecondsPerRoot = 60 }
foreach ($key in @($limit.Keys)) {
    if ($cfg.limits.ContainsKey($key)) { $limit[$key] = [int]$cfg.limits[$key] }
}
if ($limit.maxEntries -lt 1 -or $limit.maxEntries -gt 500000 -or $limit.maxDepth -lt 1 -or
    $limit.maxDepth -gt 30 -or $limit.maxSecondsPerRoot -lt 1 -or $limit.maxSecondsPerRoot -gt 60) {
    throw '扫描上限超出允许范围。'
}

# ---------------------------------------------------------------------------
# Output directory, lock, state
# ---------------------------------------------------------------------------
$outputRoot = $null; $stateFile = $null; $previous = $null; $runLock = $null; $stateMigrated = $false
try {
    if ($OutDirectory) {
        $outputRoot = Assert-PathBoundary $OutDirectory -AllowMissing
        if ([IO.File]::Exists($outputRoot)) { throw '报告位置必须是目录。' }
        $cachePaths = @($cfg.cacheRoots | ForEach-Object { if ($_ -is [string]) { $_ } else { [string](Get-SpecValue $_ 'path') } })
        foreach ($root in @($cfg.workspaceRoots) + @($cachePaths) + @($cfg.skillRoots)) {
            if (-not $root) { continue }
            try { $normalized = Normalize-Path $root } catch { continue }
            if (Is-Within $normalized $outputRoot) { throw '报告目录不能等于扫描根或包含扫描根；允许放在扫描根的子目录。' }
        }
        $null = [IO.Directory]::CreateDirectory($outputRoot)
        $lockFile = Join-Path $outputRoot '.checkup.lock'
        $null = Assert-PathBoundary $lockFile -AllowMissing
        try { $runLock = [IO.File]::Open($lockFile, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch { throw '报告目录已有体检正在运行，或锁文件不可访问；本次停止，不覆盖对比状态。' }
        $stateFile = Join-Path $outputRoot '.last-checkup.json'
        if (Test-Path -LiteralPath $stateFile) {
            $null = Assert-PathBoundary $stateFile
            if ((Get-Item -LiteralPath $stateFile).Length -gt 10MB) { throw '历史状态过大；为保护原记录已停止。' }
            try {
                $previous = Get-Content -LiteralPath $stateFile -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
                if ($previous.version -notin @(1, 2, 3) -or $previous.snapshots -isnot [hashtable]) { throw '状态格式不支持。' }
                $stateMigrated = $previous.version -lt 3
            } catch { throw '历史状态损坏或版本不支持；没有覆盖原记录，请先人工核实。' }
        }
    }

    # -----------------------------------------------------------------------
    # Measurement
    # -----------------------------------------------------------------------
    $directoryResults = [Collections.Generic.List[object]]::new()
    $blockCache = @{}

    function Get-Block([string]$Path) {
        $drive = [IO.Path]::GetPathRoot($Path)
        if (-not $script:blockCache.ContainsKey($drive)) { $script:blockCache[$drive] = Get-VolumeBlockSize $Path }
        return $script:blockCache[$drive]
    }

    function Measure-Root([string]$Root, [string]$Kind) {
        $id = "$Kind`:$Root"
        try { $rootPath = Assert-PathBoundary $Root -AllowMissing } catch { Add-Coverage $id 'refused' $_.Exception.Message; return }
        if (-not [IO.Directory]::Exists($rootPath)) { Add-Coverage $id 'missing' '目录不存在或当前账户不可访问。'; return }

        $block = Get-Block $rootPath
        $stats = @{ logicalBytes = [long]0; allocationBytes = [long]0; files = 0; directories = 0
                    entries = 0; skipped = 0; inaccessible = 0; limited = $false }
        $buckets = @{}
        $dependencies = @{}
        $largeFiles = [Collections.Generic.List[object]]::new()
        $logs = [Collections.Generic.List[object]]::new()
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $queue = [Collections.Generic.Queue[object]]::new()
        $queue.Enqueue(@{ path = $rootPath; depth = 0; group = '.'; dependency = $null })

        $largeBytes = [long]$cfg.rules.largeFileMB * 1MB
        $logBytes = [long]$cfg.rules.logFileMB * 1MB
        $logCutoff = (Get-Date).AddDays(-[double]$cfg.rules.logOlderThanDays)

        while ($queue.Count -gt 0) {
            if ($stats.entries -ge $limit.maxEntries -or $clock.Elapsed.TotalSeconds -ge $limit.maxSecondsPerRoot) {
                $stats.limited = $true; break
            }
            $item = $queue.Dequeue()
            $p = $item.path
            if (($outputRoot -and (Is-Within $p $outputRoot)) -or
                @($protected | Where-Object { Is-Within $p $_ }).Count -gt 0 -or
                [IO.Path]::GetFileName($p) -match $sensitive) { $stats.skipped++; continue }
            $stats.entries++
            try { $attrs = [IO.File]::GetAttributes($p) } catch { $stats.inaccessible++; continue }
            if (([int]$attrs -band 0x441400) -ne 0) { $stats.skipped++; continue }

            if (($attrs -band [IO.FileAttributes]::Directory) -ne 0) {
                $stats.directories++
                $dirName = [IO.Path]::GetFileName($p)
                if ($dirName -in @('node_modules', '.venv', 'venv', '__pycache__', '.next', 'dist', 'build')) {
                    $dependencies[$p] = [ordered]@{ path = $p; logicalBytes = [long]0 }
                    $item.dependency = $p
                }
                if ($item.depth -ge $limit.maxDepth) { $stats.limited = $true; continue }
                try {
                    foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($p)) {
                        if ($queue.Count + $stats.entries -ge $limit.maxEntries) { $stats.limited = $true; break }
                        $group = if ($item.depth -eq 0) { [IO.Path]::GetFileName($child) } else { $item.group }
                        $queue.Enqueue(@{ path = $child; depth = $item.depth + 1; group = $group; dependency = $item.dependency })
                    }
                } catch { $stats.inaccessible++ }
            } else {
                $fileInfo = [IO.FileInfo]::new($p)
                $length = $fileInfo.Length
                $stats.files++
                $stats.logicalBytes += $length
                $stats.allocationBytes += (Get-AllocationSize $length $block)
                if (-not $buckets.ContainsKey($item.group)) { $buckets[$item.group] = [long]0 }
                $buckets[$item.group] += $length
                if ($item.dependency) { $dependencies[$item.dependency].logicalBytes += $length }
                if ($length -ge $largeBytes) {
                    Add-LargestCandidate $largeFiles ([ordered]@{ path = $p; logicalBytes = $length
                                                                 modifiedUtc = $fileInfo.LastWriteTimeUtc.ToString('o') })
                }
                if ($fileInfo.Extension -in @('.log', '.out', '.err') -and $length -ge $logBytes -and $fileInfo.LastWriteTime -lt $logCutoff) {
                    Add-LargestCandidate $logs ([ordered]@{ path = $p; logicalBytes = $length
                                                            modifiedUtc = $fileInfo.LastWriteTimeUtc.ToString('o') })
                }
            }
        }
        $clock.Stop()
        $complete = -not $stats.limited -and $stats.inaccessible -eq 0 -and $stats.skipped -eq 0
        $result = [ordered]@{
            path = $rootPath; kind = $Kind; logicalBytes = $stats.logicalBytes; allocationBytes = $stats.allocationBytes
            complete = $complete; stats = $stats
            topLevel = @($buckets.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20 |
                         ForEach-Object { [ordered]@{ name = $_.Key; logicalBytes = $_.Value } })
            dependencies = @($dependencies.Values | Sort-Object { $_.logicalBytes } -Descending | Select-Object -First 30)
            largeFiles = @($largeFiles | Sort-Object { $_.logicalBytes } -Descending | Select-Object -First 20)
            logs = @($logs | Sort-Object { $_.logicalBytes } -Descending | Select-Object -First 20)
        }
        $script:directoryResults.Add($result)
        $status = if ($stats.limited -or $stats.inaccessible -gt 0) { 'partial' } else { 'ok' }
        Add-Coverage $id $status ("观察到 {0} 个文件，逻辑大小 {1} GiB，占用 {2} GiB；排除 {3}，不可访问 {4}，达到上限 {5}。" -f
            $stats.files, (GiB $stats.logicalBytes), (GiB $stats.allocationBytes), $stats.skipped, $stats.inaccessible, $stats.limited)
        if ($status -eq 'ok') {
            $snapshots[$id] = @{ bytes = $stats.logicalBytes; skipped = $stats.skipped }
            if ($previous -and $previous.snapshots.ContainsKey($id) -and
                (Get-SpecValue $previous.snapshots[$id] 'skipped') -eq $stats.skipped) {
                $growth = $stats.logicalBytes - [long](Get-SpecValue $previous.snapshots[$id] 'bytes')
                $threshold = [long]$cfg.thresholds.growthWarnGB * 1GB
                if ($growth -ge $threshold) {
                    Add-Finding ('growth:' + $rootPath) 'warning' $id ("与上次可比扫描相比增长 {0} GiB；不是可释放空间。" -f (GiB $growth)) ($previous.measuredAtUtc + '|' + $stats.logicalBytes)
                }
            }
        }
    }

    foreach ($kind in @('workspace', 'cache', 'skill')) {
        $key = @{ workspace = 'workspaceRoots'; cache = 'cacheRoots'; skill = 'skillRoots' }[$kind]
        $roots = if ($kind -eq 'cache') {
            @($cfg.cacheRoots | ForEach-Object { if ($_ -is [string]) { $_ } else { [string](Get-SpecValue $_ 'path') } })
        } else { @($cfg[$key]) }
        foreach ($root in @($roots | Select-Object -Unique)) { if ($root) { Measure-Root $root $kind } }
        if (@($roots | Where-Object { $_ }).Count -eq 0) { Add-Coverage $kind 'not_configured' '未选择目录，没有扫描。' }
    }
    $data.directories = @($directoryResults)

    # -----------------------------------------------------------------------
    # Skills (drift only)
    # -----------------------------------------------------------------------
    $skills = [Collections.Generic.List[object]]::new()
    foreach ($root in $cfg.skillRoots) {
        try {
            $rootPath = Assert-PathBoundary $root
            $count = 0
            foreach ($folder in [IO.Directory]::EnumerateDirectories($rootPath)) {
                if (++$count -gt 1000) { Add-Coverage ('skill-instructions:' + $root) 'partial' 'Skill 子目录数量超过 1000。'; break }
                if ([IO.Path]::GetFileName($folder).StartsWith('.')) { continue }
                $file = Join-Path $folder 'SKILL.md'
                if (-not [IO.File]::Exists($file)) { continue }
                try {
                    $null = Assert-PathBoundary $file
                    if ((Get-Item -LiteralPath $file).Length -gt 1MB) { throw 'Skill 说明超过 1 MiB。' }
                    $text = [IO.File]::ReadAllText($file, $utf8)
                    $name = [IO.Path]::GetFileName($folder)
                    if ($text -match '(?m)^name:\s*["'']?([^\r\n"'']+)') { $name = $Matches[1].Trim() }
                    $skills.Add([ordered]@{ name = $name; path = $folder
                                            instructionsSha256 = (Hash-Text ($text.Replace("`r`n", "`n"))); lastUsed = $null })
                } catch { Add-Coverage ('skill-instructions:' + $folder) 'partial' '说明文件过大、受保护或不可访问，未读取。' }
            }
        } catch { Add-Coverage ('skill-instructions:' + $root) 'error' 'Skill 根目录未能完整读取。' }
    }
    $data.skills = @($skills)
    if ($cfg.skillRoots.Count -gt 0) {
        $skillInstructionErrors = @($coverage | Where-Object { $_.id.StartsWith('skill-instructions:') -and $_.status -ne 'ok' })
        Add-Coverage 'skills' $(if ($skillInstructionErrors.Count -gt 0) { 'partial' } else { 'ok' }) '同名比较仅覆盖可读取的独立 Skill 说明。'
    } else { Add-Coverage 'skills' 'not_configured' '未选择独立 Skill 根目录。' }

    $data.duplicateSkills = @($skills | Group-Object { $_.name } | Where-Object Count -gt 1 | ForEach-Object {
        $same = (@($_.Group.instructionsSha256 | Select-Object -Unique).Count -eq 1)
        if (-not $same) {
            Add-Finding ('drift-skill:' + $_.Name) 'review' 'skills' ('同名 Skill 内容不一致：' + $_.Name + '；需核实哪一份是当前版本，不据此删除。') (($_.Group.path | Sort-Object) -join '|')
        }
        [ordered]@{ name = $_.Name; paths = @($_.Group | ForEach-Object { $_.path }); sameInstructions = $same; wholeDirectoryEquality = 'not_checked' }
    })
    $driftSkills = @($data.duplicateSkills | Where-Object { -not $_.sameInstructions })
    $sameSkills = @($data.duplicateSkills | Where-Object { $_.sameInstructions })
    $data.skillSummary = [ordered]@{ duplicateGroups = @($data.duplicateSkills).Count; sameCount = $sameSkills.Count; driftCount = $driftSkills.Count }

    # -----------------------------------------------------------------------
    # System checks
    # -----------------------------------------------------------------------
    function Compare-Inventory([string]$Id, [array]$Items) {
        $snapshots[$Id] = @{ items = @($Items | Sort-Object -Unique) }
        if ($previous -and $previous.snapshots.ContainsKey($Id)) {
            $old = @(Get-SpecValue $previous.snapshots[$Id] 'items')
            foreach ($item in $Items) { if ($item -notin $old) { $changes.Add([ordered]@{ check = $Id; type = 'added'; item = $item; notify = $true }) } }
            foreach ($item in $old) { if ($item -notin $Items) { $changes.Add([ordered]@{ check = $Id; type = 'removed'; item = $item; notify = $true }) } }
        }
    }
    function Query-System([string]$Id, [scriptblock]$Query) {
        if ($SkipSystemChecks) { Add-Coverage $Id 'not_checked' '本次使用 SkipSystemChecks。'; return }
        try { & $Query; Add-Coverage $Id 'ok' '查询完成；仅覆盖当前账户可见范围。' }
        catch {
            $detail = "查询失败（$($_.Exception.GetType().Name)）；未将失败当作正常或空结果。"
            Add-Coverage $Id 'error' $detail
        }
    }

    Query-System 'system' {
        $os = Get-CimInstance Win32_OperatingSystem -Property LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory -OperationTimeoutSec 15
        $data.system = [ordered]@{ lastBootUtc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
                                   totalMemoryBytes = ([long]$os.TotalVisibleMemorySize * 1KB)
                                   availableMemoryBytes = ([long]$os.FreePhysicalMemory * 1KB) }
        $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -Property DeviceID, Size, FreeSpace -OperationTimeoutSec 15 | ForEach-Object {
            if ($_.Size -gt 0) {
                $pct = [Math]::Round(100.0 * $_.FreeSpace / $_.Size, 1)
                if ($pct -lt [double]$cfg.thresholds.diskFreePercentWarn) {
                    Add-Finding ('low-disk:' + $_.DeviceID) 'warning' 'disk' ("{0} 剩余 {1} GiB（{2}%）。" -f $_.DeviceID, (GiB $_.FreeSpace), $pct)
                }
                [ordered]@{ drive = $_.DeviceID; sizeBytes = $_.Size; freeBytes = $_.FreeSpace; freePercent = $pct }
            }
        })
        $data.disks = $disks
        $memPct = [Math]::Round(100.0 * $data.system.availableMemoryBytes / $data.system.totalMemoryBytes, 1)
        if ($memPct -lt [double]$cfg.thresholds.memAvailablePercentWarn) {
            Add-Finding ('low-memory:snapshot') 'review' 'memory' ('当前可用内存 {0} GiB（{1}%），单次快照不代表长期故障。' -f (GiB $data.system.availableMemoryBytes), $memPct)
        }
    }

    Query-System 'startup' {
        $items = @(Get-CimInstance Win32_StartupCommand -Property Name, Location, Command -OperationTimeoutSec 15 | ForEach-Object {
            $target = Get-StartupExecutable $_.Command
            [ordered]@{ name = $_.Name; location = $_.Location; executable = $target }
        })
        $data.startup = $items
        $old = if ($previous -and $previous.snapshots.ContainsKey('startup')) { $previous.snapshots.startup } else { $null }
        $comparison = Compare-StartupInventory $items $old
        $snapshots.startup = $comparison.snapshot
        foreach ($change in $comparison.changes) { $changes.Add($change) }
        $unknown = @($items | Where-Object { -not $_.executable }).Count
        if ($unknown -gt 0) {
            Add-Coverage 'startup-targets' 'partial' ("{0} 个启动项的可执行目标无法可靠提取；未保存参数，未据此认定安全。" -f $unknown)
        } else { Add-Coverage 'startup-targets' 'ok' '启动项目标已提取；没有比较解释器后面的脚本参数。' }
    }

    Query-System 'listeners' {
        $connections = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue -ErrorVariable connectionErrors)
        if (@($connectionErrors | Where-Object { $_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*' }).Count -gt 0) { throw '监听查询失败。' }
        if ($connections.Count -gt 1000) { throw '监听记录超过 1000，需要缩小范围。' }
        $items = @($connections | ForEach-Object {
            $procName = 'unknown'; $procPath = $null
            try { $proc = Get-Process -Id $_.OwningProcess; $procName = $proc.ProcessName; $procPath = $proc.Path } catch { }
            [ordered]@{ address = $_.LocalAddress; port = $_.LocalPort; processId = $_.OwningProcess
                        process = $procName; executable = $procPath }
        })
        $data.listeners = $items
        $old = if ($previous -and $previous.snapshots.ContainsKey('listeners')) { $previous.snapshots.listeners } else { $null }
        $comparison = Compare-ListenerInventory $items $old
        $snapshots.listeners = $comparison.snapshot
        foreach ($change in $comparison.changes) { $changes.Add($change) }
    }

    # Power is advisory-only and off by default: powercfg /requests needs elevation.
    if ($cfg.system.power.enabled) {
        Query-System 'power' {
            $psi = [Diagnostics.ProcessStartInfo]::new((Get-SystemPowerTool))
            $psi.ArgumentList.Add('/requests'); $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
            $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
            $proc = [Diagnostics.Process]::Start($psi)
            $stdout = $proc.StandardOutput.ReadToEndAsync(); $stderr = $proc.StandardError.ReadToEndAsync()
            if (-not $proc.WaitForExit(15000)) { $proc.Dispose(); throw '电源查询超时。' }
            $raw = $stdout.GetAwaiter().GetResult(); $null = $stderr.GetAwaiter().GetResult()
            $exitCode = $proc.ExitCode; $proc.Dispose()
            if ($exitCode -ne 0) { throw '电源查询需要额外权限或不可用。' }
            $data.powerRequests = $raw.Trim()
            Compare-Inventory 'power' @($raw.Trim())
        }
    } else {
        Add-Coverage 'power' 'not_checked' '配置中未启用（非管理员下 powercfg /requests 必然失败）。'
    }

    if ($cfg.taskPathPrefixes.Count -eq 0) { Add-Coverage 'scheduled-tasks' 'not_configured' '未选择系统任务计划路径；AI 工具自动化也未由此检查。' }
    else {
        Query-System 'scheduled-tasks' {
            $tasks = [Collections.Generic.List[object]]::new()
            foreach ($prefix in $cfg.taskPathPrefixes) {
                if ($prefix -notmatch '^\\' -or $prefix -match '[*?\[\]]') { throw '任务路径必须是无通配符的前缀。' }
                $selected = @(Get-ScheduledTask -TaskPath ($prefix + '*') -ErrorAction Stop)
                foreach ($task in $selected) {
                    $info = Get-ScheduledTaskInfo -InputObject $task
                    $id = $task.TaskPath + $task.TaskName
                    $tasks.Add([ordered]@{ name = $id; state = [string]$task.State
                                           lastRun = $info.LastRunTime.ToString('o'); result = $info.LastTaskResult })
                    $warning = New-TaskResultFinding $id $info.LastTaskResult ([string]$task.State)
                    if ($warning) { $findings.Add($warning) }
                }
            }
            $data.scheduledTasks = @($tasks)
            Compare-Inventory 'scheduled-tasks' @($tasks | ForEach-Object { $_.name })
        }
    }
    if ($cfg.serviceNames.Count -eq 0) { Add-Coverage 'services' 'not_configured' '未选择服务名称。' }
    else {
        Query-System 'services' {
            $items = @(foreach ($name in $cfg.serviceNames) {
                if ($name -match '[*?\[\]]') { throw '服务名称不能含通配符。' }
                $svc = Get-Service -Name $name
                if ($svc.StartType -eq 'Automatic' -and $svc.Status -eq 'Stopped') {
                    Add-Finding ('service-stopped:' + $name) 'review' 'services' ($name + ' 设置为自动启动但当前已停止；触发启动服务也可能正常。')
                }
                [ordered]@{ name = $name; status = [string]$svc.Status; startType = [string]$svc.StartType }
            })
            $data.services = $items
        }
    }

    foreach ($probe in $cfg.outputProbes) {
        try {
            $probePath = [string](Get-SpecValue $probe 'path')
            $probeDays = [int](Get-SpecValue $probe 'maxAgeDays')
            $p = Assert-PathBoundary $probePath
            if ($probeDays -lt 1 -or $probeDays -gt 365) { throw '产出检查 maxAgeDays 应为 1 至 365。' }
            $item = Get-Item -LiteralPath $p -Force
            if (($capturedAt.UtcDateTime - $item.LastWriteTimeUtc).TotalDays -gt $probeDays) {
                Add-Finding ('stale-output:' + $p) 'review' ('output:' + $p) ($p + ' 修改时间超过预期；不证明内容正确或任务失效。')
            }
            Add-Coverage ('output:' + $p) 'ok' '已检查存在性和修改时间，未读取正文。'
        } catch { Add-Coverage ('output:' + [string](Get-SpecValue $probe 'path')) 'error' $_.Exception.Message }
    }

    # -----------------------------------------------------------------------
    # Stability signals
    # -----------------------------------------------------------------------
    $data.stability = [ordered]@{ eventErrors = $null; crashes = $null; pageFile = $null; handleTotal = $null
                                   bootSecondsMedian = $null; diskHealth = $null; daysToFull = [ordered]@{} }
    $sinceDays = [double]$cfg.system.eventLogDays

    Query-System 'events' {
        $since = (Get-Date).AddDays(-$sinceDays)
        $evts = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = $since } -ErrorAction Stop)
        $groups = @($evts | Group-Object { $_.ProviderName + '#' + $_.Id } | Sort-Object Count -Descending | Select-Object -First 5)
        $top = @($groups | ForEach-Object {
            [ordered]@{ provider = ($_.Name -split '#')[0]; id = [int](($_.Name -split '#')[1]); count = $_.Count }
        })
        $data.stability.eventErrors = [ordered]@{ windowDays = $sinceDays; count = $evts.Count; top = $top }
        if ($evts.Count -gt 0) {
            Add-Finding ('events:system-errors') 'review' 'events' ("近 {0} 天系统日志有 {1} 条错误/严重事件；需看 Top 来源判断是否为持续性故障。" -f $sinceDays, $evts.Count) (($top | ForEach-Object { $_.provider + ':' + $_.id }) -join ',')
        }
    }

    Query-System 'crashes' {
        $since = (Get-Date).AddDays(-$sinceDays)
        $evts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2; StartTime = $since } -ErrorAction Stop)
        $app = @($evts | Where-Object { $_.ProviderName -in @('Application Error', '.NET Runtime', 'Windows Error Reporting') })
        $data.stability.crashes = [ordered]@{ count = $app.Count
            top = @($app | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                [ordered]@{ provider = $_.Name; count = $_.Count } }) }
        if ($app.Count -gt 0) { Add-Finding ('crashes:application') 'review' 'crashes' ("近 {0} 天应用崩溃/错误 {1} 次。" -f $sinceDays, $app.Count) ([string]$app.Count) }
    }

    Query-System 'paging' {
        $pf = @(Get-CimInstance Win32_PageFileUsage -ErrorAction Stop)
        $allocated = ($pf | Measure-Object -Property AllocatedBaseSize -Sum).Sum
        $used = ($pf | Measure-Object -Property CurrentUsage -Sum).Sum
        $pct = if ($allocated -gt 0) { [Math]::Round(100.0 * $used / $allocated, 1) } else { 0 }
        $data.stability.pageFile = [ordered]@{ allocatedMB = $allocated; usedMB = $used; usedPercent = $pct }
        if ($pct -ge 80) { Add-Finding ('paging:high') 'review' 'paging' ('页面文件使用率 {0}%，可能存在内存压力。' -f $pct) ([string]$pct) }
    }

    Query-System 'handles' {
        $total = ((Get-Process -ErrorAction SilentlyContinue | Measure-Object -Property Handles -Sum).Sum)
        $data.stability.handleTotal = [int]$total
        if ($previous -and $previous.ContainsKey('handleTotal') -and $previous.handleTotal -gt 0) {
            $delta = ($total - [int]$previous.handleTotal) / [double]$previous.handleTotal
            if ($delta -gt 0.2) { Add-Finding ('handles:growth') 'review' 'handles' ('句柄总数较上次增长 {0:P0}，需确认是否有进程泄漏。' -f $delta) ([string]$total) }
        }
    }

    Query-System 'diskhealth' {
        $disks = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            $counter = $null
            try { $counter = $_ | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }
            [ordered]@{ device = $_.FriendlyName; mediaType = [string]$_.MediaType; health = [string]$_.HealthStatus
                        wear = $(if ($counter) { $counter.Wear } else { $null })
                        readErrors = $(if ($counter) { $counter.ReadErrorsTotal } else { $null }) }
        })
        $data.stability.diskHealth = $disks
        $bad = @($disks | Where-Object { $_.health -and $_.health -ne 'Healthy' })
        if ($bad.Count -gt 0) { Add-Finding ('disk:health') 'warning' 'diskhealth' ('磁盘健康状态异常：' + (($bad | ForEach-Object { $_.device }) -join '、')) ($bad.Count) }
    }

    try {
        $evts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100 } -MaxEvents 10 -ErrorAction Stop)
        $times = foreach ($e in $evts) {
            $xml = [xml]$e.ToXml()
            $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'BootTime' }
            if ($node) { [int]$node.'#text' }
        }
        $sorted = @($times | Sort-Object)
        $median = if ($sorted.Count -gt 0) { $sorted[[int][Math]::Floor($sorted.Count / 2)] } else { $null }
        $data.stability.bootSecondsMedian = if ($median) { [Math]::Round($median / 1000.0, 1) } else { $null }
        if ($median -and ($median / 1000.0) -gt 60) { Add-Finding ('boot:slow') 'review' 'boot.perf' ('最近启动耗时中位数 {0:N1} 秒。' -f ($median / 1000.0)) ([string]$median) }
        Add-Coverage 'boot.perf' 'ok' '查询完成；该日志可能默认未启用。'
    } catch {
        # The diagnostics-performance log is often disabled; that is a gap, not a fault.
        Add-Coverage 'boot.perf' 'not_checked' '启动性能日志未启用或没有可用记录，本次无法判断启动耗时。'
    }

    foreach ($id in @('sfc', 'recycle-bin', 'deleted-open-files', 'browser-sites', 'ai-app-automations', 'repository-references', 'skill-usage', 'backup-restorability')) {
        Add-Coverage $id 'not_checked' '本版未自动覆盖，见 references/checklist.md；未知不代表正常。'
    }

    # -----------------------------------------------------------------------
    # Reclaim candidates + plan
    # -----------------------------------------------------------------------
    $cacheSpecs = [Collections.Generic.List[object]]::new()
    foreach ($spec in $cfg.cacheRoots) {
        $resolved = Resolve-CacheRootSpec $spec
        if ($resolved.name -in @('chrome', 'edge') -and $resolved.path) {
            $cacheSpecs.Add($resolved)
        } else {
            $cacheSpecs.Add($resolved)
        }
    }
    $workspaceResults = @($directoryResults | Where-Object { $_.kind -eq 'workspace' })
    $candidateState = if ($previous -and $previous.ContainsKey('candidates')) { $previous } else { $null }
    $reclaimResult = Get-ReclaimCandidates -Config $cfg -CacheSpecs @($cacheSpecs) -WorkspaceResults $workspaceResults `
        -State $candidateState -BlockSize 4096

    $items = @($reclaimResult.items | Where-Object { [long]$_.allocationBytes -gt 0 })
    $safe = @($items | Where-Object { $_.grade -eq 'A' })
    $confirm = @($items | Where-Object { $_.grade -eq 'B' })
    $advisory = @($items | Where-Object { $_.grade -eq 'C' })

    $data.reclaim = [ordered]@{
        safe     = [ordered]@{ bytes = (Sum-Allocation $safe); items = $safe.Count; caption = '删除后会自动重建' }
        confirm  = [ordered]@{ bytes = (Sum-Allocation $confirm); items = $confirm.Count; caption = '有代价或可能含你的内容' }
        advisory = [ordered]@{ bytes = (Sum-Allocation $advisory); items = $advisory.Count; caption = '仅提示，不进清理清单' }
        excluded = @($reclaimResult.excluded)
    }
    $data.candidates = @($items)

    $planItems = [Collections.Generic.List[object]]::new()
    $planSkipped = [Collections.Generic.List[object]]::new()
    $budget = [long]$cfg.cleanup.maxPerRunGB * 1GB
    $used = [long]0
    $maxItems = [int]$cfg.cleanup.maxItemsPerRun
    # The switch has to gate the assembly itself. Deciding it only in the report text left a
    # fully executable plan.json on disk while the report claimed nothing was generated.
    if (-not $cfg.cleanup.enabled) {
        $planSkipped.Add([ordered]@{ path = '(整个计划)'; reason = '配置中未启用清理计划（cleanup.enabled=false）' })
    } else {
        foreach ($c in ($items | Where-Object { $_.grade -in @('A', 'B') } | Sort-Object { $_.allocationBytes } -Descending)) {
            if ($planItems.Count -ge $maxItems) { $planSkipped.Add([ordered]@{ path = $c.path; reason = '超过单次条目上限' }); continue }
            if (-not $c.directDelete) { $planSkipped.Add([ordered]@{ path = $c.path; reason = '该类不使用整目录删除，需专用命令'; suggestedAction = $c.suggestedAction }); continue }
            # null = not checked (directories). Only a confirmed true blocks the item.
            if ($c.inUse -eq $true) { $planSkipped.Add([ordered]@{ path = $c.path; reason = '正在使用' }); continue }
            if (-not $cfg.cleanup.skipObservationCheck -and [int]$c.seenCount -lt 2) {
                $planSkipped.Add([ordered]@{ path = $c.path; reason = '首次观测，需下次体检再次确认' }); continue
            }
            if (($used + [long]$c.allocationBytes) -gt $budget) { $planSkipped.Add([ordered]@{ path = $c.path; reason = '超过单次体积上限' }); continue }
            $used += [long]$c.allocationBytes
            $planItems.Add($c)
        }
    }

    $data.plan = [ordered]@{ enabled = [bool]$cfg.cleanup.enabled
                             itemCount = $planItems.Count; totalBytes = $used; skipped = @($planSkipped) }
    if ($SkipSystemChecks -eq $false -and $planItems.Count -eq 0 -and $safe.Count -gt 0) {
        $advisories.Add([ordered]@{ id = 'plan:pending-observation'; message = '本轮识别到可回收候选，但均为首次观测；下次体检再次出现才会进入清理计划。' })
    }

    # -----------------------------------------------------------------------
    # Findings delta
    # -----------------------------------------------------------------------
    $previousRecords = @{}
    if ($previous -and $previous.version -eq 3 -and $previous.ContainsKey('findingRecords')) { $previousRecords = $previous.findingRecords }
    elseif ($previous -and $previous.version -eq 2 -and $previous.ContainsKey('findingRecords')) { $previousRecords = $previous.findingRecords }
    elseif ($previous -and $previous.ContainsKey('findingIds')) {
        foreach ($id in $previous.findingIds) {
            $check = 'legacy'
            if ($id -match '^coverage:(.*):(?:partial|error|refused|missing)$') { $check = $Matches[1] }
            elseif ($id.StartsWith('task-result:')) { $check = 'scheduled-tasks' }
            elseif ($id.StartsWith('low-disk:')) { $check = 'disk' }
            elseif ($id.StartsWith('drift-skill:')) { $check = 'skills' }
            elseif ($id.StartsWith('service-stopped:')) { $check = 'services' }
            elseif ($id.StartsWith('stale-output:')) { $check = 'output:' + $id.Substring(13) }
            $previousRecords[$id] = @{ id = $id; check = $check; severity = 'review'; fingerprint = $null; message = ('旧版告警待复核：' + $id) }
        }
    }
    if (-not $cfg.system.power.enabled -and $previousRecords.Count -gt 0) {
        foreach ($stale in @($previousRecords.Keys | Where-Object { $_ -like 'coverage:power*' })) { $previousRecords.Remove($stale) }
    }
    $outcomes = @{}
    foreach ($entry in $coverage) { $outcomes[$entry.id] = $entry.status }
    $outcomes.disk = if ($outcomes.ContainsKey('system')) { $outcomes.system } else { 'not_checked' }
    $findingDelta = Get-FindingDelta @($findings) $previousRecords $outcomes
    $pendingFindings = @($findingDelta.pending | ForEach-Object { $findingDelta.records[$_] })
    $actionableChanges = @($changes | Where-Object { $_.notify })
    $hasActionable = ($null -eq $previous -or $stateMigrated -or $findingDelta.new.Count -gt 0 -or
                      $findingDelta.changed.Count -gt 0 -or $findingDelta.recovered.Count -gt 0 -or $actionableChanges.Count -gt 0)
    $incomplete = @($coverage | Where-Object { $_.status -in @('error', 'refused', 'missing') }).Count -gt 0

    $diskHistory = @()
    if ($previous -and $previous.ContainsKey('diskFree')) { $diskHistory = @($previous.diskFree) }
    $diskFreeNow = [ordered]@{ at = $capturedAt.ToString('o') }
    foreach ($d in @($(if ($data.Contains('disks')) { $data.disks } else { @() }))) {
        if ($d) { $diskFreeNow[($d.drive.Substring(0, 1).ToLower() + 'Free')] = [long]$d.freeBytes }
    }
    $diskHistory = @($diskHistory) + @($diskFreeNow)
    if ($diskHistory.Count -gt 30) { $diskHistory = @($diskHistory | Select-Object -Last 30) }
    $data.stability.daysToFull = [ordered]@{}
    foreach ($d in @($(if ($data.Contains('disks')) { $data.disks } else { @() }))) {
        if ($d) {
            $letter = $d.drive.Substring(0, 1)
            $data.stability.daysToFull[$letter] = Get-DiskDaysToFull $diskHistory $letter ([double]$d.freeBytes)
        }
    }

    $result = [ordered]@{
        version = 3; readOnly = $true; measuredAtUtc = $capturedAt.ToString('o')
        status = $(if ($incomplete) { 'incomplete' } else { 'completed' })
        firstRun = ($null -eq $previous); stateMigrated = $stateMigrated
        hasActionableChanges = $hasActionable
        findings = @($findings); pendingFindings = $pendingFindings
        newFindingIds = $findingDelta.new; changedFindingIds = $findingDelta.changed; recoveredFindingIds = $findingDelta.recovered
        changes = @($changes); actionableChangeCount = $actionableChanges.Count
        advisories = @($advisories)
        coverage = @($coverage); data = $data
        reclaim = $data.reclaim; plan = $data.plan
        limitations = @(
            '目录大小为逻辑字节与分配字节两种口径；两者都不是可回收空间。',
            '不同扫描根和嵌套依赖可能重叠，不能相加。',
            '修改时间和同名、同哈希都不能证明无用或可删除。',
            '系统查询仅覆盖当前权限；不查询进程命令行，启动项配置只提取可执行目标，不保存参数。',
            '首次快照与历史快照均不等于用户认可的正常名单。',
            '本地监听连续两次被观察到不证明期间持续运行，也不代表可以关闭。'
        )
    }

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------
    function Write-NewFile([string]$Path, [string]$Content) {
        $null = Assert-PathBoundary $Path -AllowMissing
        $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $bytes = $utf8.GetBytes($Content); $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    }

    $planFile = $null
    if ($outputRoot) {
        $null = Assert-PathBoundary $outputRoot -AllowMissing
        $null = [IO.Directory]::CreateDirectory($outputRoot)
        $stamp = $capturedAt.ToOffset([TimeSpan]::FromHours(8)).ToString('yyyy-MM-dd-HHmmss-fff') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
        $jsonFile = Join-Path $outputRoot ($stamp + '-体检.json')
        $mdFile = Join-Path $outputRoot ($stamp + '-体检.md')
        $planFile = Join-Path $outputRoot ($stamp + '-plan.json')

        if ($cfg.cleanup.enabled) {
            $planObject = [ordered]@{ version = 1; generatedAtUtc = $capturedAt.ToString('o'); outDirectory = $outputRoot
                                      items = @($planItems); skipped = @($planSkipped) }
            Write-NewFile $planFile (($planObject | ConvertTo-Json -Depth 12) + "`n")
            $result.plan.path = $planFile
        } else {
            # No plan file at all: an empty-but-present file still reads as "a plan exists".
            $planFile = $null
            $result.plan.path = $null
        }

        $json = $result | ConvertTo-Json -Depth 30
        $lines = [Collections.Generic.List[string]]::new()
        $timeText = $capturedAt.ToOffset([TimeSpan]::FromHours(8)).ToString('yyyy-MM-dd HH:mm:ss')
        $lines.Add('# Windows 只读体检 ' + $timeText + '（北京时间）')
        $statusText = if ($incomplete) { '部分检查未完成，缺口见下方' } else { '已完成所选查询，保护性排除项不计入容量' }
        $writeWhat = if ($cfg.cleanup.enabled) { '仅写报告与计划' } else { '仅写报告（清理计划已关闭）' }
        $lines.Add("`n本次结果：$statusText。可回收 A 档 " + (Format-Size $data.reclaim.safe.bytes) +
                   "、B 档 " + (Format-Size $data.reclaim.confirm.bytes) + "；待审阅 " + $findings.Count + " 项。" + $writeWhat + "，不删除任何文件。")
        if ($stateMigrated) { $lines.Add("`n历史记录已升级到 version=3；新增候选计数从本次开始累积。") }

        $lines.Add("`n## 本机概况`n")
        if ($data.Contains('disks')) {
            foreach ($disk in $data.disks) {
                $d2f = if ($data.stability.daysToFull.Contains([string]$disk.drive.Substring(0, 1))) { $data.stability.daysToFull[[string]$disk.drive.Substring(0, 1)] } else { $null }
                $suffix = if ($d2f) { "；按当前消耗速度约 $d2f 次体检后写满" } else { '' }
                $lines.Add('- ' + $disk.drive + ' 可用 ' + (Format-Size $disk.freeBytes) + ' / 总计 ' + (Format-Size $disk.sizeBytes) + '（剩余 ' + $disk.freePercent + '%）' + $suffix + '。')
            }
        } else { $lines.Add('- 磁盘余量：本次未取得，不能判断为正常。') }
        if ($data.Contains('system')) {
            $lines.Add('- 内存快照：当前可用 ' + (Format-Size $data.system.availableMemoryBytes) + ' / ' + (Format-Size $data.system.totalMemoryBytes) + '；不是长期故障判断。')
            $boot = [DateTimeOffset]::Parse($data.system.lastBootUtc).ToOffset([TimeSpan]::FromHours(8))
            $lines.Add('- 系统报告的最近启动时间：' + $boot.ToString('yyyy-MM-dd HH:mm') + '（北京时间）。')
        }

        $lines.Add("`n## 可回收空间`n")
        foreach ($tier in @(@('A 可安全回收', $data.reclaim.safe), @('B 需确认', $data.reclaim.confirm), @('C 仅提示', $data.reclaim.advisory))) {
            $lines.Add('- **' + $tier[0] + '**：' + (Format-Size $tier[1].bytes) + '（' + $tier[1].items + ' 项）—— ' + $tier[1].caption)
        }
        if ($safe.Count -gt 0) {
            $lines.Add("`n### A 档明细（可再生）`n")
            foreach ($c in ($safe | Sort-Object { $_.allocationBytes } -Descending | Select-Object -First 15)) {
                $lines.Add('- ' + (Format-Size $c.allocationBytes) + ' · ' + $c.path)
                $lines.Add('  - ' + $c.reason + '；再生：' + $c.regenerate)
            }
        }
        if ($confirm.Count -gt 0) {
            $lines.Add("`n### B 档明细（有代价）`n")
            foreach ($c in ($confirm | Sort-Object { $_.allocationBytes } -Descending | Select-Object -First 15)) {
                $lines.Add('- ' + (Format-Size $c.allocationBytes) + ' · ' + $c.path)
                $lines.Add('  - ' + $c.reason + '；恢复：' + $c.restore)
            }
        }

        $lines.Add("`n## 清理计划`n")
        if (-not $cfg.cleanup.enabled) {
            $lines.Add('- 配置中已关闭清理计划生成（`cleanup.enabled=false`）：本次**没有生成 plan.json**，也没有可执行条目。')
            $lines.Add('- 上面的 A/B/C 档只是占用盘点，不构成清理清单。需要清理时先改配置再重跑体检。')
        } elseif ($planItems.Count -eq 0) {
            $lines.Add('- 本次无可执行条目。' + $(if ($safe.Count -gt 0) { '识别到的候选均为首次观测，需下次体检再次确认后才进入计划（两次观测原则）。' } else { '未识别到符合规则的候选。' }))
        } else {
            $lines.Add('- 可执行 ' + $planItems.Count + ' 项，合计 ' + (Format-Size $used) + '。计划文件：`' + $planFile + '`')
            $lines.Add('- 执行命令（默认 dry-run，必须显式 -Apply 才会移动文件）：')
            $lines.Add('  ```powershell')
            $lines.Add('  & ''<pwsh>'' -NoProfile -File ''<skill>/scripts/Invoke-Cleanup.ps1'' -PlanPath ''' + $planFile + ''' -QuarantineRoot ''' + $cfg.cleanup.quarantineRoot + '''')
            $lines.Add('  ```')
        }
        if ($planSkipped.Count -gt 0) {
            $lines.Add("`n本次未进入计划的原因：")
            foreach ($s in ($planSkipped | Select-Object -First 8)) { $lines.Add('- ' + $s.path + ' —— ' + $s.reason) }
        }

        $lines.Add("`n## 需要审阅的发现`n")
        if ($findings.Count -eq 0) { $lines.Add('已执行检查没有产生告警；未覆盖项目见下方。') }
        foreach ($f in $findings) {
            $label = if ($f.id -in $findingDelta.new) { '新增' } elseif ($f.id -in $findingDelta.changed) { '内容变化' } else { '仍需核实' }
            $lines.Add('- [' + $label + '] ' + $f.message)
        }
        if ($pendingFindings.Count -gt 0) {
            $lines.Add("`n## 历史告警，本次未能复核`n")
            foreach ($f in $pendingFindings) { $lines.Add('- ' + $f.message + '（本次相关检查未完成或未选择，没有据此判定恢复。）') }
        }

        $lines.Add("`n## 稳定性信号`n")
        $st = $data.stability
        if ($SkipSystemChecks) { $lines.Add('- 本次使用 SkipSystemChecks，系统与稳定性查询全部跳过；缺口见下方。') }
        elseif (-not $st.eventErrors -and -not $st.crashes -and -not $st.pageFile) { $lines.Add('- 系统检查未返回可用信号，原因见下方覆盖范围。') }
        if ($st.eventErrors) { $lines.Add('- 系统日志（近 ' + $st.eventErrors.windowDays + ' 天）错误/严重：' + $st.eventErrors.count + ' 条' + $(if ($st.eventErrors.top.Count -gt 0) { '；Top：' + (($st.eventErrors.top | ForEach-Object { $_.provider + '(' + $_.id + ')x' + $_.count }) -join '、') } else { '' }) + '。') }
        if ($st.crashes) { $lines.Add('- 应用崩溃/错误：' + $st.crashes.count + ' 次。') }
        if ($st.pageFile) { $lines.Add('- 页面文件：' + $st.pageFile.usedMB + ' / ' + $st.pageFile.allocatedMB + ' MB（' + $st.pageFile.usedPercent + '%）。') }
        if ($st.handleTotal) { $lines.Add('- 句柄总数：' + $st.handleTotal + '。') }
        if ($st.bootSecondsMedian) { $lines.Add('- 最近启动耗时中位数：' + $st.bootSecondsMedian + ' 秒。') }
        if ($st.diskHealth) { foreach ($dh in $st.diskHealth) { $lines.Add('- 磁盘 ' + $dh.device + '：健康 ' + $dh.health + $(if ($null -ne $dh.wear) { '；磨损 ' + $dh.wear + '%' } else { '' }) + '。') } }
        if ($advisories.Count -gt 0) { foreach ($a in $advisories) { $lines.Add('- 提示：' + $a.message) } }

        if ($data.skillSummary -and $data.skillSummary.duplicateGroups -gt 0) {
            $lines.Add("`n## Skill 同名情况`n")
            $lines.Add('- 同名 ' + $data.skillSummary.duplicateGroups + ' 组，说明一致的 ' + $data.skillSummary.sameCount + ' 组，不一致的 ' + $data.skillSummary.driftCount + ' 组' + $(if ($data.skillSummary.driftCount -gt 0) { '（见告警）' } else { '' }) + '。')
        }

        $lines.Add("`n## 与上次可比记录的变化`n")
        if ($null -eq $previous) { $lines.Add('首次采集，供你审阅；没有自动将当前状态设为正常名单。') }
        elseif ($changes.Count -eq 0) { $lines.Add('本次可比记录未观察到清单变化。') }
        $changeNames = @{ added = '新增'; removed = '不再观察到'; target_changed = '目标程序变化'; observed_again = '再次观察到' }
        foreach ($c in $changes) {
            $label = if ($c.notify) { '建议关注' } else { '仅记录' }
            $lines.Add('- [' + $label + '] ' + $c.check + ' ' + $changeNames[$c.type] + '：' + $c.item)
        }

        $lines.Add("`n## 目录占用（逻辑 / 分配）`n")
        foreach ($d in $directoryResults) {
            $completeness = if ($d.complete) { '所选范围统计完成' } else { '存在排除项或缺口，仅为可见部分' }
            $lines.Add('- ' + $d.path + '：' + (Format-Size $d.logicalBytes) + ' / ' + (Format-Size $d.allocationBytes) + '；' + $completeness)
            foreach ($bucket in $d.topLevel | Select-Object -First 8) { $lines.Add('  - ' + $bucket.name + '：' + (Format-Size $bucket.logicalBytes)) }
        }
        if ($data.reclaim.excluded.Count -gt 0) {
            $lines.Add("`n未纳入的路径：")
            foreach ($e in ($data.reclaim.excluded | Select-Object -First 10)) { $lines.Add('- ' + $e.path + ' —— ' + $e.reason) }
        }

        $lines.Add("`n## 覆盖范围与缺口`n")
        foreach ($c in $coverage) { $lines.Add('- [' + $c.status + '] ' + $c.id + '：' + $c.detail) }
        $lines.Add("`n## 判断边界`n")
        foreach ($l in $result.limitations) { $lines.Add('- ' + $l) }
        $planNote = if ($cfg.cleanup.enabled) { '清理计划保存在 plan.json。' } else { '清理计划已按配置关闭，本次没有生成 plan.json。' }
        $lines.Add("`n完整元数据保存在同名 JSON，" + $planNote + "本脚本没有删除、移动受检文件或修改系统设置。")

        Write-NewFile $jsonFile ($json + "`n")
        Write-NewFile $mdFile (($lines -join "`n") + "`n")

        if ($SaveState) {
            $merged = @{}
            if ($previous) { foreach ($key in $previous.snapshots.Keys) { $merged[$key] = $previous.snapshots[$key] } }
            foreach ($key in $snapshots.Keys) { $merged[$key] = $snapshots[$key] }

            $candidateMap = @{}
            if ($previous -and $previous.ContainsKey('candidates') -and $previous.candidates) {
                foreach ($k in $previous.candidates.Keys) { $candidateMap[$k] = $previous.candidates[$k] }
            }
            foreach ($c in $items) {
                $candidateMap[$c.path] = @{ firstSeenAt = $(if ($candidateMap.ContainsKey($c.path)) { $candidateMap[$c.path].firstSeenAt } else { $capturedAt.ToString('o') })
                                            lastSeenAt = $capturedAt.ToString('o'); seenCount = [int]$c.seenCount; category = $c.category }
            }
            $cleanupHistory = @()
            if ($previous -and $previous.ContainsKey('cleanupHistory')) { $cleanupHistory = @($previous.cleanupHistory) }

            $state = @{ version = 3; measuredAtUtc = $capturedAt.ToString('o'); snapshots = $merged
                        findingIds = @($findingDelta.records.Keys); findingRecords = $findingDelta.records
                        candidates = $candidateMap; diskFree = $diskHistory; cleanupHistory = $cleanupHistory
                        handleTotal = $data.stability.handleTotal }
            $temporary = Join-Path $outputRoot ('.state-' + [Guid]::NewGuid().ToString('N') + '.tmp')
            Write-NewFile $temporary (($state | ConvertTo-Json -Depth 30) + "`n")
            $null = Assert-PathBoundary $stateFile -AllowMissing
            [IO.File]::Move($temporary, $stateFile, $true)
        }

        [ordered]@{
            readOnly = $true; status = $result.status; firstRun = $result.firstRun; stateMigrated = $stateMigrated
            hasActionableChanges = $result.hasActionableChanges
            findingCount = $findings.Count; pendingFindingCount = $pendingFindings.Count
            reclaimSafeBytes = $data.reclaim.safe.bytes; reclaimConfirmBytes = $data.reclaim.confirm.bytes
            planItemCount = $planItems.Count; planBytes = $used
            report = $mdFile; evidence = $jsonFile; plan = $planFile; stateSaved = [bool]$SaveState
        } | ConvertTo-Json
    } else {
        $result | ConvertTo-Json -Depth 30
    }
} finally {
    if ($runLock) { $runLock.Dispose() }
}
