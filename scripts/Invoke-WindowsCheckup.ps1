#requires -Version 7.2
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$OutDirectory,
    [switch]$SaveState,
    [switch]$SkipSystemChecks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Checkup.Logic.psm1') -Force
if (-not $IsWindows) { throw '此检查器仅支持 Windows。' }
if (-not $ConfigPath) { throw '请使用 -ConfigPath 指定个人配置；不会隐式扫描当前目录。' }
if ($SaveState -and -not $OutDirectory) { throw '-SaveState 需要明确的 -OutDirectory。' }
$utf8 = [Text.UTF8Encoding]::new($false)
$capturedAt = [DateTimeOffset]::UtcNow
$coverage = [Collections.Generic.List[object]]::new()
$findings = [Collections.Generic.List[object]]::new()
$changes = [Collections.Generic.List[object]]::new()
$snapshots = @{}
$data = [ordered]@{}
$sensitive = '(?i)^(\.git|\.ssh|\.aws|\.azure|\.gnupg|\.env(?:\..*)?|\.npmrc|\.pypirc|\.netrc|auth\.(json|ya?ml)|credentials?(?:\..*)?|secrets?(?:\..*)?|tokens?(?:\..*)?|passwords?(?:\..*)?|id_(rsa|ed25519|ecdsa)(?:\..*)?|.*\.(pem|key|p12|pfx|kdbx)|.*(身份证|护照|银行卡|助记词|private[-_ ]?key|recovery[-_ ]?phrase).*)$'

function Is-Within([string]$Child, [string]$Parent) {
    return $Child.Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or $Child.StartsWith($Parent.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}
function Normalize-Path([string]$Value) {
    if (-not $Value -or -not [IO.Path]::IsPathFullyQualified($Value) -or $Value.StartsWith('\\') -or $Value -notmatch '^[A-Za-z]:\\' -or $Value.Substring(2).Contains(':')) {
        throw '路径必须是本机磁盘上的绝对路径，不能使用网络路径或设备路径。'
    }
    return [IO.Path]::GetFullPath($Value).TrimEnd('\')
}
function Assert-PathBoundary([string]$Value, [switch]$AllowMissing) {
    $p = Normalize-Path $Value
    $broad = @([IO.Path]::GetPathRoot($Value).TrimEnd('\'), $env:USERPROFILE, $env:APPDATA, $env:LOCALAPPDATA, $env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, [IO.Path]::GetTempPath().TrimEnd('\'))
    if ($broad | Where-Object { $_ -and $p.Equals($_.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) }) { throw '拒绝整盘、用户主目录或宽泛系统目录。' }
    foreach ($root in $script:protected) { if (Is-Within $p $root) { throw '目标位于保护区。' } }
    foreach ($part in ($p -split '\\')) { if ($part -match $script:sensitive) { throw '目标名称属于敏感目录或文件。' } }
    $cursor = $p
    while ($cursor) {
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            $attrs = [IO.File]::GetAttributes($cursor)
            if (([int]$attrs -band 0x441400) -ne 0) { throw '目标或父目录是联接、符号链接、离线项或云端占位项。' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    if (-not $AllowMissing -and -not (Test-Path -LiteralPath $p)) { throw '目标不存在。' }
    return $p
}
function Add-Coverage([string]$Id, [string]$Status, [string]$Detail) {
    $coverage.Add([ordered]@{ id=$Id; status=$Status; detail=$Detail })
    if ($Status -in @('partial','error','refused','missing')) { Add-Finding ('coverage:'+$Id+':'+$Status) 'warning' $Id $Detail }
}
function Add-Finding([string]$Id, [string]$Severity, [string]$Check, [string]$Message, [string]$Evidence='') {
    $findings.Add([ordered]@{ id=$Id; severity=$Severity; check=$Check; message=$Message; fingerprint=(Hash-Text ($Severity+'|'+$Check+'|'+$Evidence)) })
}
function Hash-Text([string]$Text) { return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes($Text))).ToLowerInvariant() }
function GiB($Bytes) { return [Math]::Round([double]$Bytes / 1GB, 2) }
function Format-Size($Bytes) {
    if ($Bytes -ge 1GB) { return ('{0:N2} GiB' -f ($Bytes/1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MiB' -f ($Bytes/1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N1} KiB' -f ($Bytes/1KB)) }
    return ([string]$Bytes+' B')
}

$protected = @()
$configFile = Assert-PathBoundary $ConfigPath
if ((Get-Item -LiteralPath $configFile).Length -gt 1MB) { throw '配置文件超过 1 MiB。' }
$cfg = Get-Content -LiteralPath $configFile -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
if ($cfg.version -ne 1) { throw '仅支持 version=1 的配置。' }
foreach ($key in @('workspaceRoots','cacheRoots','skillRoots','protectedRoots','taskPathPrefixes','serviceNames','outputProbes')) {
    if (-not $cfg.ContainsKey($key) -or $cfg[$key] -isnot [array]) { throw "配置 $key 必须是数组。" }
}
$protected = @($cfg.protectedRoots | ForEach-Object { Normalize-Path $_ })
$limit = @{ maxEntries=50000; maxDepth=12; maxSecondsPerRoot=20 }
foreach ($key in @($limit.Keys)) {
    if ($cfg.ContainsKey('limits') -and $cfg.limits.ContainsKey($key)) { $limit[$key] = [int]$cfg.limits[$key] }
}
if ($limit.maxEntries -lt 1 -or $limit.maxEntries -gt 500000 -or $limit.maxDepth -lt 1 -or $limit.maxDepth -gt 30 -or $limit.maxSecondsPerRoot -lt 1 -or $limit.maxSecondsPerRoot -gt 60) { throw '扫描上限超出允许范围。' }

$outputRoot = $null
$stateFile = $null
$previous = $null
$runLock = $null
$stateMigrated = $false
try {
if ($OutDirectory) {
    $outputRoot = Assert-PathBoundary $OutDirectory -AllowMissing
    if ([IO.File]::Exists($outputRoot)) { throw '报告位置必须是目录。' }
    foreach ($root in @($cfg.workspaceRoots)+@($cfg.cacheRoots)+@($cfg.skillRoots)) {
        try { $normalized=Normalize-Path $root } catch { continue }
        if (Is-Within $normalized $outputRoot) { throw '报告目录不能等于扫描根或包含扫描根；允许放在扫描根的子目录。' }
    }
    $null=[IO.Directory]::CreateDirectory($outputRoot)
    $lockFile=Join-Path $outputRoot '.checkup.lock'
    $null=Assert-PathBoundary $lockFile -AllowMissing
    try { $runLock=[IO.File]::Open($lockFile,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
    catch { throw '报告目录已有体检正在运行，或锁文件不可访问；本次停止，不覆盖对比状态。' }
    $stateFile = Join-Path $outputRoot '.last-checkup.json'
    if (Test-Path -LiteralPath $stateFile) {
        $null = Assert-PathBoundary $stateFile
        if ((Get-Item -LiteralPath $stateFile).Length -gt 10MB) { throw '历史状态过大；为保护原记录已停止。' }
        try {
            $previous = Get-Content -LiteralPath $stateFile -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
            if ($previous.version -notin @(1,2) -or $previous.snapshots -isnot [hashtable] -or $previous.findingIds -isnot [array]) { throw '状态格式不支持。' }
            if ($previous.version -eq 2 -and $previous.findingRecords -isnot [hashtable]) { throw '告警状态格式不支持。' }
            $stateMigrated=$previous.version -eq 1
        } catch { throw '历史状态损坏或版本不支持；没有覆盖原记录，请先人工核实。' }
    }
}

function Measure-Root([string]$Root, [string]$Kind) {
    $id = "$Kind`:$Root"
    try { $rootPath = Assert-PathBoundary $Root -AllowMissing } catch { Add-Coverage $id 'refused' $_.Exception.Message; return }
    if (-not [IO.Directory]::Exists($rootPath)) { Add-Coverage $id 'missing' '目录不存在或当前账户不可访问。'; return }
    $stats = @{ logicalBytes=[long]0; files=0; directories=0; entries=0; skipped=0; inaccessible=0; limited=$false }
    $buckets = @{}
    $dependencies = @{}
    $largeFiles = [Collections.Generic.List[object]]::new()
    $clock = [Diagnostics.Stopwatch]::StartNew()
    # Breadth first: a large dependency tree must not hide every other project.
    $queue = [Collections.Generic.Queue[object]]::new()
    $queue.Enqueue(@{ path=$rootPath; depth=0; group='.'; dependency=$null })
    while ($queue.Count -gt 0) {
        if ($stats.entries -ge $limit.maxEntries -or $clock.Elapsed.TotalSeconds -ge $limit.maxSecondsPerRoot) { $stats.limited=$true; break }
        $item = $queue.Dequeue()
        $p = $item.path
        if (($outputRoot -and (Is-Within $p $outputRoot)) -or @($protected | Where-Object { Is-Within $p $_ }).Count -gt 0 -or [IO.Path]::GetFileName($p) -match $sensitive) { $stats.skipped++; continue }
        $stats.entries++
        try { $entry = Get-Item -LiteralPath $p -Force -ErrorAction Stop } catch { $stats.inaccessible++; continue }
        if (([int]$entry.Attributes -band 0x441400) -ne 0) { $stats.skipped++; continue }
        if ($entry.PSIsContainer) {
            $stats.directories++
            if ($entry.Name -in @('node_modules','.venv','venv','__pycache__','.next','dist','build')) {
                $dependencies[$p] = [ordered]@{ path=$p; logicalBytes=[long]0 }
                $item.dependency = $p
            }
            if ($item.depth -ge $limit.maxDepth) { $stats.limited=$true; continue }
            try {
                foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($p)) {
                    if ($queue.Count + $stats.entries -ge $limit.maxEntries) { $stats.limited=$true; break }
                    $group = if ($item.depth -eq 0) { [IO.Path]::GetFileName($child) } else { $item.group }
                    $queue.Enqueue(@{ path=$child; depth=$item.depth+1; group=$group; dependency=$item.dependency })
                }
            } catch { $stats.inaccessible++ }
        } else {
            $stats.files++; $stats.logicalBytes += $entry.Length
            if (-not $buckets.ContainsKey($item.group)) { $buckets[$item.group]=[long]0 }
            $buckets[$item.group] += $entry.Length
            if ($item.dependency) { $dependencies[$item.dependency].logicalBytes += $entry.Length }
            if ($entry.Length -ge 1GB -or ($entry.Extension -in @('.log','.out','.err') -and $entry.Length -ge 200MB)) {
                Add-LargestCandidate $largeFiles ([ordered]@{ path=$p; logicalBytes=$entry.Length; modifiedUtc=$entry.LastWriteTimeUtc.ToString('o') })
            }
        }
    }
    $clock.Stop()
    $complete = -not $stats.limited -and $stats.inaccessible -eq 0 -and $stats.skipped -eq 0
    $result = [ordered]@{ path=$rootPath; kind=$Kind; logicalBytes=$stats.logicalBytes; complete=$complete; stats=$stats; topLevel=@($buckets.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20 | ForEach-Object { [ordered]@{ name=$_.Key; logicalBytes=$_.Value } }); dependencies=@($dependencies.Values | Sort-Object { $_.logicalBytes } -Descending | Select-Object -First 30); largeFiles=@($largeFiles | Sort-Object { $_.logicalBytes } -Descending | Select-Object -First 20) }
    $script:directoryResults.Add($result)
    # Explicitly excluded entries make totals incomplete, but do not themselves indicate a fault.
    $status = if ($stats.limited -or $stats.inaccessible -gt 0) { 'partial' } else { 'ok' }
    Add-Coverage $id $status ("观察到 {0} 个文件，逻辑大小 {1} GiB；排除 {2}，不可访问 {3}，达到上限 {4}。" -f $stats.files,(GiB $stats.logicalBytes),$stats.skipped,$stats.inaccessible,$stats.limited)
    if ($status -eq 'ok') {
        $snapshots[$id] = @{ bytes=$stats.logicalBytes; skipped=$stats.skipped }
        if ($previous -and $previous.snapshots.ContainsKey($id) -and $previous.snapshots[$id].skipped -eq $stats.skipped) {
            $growth = $stats.logicalBytes - [long]$previous.snapshots[$id].bytes
            if ($growth -ge 2GB) { Add-Finding ('growth:'+$rootPath) 'warning' $id ("与上次可比扫描相比增长 {0} GiB；不是可释放空间。" -f (GiB $growth)) ($previous.measuredAtUtc+'|'+$stats.logicalBytes) }
        }
    }
}

$directoryResults = [Collections.Generic.List[object]]::new()
foreach ($kind in @('workspace','cache','skill')) {
    $key = @{workspace='workspaceRoots';cache='cacheRoots';skill='skillRoots'}[$kind]
    foreach ($root in @($cfg[$key] | Select-Object -Unique)) { Measure-Root $root $kind }
    if ($cfg[$key].Count -eq 0) { Add-Coverage $kind 'not_configured' '未选择目录，没有扫描。' }
}
$data.directories = @($directoryResults)

$skills = [Collections.Generic.List[object]]::new()
foreach ($root in $cfg.skillRoots) {
    try {
        $rootPath = Assert-PathBoundary $root
        $count = 0
        foreach ($folder in [IO.Directory]::EnumerateDirectories($rootPath)) {
            if (++$count -gt 1000) { Add-Coverage ('skill-instructions:'+$root) 'partial' 'Skill 子目录数量超过 1000。'; break }
            if ([IO.Path]::GetFileName($folder).StartsWith('.')) { continue }
            $file = Join-Path $folder 'SKILL.md'
            if (-not [IO.File]::Exists($file)) { continue }
            try {
                $null = Assert-PathBoundary $file
                if ((Get-Item -LiteralPath $file).Length -gt 1MB) { throw 'Skill 说明超过 1 MiB。' }
                $text = [IO.File]::ReadAllText($file, $utf8)
                $name = [IO.Path]::GetFileName($folder)
                if ($text -match '(?m)^name:\s*["'']?([^\r\n"'']+)') { $name = $Matches[1].Trim() }
                $skills.Add([ordered]@{ name=$name; path=$folder; instructionsSha256=(Hash-Text ($text.Replace("`r`n","`n"))); lastUsed=$null })
            } catch { Add-Coverage ('skill-instructions:'+$folder) 'partial' '说明文件过大、受保护或不可访问，未读取。' }
        }
    } catch { Add-Coverage ('skill-instructions:'+$root) 'error' 'Skill 根目录未能完整读取。' }
}
$data.skills = @($skills)
if ($cfg.skillRoots.Count -gt 0) {
    $skillInstructionErrors=@($coverage | Where-Object { $_.id.StartsWith('skill-instructions:') -and $_.status -ne 'ok' })
    Add-Coverage 'skills' $(if ($skillInstructionErrors.Count -gt 0) { 'partial' } else { 'ok' }) '同名比较仅覆盖可读取的独立 Skill 说明。'
} else { Add-Coverage 'skills' 'not_configured' '未选择独立 Skill 根目录。' }
$data.duplicateSkills = @($skills | Group-Object { $_.name } | Where-Object Count -gt 1 | ForEach-Object {
    Add-Finding ('duplicate-skill:'+$_.Name) 'review' 'skills' ('同名 Skill：'+$_.Name+'；需核实脚本和附带资源，不据此删除。') (($_.Group.path | Sort-Object) -join '|')
    [ordered]@{ name=$_.Name; paths=@($_.Group | ForEach-Object { $_.path }); sameInstructions=(@($_.Group.instructionsSha256 | Select-Object -Unique).Count -eq 1); wholeDirectoryEquality='not_checked' }
})

function Compare-Inventory([string]$Id, [array]$Items) {
    $snapshots[$Id] = @{ items=@($Items | Sort-Object -Unique) }
    if ($previous -and $previous.snapshots.ContainsKey($Id)) {
        $old = @($previous.snapshots[$Id].items)
        foreach ($item in $Items) { if ($item -notin $old) { $changes.Add([ordered]@{ check=$Id; type='added'; item=$item; notify=$true }) } }
        foreach ($item in $old) { if ($item -notin $Items) { $changes.Add([ordered]@{ check=$Id; type='removed'; item=$item; notify=$true }) } }
    }
}
function Query-System([string]$Id, [scriptblock]$Query) {
    if ($SkipSystemChecks) { Add-Coverage $Id 'not_checked' '本次使用 SkipSystemChecks。'; return }
    try { & $Query; Add-Coverage $Id 'ok' '查询完成；仅覆盖当前账户可见范围。' }
    catch {
        $detail = if ($Id -eq 'power') { '电源请求查询失败，当前权限或系统能力不足；未自动提权。' } else { "查询失败（$($_.Exception.GetType().Name)）；未将失败当作正常或空结果。" }
        Add-Coverage $Id 'error' $detail
    }
}
Query-System 'system' {
    $os = Get-CimInstance Win32_OperatingSystem -Property LastBootUpTime,TotalVisibleMemorySize,FreePhysicalMemory -OperationTimeoutSec 15
    $data.system = [ordered]@{ lastBootUtc=$os.LastBootUpTime.ToUniversalTime().ToString('o'); totalMemoryBytes=([long]$os.TotalVisibleMemorySize*1KB); availableMemoryBytes=([long]$os.FreePhysicalMemory*1KB) }
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -Property DeviceID,Size,FreeSpace -OperationTimeoutSec 15 | ForEach-Object {
        if ($_.Size -gt 0) {
            $pct=[Math]::Round(100.0*$_.FreeSpace/$_.Size,1)
            if ($_.FreeSpace -lt 20GB -and $pct -lt 10) { Add-Finding ('low-disk:'+$_.DeviceID) 'warning' 'disk' ("{0} 剩余 {1} GiB（{2}%）。" -f $_.DeviceID,(GiB $_.FreeSpace),$pct) }
            [ordered]@{ drive=$_.DeviceID; sizeBytes=$_.Size; freeBytes=$_.FreeSpace; freePercent=$pct }
        }
    })
    $data.disks=$disks
}
Query-System 'startup' {
    $items = @(Get-CimInstance Win32_StartupCommand -Property Name,Location,Command -OperationTimeoutSec 15 | ForEach-Object {
        $target=Get-StartupExecutable $_.Command
        [ordered]@{ name=$_.Name; location=$_.Location; executable=$target }
    })
    $data.startup=$items
    $old=if ($previous -and $previous.snapshots.ContainsKey('startup')) { $previous.snapshots.startup } else { $null }
    $comparison=Compare-StartupInventory $items $old
    $snapshots.startup=$comparison.snapshot
    foreach ($change in $comparison.changes) { $changes.Add($change) }
    $unknown=@($items | Where-Object { -not $_.executable }).Count
    if ($unknown -gt 0) { Add-Coverage 'startup-targets' 'partial' ("{0} 个启动项的可执行目标无法可靠提取；未保存参数，未据此认定安全。" -f $unknown) }
    else { Add-Coverage 'startup-targets' 'ok' '启动项目标已提取；没有比较解释器后面的脚本参数。' }
}
Query-System 'listeners' {
    $connections = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue -ErrorVariable connectionErrors)
    if (@($connectionErrors | Where-Object { $_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*' }).Count -gt 0) { throw '监听查询失败。' }
    if ($connections.Count -gt 1000) { throw '监听记录超过 1000，需要缩小范围。' }
    $items = @($connections | ForEach-Object {
        $procName='unknown'; $procPath=$null
        try { $proc=Get-Process -Id $_.OwningProcess; $procName=$proc.ProcessName; $procPath=$proc.Path } catch { }
        [ordered]@{ address=$_.LocalAddress; port=$_.LocalPort; processId=$_.OwningProcess; process=$procName; executable=$procPath }
    })
    $data.listeners=$items
    $old=if ($previous -and $previous.snapshots.ContainsKey('listeners')) { $previous.snapshots.listeners } else { $null }
    $comparison=Compare-ListenerInventory $items $old
    $snapshots.listeners=$comparison.snapshot
    foreach ($change in $comparison.changes) { $changes.Add($change) }
}
Query-System 'power' {
    $psi=[Diagnostics.ProcessStartInfo]::new((Get-SystemPowerTool)); $psi.ArgumentList.Add('/requests'); $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
    $proc=[Diagnostics.Process]::Start($psi)
    $stdout=$proc.StandardOutput.ReadToEndAsync(); $stderr=$proc.StandardError.ReadToEndAsync()
    # Do not stop a process, including this helper, if it exceeds the query budget.
    if (-not $proc.WaitForExit(15000)) { $proc.Dispose(); throw '电源查询超时。' }
    $raw=$stdout.GetAwaiter().GetResult(); $null=$stderr.GetAwaiter().GetResult()
    $exitCode=$proc.ExitCode; $proc.Dispose()
    if ($exitCode -ne 0) { throw '电源查询需要额外权限或不可用。' }
    $data.powerRequests=$raw.Trim()
    # Headings and localized None values are intentionally not parsed into guesses.
    Compare-Inventory 'power' @($raw.Trim())
}

if ($cfg.taskPathPrefixes.Count -eq 0) { Add-Coverage 'scheduled-tasks' 'not_configured' '未选择系统任务计划路径；AI 工具自动化也未由此检查。' }
else { Query-System 'scheduled-tasks' {
    $tasks=[Collections.Generic.List[object]]::new()
    foreach ($prefix in $cfg.taskPathPrefixes) {
        if ($prefix -notmatch '^\\' -or $prefix -match '[*?\[\]]') { throw '任务路径必须是无通配符的前缀。' }
        $selected=@(Get-ScheduledTask -TaskPath ($prefix+'*') -ErrorAction Stop)
        foreach ($task in $selected) {
            $info=Get-ScheduledTaskInfo -InputObject $task
            $id=$task.TaskPath+$task.TaskName
            $tasks.Add([ordered]@{ name=$id; state=[string]$task.State; lastRun=$info.LastRunTime.ToString('o'); result=$info.LastTaskResult })
            $warning=New-TaskResultFinding $id $info.LastTaskResult ([string]$task.State)
            if ($warning) { $findings.Add($warning) }
        }
    }
    $data.scheduledTasks=@($tasks)
    Compare-Inventory 'scheduled-tasks' @($tasks | ForEach-Object { $_.name })
} }
if ($cfg.serviceNames.Count -eq 0) { Add-Coverage 'services' 'not_configured' '未选择服务名称。' }
else { Query-System 'services' {
    $items=@(foreach ($name in $cfg.serviceNames) {
        if ($name -match '[*?\[\]]') { throw '服务名称不能含通配符。' }
        $svc=Get-Service -Name $name
        if ($svc.StartType -eq 'Automatic' -and $svc.Status -eq 'Stopped') { Add-Finding ('service-stopped:'+$name) 'review' 'services' ($name+' 设置为自动启动但当前已停止；触发启动服务也可能正常。') }
        [ordered]@{ name=$name; status=[string]$svc.Status; startType=[string]$svc.StartType }
    })
    $data.services=$items
} }

foreach ($probe in $cfg.outputProbes) {
    try {
        $p=Assert-PathBoundary $probe.path
        if ($probe.maxAgeDays -lt 1 -or $probe.maxAgeDays -gt 365) { throw '产出检查 maxAgeDays 应为 1 至 365。' }
        $item=Get-Item -LiteralPath $p -Force
        if (($capturedAt.UtcDateTime-$item.LastWriteTimeUtc).TotalDays -gt $probe.maxAgeDays) { Add-Finding ('stale-output:'+$p) 'review' ('output:'+$p) ($p+' 修改时间超过预期；不证明内容正确或任务失效。') }
        Add-Coverage ('output:'+$p) 'ok' '已检查存在性和修改时间，未读取正文。'
    } catch { Add-Coverage ('output:'+$probe.path) 'error' $_.Exception.Message }
}
foreach ($id in @('recycle-bin','deleted-open-files','browser-sites','ai-app-automations','repository-references','skill-usage','backup-restorability')) { Add-Coverage $id 'not_checked' '本版未自动覆盖，见 references/checklist.md；未知不代表正常。' }

$previousRecords=@{}
if ($previous -and $previous.version -eq 2) { $previousRecords=$previous.findingRecords }
elseif ($previous) {
    foreach ($id in $previous.findingIds) {
        $check='legacy'
        if ($id -match '^coverage:(.*):(?:partial|error|refused|missing)$') { $check=$Matches[1] }
        elseif ($id.StartsWith('task-result:')) { $check='scheduled-tasks' }
        elseif ($id.StartsWith('low-disk:')) { $check='disk' }
        elseif ($id.StartsWith('duplicate-skill:')) { $check='skills' }
        elseif ($id.StartsWith('service-stopped:')) { $check='services' }
        elseif ($id.StartsWith('stale-output:')) { $check='output:'+$id.Substring(13) }
        elseif ($id.StartsWith('growth:')) {
            $path=$id.Substring(7)
            $matching=@($previous.snapshots.Keys | Where-Object { $_.EndsWith(':'+$path,[StringComparison]::OrdinalIgnoreCase) })
            if ($matching.Count -gt 0) { $check=$matching[0] }
        }
        $previousRecords[$id]=@{ id=$id; check=$check; severity='review'; fingerprint=$null; message=('旧版告警待复核：'+$id) }
    }
}
$outcomes=@{}
foreach ($entry in $coverage) { $outcomes[$entry.id]=$entry.status }
$outcomes.disk=if ($outcomes.ContainsKey('system')) { $outcomes.system } else { 'not_checked' }
$findingDelta=Get-FindingDelta @($findings) $previousRecords $outcomes
$pendingFindings=@($findingDelta.pending | ForEach-Object { $findingDelta.records[$_] })
$actionableChanges=@($changes | Where-Object { $_.notify })
$hasActionable=($null -eq $previous -or $stateMigrated -or $findingDelta.new.Count -gt 0 -or $findingDelta.changed.Count -gt 0 -or $findingDelta.recovered.Count -gt 0 -or $actionableChanges.Count -gt 0)
$incomplete=@($coverage | Where-Object { $_.status -in @('error','partial','refused','missing') }).Count -gt 0
$result=[ordered]@{ version=2; readOnly=$true; measuredAtUtc=$capturedAt.ToString('o'); status=$(if ($incomplete) { 'incomplete' } else { 'completed' }); firstRun=($null -eq $previous); stateMigrated=$stateMigrated; hasActionableChanges=$hasActionable; findings=@($findings); pendingFindings=$pendingFindings; newFindingIds=$findingDelta.new; changedFindingIds=$findingDelta.changed; recoveredFindingIds=$findingDelta.recovered; changes=@($changes); actionableChangeCount=$actionableChanges.Count; coverage=@($coverage); data=$data; limitations=@('目录大小为逻辑字节，不是可回收空间；排除项及扫描上限可能使统计不完整。','不同扫描根和嵌套依赖可能重叠，不能相加。','修改时间和同名、同哈希都不能证明无用或可删除。','系统查询仅覆盖当前权限；不查询进程命令行，启动项配置只提取可执行目标，不保存参数。','首次快照与历史快照均不等于用户认可的正常名单。','本地监听连续两次被观察到不证明期间持续运行，也不代表可以关闭。') }

function Write-NewFile([string]$Path, [string]$Content) {
    $null=Assert-PathBoundary $Path -AllowMissing
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $bytes=$utf8.GetBytes($Content); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}
if ($outputRoot) {
    $null=Assert-PathBoundary $outputRoot -AllowMissing
    $null=[IO.Directory]::CreateDirectory($outputRoot)
    $stamp=$capturedAt.ToOffset([TimeSpan]::FromHours(8)).ToString('yyyy-MM-dd-HHmmss-fff')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,6)
    $jsonFile=Join-Path $outputRoot ($stamp+'-体检.json')
    $mdFile=Join-Path $outputRoot ($stamp+'-体检.md')
    $json=$result | ConvertTo-Json -Depth 30
    $lines=[Collections.Generic.List[string]]::new()
    $lines.Add('# Windows 只读体检 '+$capturedAt.ToOffset([TimeSpan]::FromHours(8)).ToString('yyyy-MM-dd HH:mm:ss')+'（北京时间）')
    $statusText=if ($incomplete) { '部分检查未完成，缺口见下方' } else { '已完成所选查询，保护性排除项不计入容量' }
    $lines.Add("`n本次结果：$statusText。当前有 $($findings.Count) 项需审阅；有 $($actionableChanges.Count) 项变化建议关注。仅写报告和对比状态。")
    if ($stateMigrated) { $lines.Add("`n历史记录已从旧版格式迁移；本次新增可执行目标等基线，不能据此认定目标刚被修改。") }
    $lines.Add("`n## 本机概况`n")
    if ($data.Contains('disks')) {
        foreach ($disk in $data.disks) { $lines.Add('- '+$disk.drive+' 可用 '+(Format-Size $disk.freeBytes)+' / 总计 '+(Format-Size $disk.sizeBytes)+'（剩余 '+$disk.freePercent+'%）。') }
    } else { $lines.Add('- 磁盘余量：本次未取得，不能判断为正常。') }
    if ($data.Contains('system')) {
        $lines.Add('- 内存快照：当前可用 '+(Format-Size $data.system.availableMemoryBytes)+' / '+(Format-Size $data.system.totalMemoryBytes)+'；不是长期故障判断。')
        $boot=[DateTimeOffset]::Parse($data.system.lastBootUtc).ToOffset([TimeSpan]::FromHours(8))
        $lines.Add('- 系统报告的最近启动时间：'+$boot.ToString('yyyy-MM-dd HH:mm')+'（北京时间）。')
    }
    foreach ($pair in @(@('startup','可见启动项'),@('listeners','监听记录'),@('scheduledTasks','已查询计划任务'))) {
        if ($data.Contains($pair[0])) { $lines.Add('- '+$pair[1]+'：'+@($data[$pair[0]]).Count+' 条。') }
    }
    $lines.Add("`n## 需要审阅的发现`n")
    if ($findings.Count -eq 0) { $lines.Add('已执行检查没有产生告警；未覆盖项目见下方。') }
    foreach ($f in $findings) {
        $label=if ($f.id -in $findingDelta.new) { '新增' } elseif ($f.id -in $findingDelta.changed) { '内容变化' } else { '仍需核实' }
        $lines.Add('- ['+$label+'] '+$f.message)
    }
    if ($pendingFindings.Count -gt 0) {
        $lines.Add("`n## 历史告警，本次未能复核`n")
        foreach ($f in $pendingFindings) { $lines.Add('- '+$f.message+'（本次相关检查未完成或未选择，没有据此判定恢复。）') }
    }
    if ($findingDelta.recovered.Count -gt 0) {
        $lines.Add("`n## 本次成功检查中不再出现的告警`n")
        foreach ($id in $findingDelta.recovered) { $lines.Add('- '+$previousRecords[$id].message+'（本次未再观察到，不等于已证明根因修复。）') }
    }
    $lines.Add("`n## 与上次可比记录的变化`n")
    if ($null -eq $previous) { $lines.Add('首次采集，供你审阅；没有自动将当前状态设为正常名单。') }
    if ($previous -and $changes.Count -eq 0) { $lines.Add('本次可比记录未观察到清单变化。') }
    $changeNames=@{ added='新增'; removed='不再观察到'; target_changed='目标程序变化'; observed_again='再次观察到' }
    foreach ($c in $changes) {
        $label=if ($c.notify) { '建议关注' } else { '仅记录' }
        $lines.Add('- ['+$label+'] '+$c.check+' '+$changeNames[$c.type]+'：'+$c.item)
        if ($c.Contains('before')) { $lines.Add('  - 原目标：'+$c.before+'；当前目标：'+$c.after) }
    }
    $lines.Add("`n## 目录占用（逻辑大小）`n")
    foreach ($d in $directoryResults) {
        $completeness=if ($d.complete) { '所选范围统计完成' } else { '存在排除项或缺口，仅为可见部分' }
        $lines.Add('- '+$d.path+'：'+(Format-Size $d.logicalBytes)+'；'+$completeness)
        foreach ($bucket in $d.topLevel | Select-Object -First 8) { $lines.Add('  - '+$bucket.name+'：'+(Format-Size $bucket.logicalBytes)) }
        foreach ($file in $d.largeFiles | Select-Object -First 5) { $lines.Add('  - 大文件/日志候选：'+$file.path+'（'+(Format-Size $file.logicalBytes)+'）；不代表可以删除。') }
    }
    $lines.Add("`n## 覆盖范围与缺口`n")
    foreach ($c in $coverage) { $lines.Add('- ['+$c.status+'] '+$c.id+'：'+$c.detail) }
    $lines.Add("`n## 判断边界`n")
    foreach ($l in $result.limitations) { $lines.Add('- '+$l) }
    $lines.Add("`n完整元数据保存在同名 JSON。没有删除、移动受检文件或修改系统设置。后续处理仍需具体授权。")
    Write-NewFile $jsonFile ($json+"`n")
    Write-NewFile $mdFile (($lines -join "`n")+"`n")
    if ($SaveState) {
        $merged=@{}
        if ($previous) { foreach ($key in $previous.snapshots.Keys) { $merged[$key]=$previous.snapshots[$key] } }
        foreach ($key in $snapshots.Keys) { $merged[$key]=$snapshots[$key] }
        $state=@{ version=2; measuredAtUtc=$capturedAt.ToString('o'); snapshots=$merged; findingIds=@($findingDelta.records.Keys); findingRecords=$findingDelta.records }
        $temporary=Join-Path $outputRoot ('.state-'+[Guid]::NewGuid().ToString('N')+'.tmp')
        Write-NewFile $temporary (($state | ConvertTo-Json -Depth 30)+"`n")
        $null=Assert-PathBoundary $stateFile -AllowMissing
        [IO.File]::Move($temporary,$stateFile,$true)
    }
    [ordered]@{ readOnly=$true; status=$result.status; firstRun=$result.firstRun; stateMigrated=$stateMigrated; hasActionableChanges=$result.hasActionableChanges; findingCount=$findings.Count; pendingFindingCount=$pendingFindings.Count; newFindingIds=$findingDelta.new; changedFindingIds=$findingDelta.changed; recoveredFindingIds=$findingDelta.recovered; changeCount=$changes.Count; actionableChangeCount=$actionableChanges.Count; report=$mdFile; evidence=$jsonFile; stateSaved=[bool]$SaveState } | ConvertTo-Json
} else { $result | ConvertTo-Json -Depth 30 }
} finally {
    if ($runLock) { $runLock.Dispose() }
}
