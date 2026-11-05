Set-StrictMode -Version Latest

function Get-SystemPowerTool {
    $tool = Join-Path ([Environment]::SystemDirectory) 'powercfg.exe'
    if (-not [IO.File]::Exists($tool) -or (([int][IO.File]::GetAttributes($tool) -band 0x400) -ne 0)) {
        throw '系统目录中的 powercfg.exe 不可用；不回退到 PATH 查找。'
    }
    return $tool
}

function Get-StartupExecutable([string]$Command) {
    # Inspect only the first executable token; never emit or retain its arguments.
    $target = $null
    if ($Command -match '^\s*"([^"\r\n]+\.(?:exe|com))"(?=\s|$)') { $target = $Matches[1] }
    elseif ($Command -match '^\s*([^\s"\r\n]+\.(?:exe|com))(?=\s|$)') { $target = $Matches[1] }
    if (-not $target) { return $null }
    $target = [Environment]::ExpandEnvironmentVariables($target)
    if ($target -notmatch '^[A-Za-z]:\\' -or $target.Substring(2).Contains(':')) { return $null }
    return [IO.Path]::GetFullPath($target)
}

function New-TaskResultFinding([string]$Id, [uint32]$Result, [string]$State) {
    if ($State -eq 'Running' -or $Result -eq 0 -or $Result -in (0x41300..0x41308)) { return $null }
    $disabled = $State -eq 'Disabled'
    $code = '0x{0:X8}' -f $Result
    $message = if ($disabled) { $Id + ' 已禁用；停用前最后结果为 ' + $code + '，不是当前运行故障。' }
               else { $Id + ' 最后运行未返回成功（' + $code + '）；需核对记录和实际产出，不能直接认定持续故障。' }
    return @{ id = ('task-result:' + $Id); severity = $(if ($disabled) { 'review' } else { 'warning' })
              check = 'scheduled-tasks'; message = $message; fingerprint = ([string]$Result + '|disabled=' + $disabled) }
}

function Add-LargestCandidate([Collections.Generic.List[object]]$Candidates, [object]$Candidate, [int]$Limit = 20) {
    $Candidates.Add($Candidate)
    if ($Candidates.Count -gt $Limit) {
        $smallest = 0
        for ($i = 1; $i -lt $Candidates.Count; $i++) {
            if ($Candidates[$i].logicalBytes -lt $Candidates[$smallest].logicalBytes) { $smallest = $i }
        }
        $Candidates.RemoveAt($smallest)
    }
}

function Compare-StartupInventory([array]$Current, [hashtable]$Previous) {
    $old = @{}
    if ($Previous) {
        if ($Previous.ContainsKey('entries')) { $old = $Previous.entries }
        elseif ($Previous.ContainsKey('items')) { foreach ($key in $Previous.items) { $old[$key] = $null } }
    }
    $entries = @{}; $delta = [Collections.Generic.List[object]]::new()
    foreach ($item in $Current) {
        $key = $item.location + '|' + $item.name
        $target = $item.executable
        if ($Previous -and -not $old.ContainsKey($key)) {
            $delta.Add(@{ check = 'startup'; type = 'added'; item = $key; notify = $true })
        } elseif ($Previous -and $old[$key] -and $target -and $old[$key] -ine $target) {
            $delta.Add(@{ check = 'startup'; type = 'target_changed'; item = $key; before = $old[$key]; after = $target; notify = $true })
        }
        $entries[$key] = if ($target) { $target } elseif ($old.ContainsKey($key)) { $old[$key] } else { $null }
    }
    foreach ($key in $old.Keys) {
        if (-not $entries.ContainsKey($key)) { $delta.Add(@{ check = 'startup'; type = 'removed'; item = $key; notify = $true }) }
    }
    return @{ snapshot = @{ entries = $entries }; changes = @($delta) }
}

function Compare-ListenerInventory([array]$Current, [hashtable]$Previous) {
    $old = @{}
    if ($Previous) {
        if ($Previous.ContainsKey('entries')) { $old = $Previous.entries }
        elseif ($Previous.ContainsKey('items')) {
            foreach ($line in $Previous.items) {
                $parts = $line -split '\|', 3
                if ($parts.Count -ne 3) { continue }
                $exe = if ($parts[0] -match '^[A-Za-z]:\\') { $parts[0] } else { $null }
                $name = if ($exe) { [IO.Path]::GetFileNameWithoutExtension($exe) } else { $parts[0] }
                $key = ($name + '|' + $parts[1] + '|' + $parts[2]).ToLowerInvariant()
                $old[$key] = @{ executable = $exe; observations = 2; introduced = $false }
            }
        }
    }
    $entries = @{}; $delta = [Collections.Generic.List[object]]::new()
    foreach ($item in $Current) {
        $key = ($item.process + '|' + $item.address + '|' + $item.port).ToLowerInvariant()
        if ($entries.ContainsKey($key)) { continue }
        $parsed = $null
        $loopback = [Net.IPAddress]::TryParse($item.address, [ref]$parsed) -and [Net.IPAddress]::IsLoopback($parsed)
        $unknown = -not $item.process -or $item.process -eq 'unknown'
        $entry = @{ executable = $item.executable; observations = 2; introduced = $false }
        if ($Previous -and -not $old.ContainsKey($key)) {
            $notify = -not $loopback -or $unknown
            $entry.observations = 1; $entry.introduced = -not $notify
            $delta.Add(@{ check = 'listeners'; type = 'added'; item = $key; notify = $notify })
        } elseif ($old.ContainsKey($key)) {
            $prior = $old[$key]
            if ($prior.executable -and $entry.executable -and $prior.executable -ine $entry.executable) {
                $delta.Add(@{ check = 'listeners'; type = 'target_changed'; item = $key; before = $prior.executable; after = $entry.executable; notify = $true })
            }
            if (-not $entry.executable) { $entry.executable = $prior.executable }
            $entry.observations = [Math]::Min(2, 1 + [int]$prior.observations)
            if ($prior.introduced -and $entry.observations -ge 2) {
                $delta.Add(@{ check = 'listeners'; type = 'observed_again'; item = $key; notify = $true })
            }
        }
        $entries[$key] = $entry
    }
    foreach ($key in $old.Keys) {
        if (-not $entries.ContainsKey($key)) { $delta.Add(@{ check = 'listeners'; type = 'removed'; item = $key; notify = $false }) }
    }
    return @{ snapshot = @{ entries = $entries }; changes = @($delta) }
}

function Get-FindingDelta([array]$Current, [hashtable]$PreviousRecords, [hashtable]$Outcomes) {
    $records = @{}; $new = [Collections.Generic.List[string]]::new(); $changed = [Collections.Generic.List[string]]::new()
    $recovered = [Collections.Generic.List[string]]::new(); $pending = [Collections.Generic.List[string]]::new()
    foreach ($f in $Current) { $records[$f.id] = $f }
    foreach ($id in @($records.Keys)) {
        if (-not $PreviousRecords.ContainsKey($id)) { $new.Add($id) }
        elseif ($PreviousRecords[$id].fingerprint -and $PreviousRecords[$id].fingerprint -ne $records[$id].fingerprint) { $changed.Add($id) }
    }
    foreach ($id in $PreviousRecords.Keys) {
        if ($records.ContainsKey($id)) { continue }
        $old = $PreviousRecords[$id]
        $status = if ($Outcomes.ContainsKey($old.check)) { $Outcomes[$old.check] } else { 'not_checked' }
        if ($status -eq 'ok') { $recovered.Add($id) }
        elseif ($id.StartsWith('coverage:') -and $status -in @('partial', 'error', 'refused', 'missing')) {
            # A changed failure category replaces the old failure, without claiming recovery.
        } else { $records[$id] = $old; $pending.Add($id) }
    }
    return @{ records = $records; new = @($new); changed = @($changed); recovered = @($recovered); pending = @($pending) }
}

# ---------------------------------------------------------------------------
# v2 additions
# ---------------------------------------------------------------------------

function Get-StableHash([string]$Text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant().Substring(0, 16)
}

function Get-VolumeBlockSize([string]$Path) {    try {
        $drive = [IO.Path]::GetPathRoot($Path)
        $vol = Get-CimInstance Win32_Volume -Filter ("DriveLetter='{0}'" -f $drive.TrimEnd('\')) -ErrorAction Stop
        if ($vol -and $vol.BlockSize -gt 0) { return [int]$vol.BlockSize }
    } catch { }
    return 4096
}

function Get-AllocationSize([long]$Length, [int]$BlockSize) {
    if ($Length -le 0) { return [long]0 }
    if ($BlockSize -le 0) { return $Length }
    return [long]([Math]::Ceiling($Length / [double]$BlockSize) * $BlockSize)
}

function Test-FileInUse([string]$Path) {
    # Opens with FileShare.None: success means no other handle holds it. Read access, not
    # ReadWrite - a read-only file refuses write access and would be reported as busy even
    # though nobody is holding it.
    try {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        $fs.Dispose()
        return $false
    } catch [UnauthorizedAccessException] { return $true }
    catch { return $true }
}

function Test-LinkOrPlaceholder([string]$Path) {
    try {
        $attrs = [IO.File]::GetAttributes($Path)
        return (([int]$attrs -band 0x441400) -ne 0)
    } catch { return $true }
}

function Get-SpecValue($Spec, [string]$Key) {
    if ($null -eq $Spec) { return $null }
    if ($Spec -is [System.Collections.IDictionary]) { return $Spec[$Key] }
    return $Spec.$Key
}

function Resolve-CacheRootSpec([object]$Spec) {
    $named = @{
        'npm'          = "$env:LOCALAPPDATA\npm-cache"
        'pip'          = "$env:LOCALAPPDATA\pip\cache"
        'uv'           = "$env:LOCALAPPDATA\uv\cache"
        'pnpm-store'   = "$env:LOCALAPPDATA\pnpm\store"
        'playwright'   = "$env:LOCALAPPDATA\ms-playwright"
        'temp'         = "$env:LOCALAPPDATA\Temp"
        'chrome'       = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        'edge'         = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    }
    if ($Spec -is [string]) { return @{ name = [IO.Path]::GetFileName($Spec); path = $Spec } }
    $kind = Get-SpecValue $Spec 'kind'
    if ($kind -eq 'named') {
        $key = [string](Get-SpecValue $Spec 'name')
        if (-not $named.ContainsKey($key)) { return @{ name = $key; path = $null; unsupported = $true } }
        return @{ name = $key; path = $named[$key] }
    }
    $p = [string](Get-SpecValue $Spec 'path')
    return @{ name = [IO.Path]::GetFileName($p); path = $p }
}

function Resolve-BrowserCachePaths([string]$UserDataRoot, [string]$BrowserName) {
    $result = [Collections.Generic.List[object]]::new()
    if (-not (Test-Path -LiteralPath $UserDataRoot)) { return @($result) }
    $profiles = @(Get-ChildItem -LiteralPath $UserDataRoot -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })
    foreach ($profile in $profiles) {
        foreach ($sub in @('Cache', 'Code Cache', 'GPUCache', 'Service Worker\CacheStorage')) {
            $p = Join-Path $profile.FullName $sub
            if (Test-Path -LiteralPath $p) {
                $result.Add(@{ name = "$BrowserName/$($profile.Name)/$sub"; path = $p })
            }
        }
    }
    return @($result)
}

function Get-DiskDaysToFull($History, [string]$Drive, [double]$AvailableBytes) {
    # Linear fit over saved free-space samples; requires at least 5 points.
    if (-not $History -or @($History).Count -lt 5) { return $null }
    $points = @($History | Where-Object { $_.($Drive.ToLower() + 'Free') } )
    if ($points.Count -lt 5) { return $null }
    $n = $points.Count
    $xs = 0..($n - 1)
    $ys = @($points | ForEach-Object { [double]$_.($Drive.ToLower() + 'Free') })
    $meanX = ($xs | Measure-Object -Average).Average
    $meanY = ($ys | Measure-Object -Average).Average
    $num = 0.0; $den = 0.0
    for ($i = 0; $i -lt $n; $i++) { $num += ($xs[$i] - $meanX) * ($ys[$i] - $meanY); $den += [Math]::Pow($xs[$i] - $meanX, 2) }
    if ($den -eq 0) { return $null }
    $slope = $num / $den
    if ($slope -ge 0) { return $null }
    $perRun = -$slope
    if ($perRun -le 0) { return $null }
    $runsLeft = $AvailableBytes / $perRun
    return [int][Math]::Min(9999, [Math]::Round($runsLeft))
}

Export-ModuleMember -Function Get-SystemPowerTool, Get-StartupExecutable, New-TaskResultFinding,
    Add-LargestCandidate, Compare-StartupInventory, Compare-ListenerInventory, Get-FindingDelta,
    Get-VolumeBlockSize, Get-AllocationSize, Test-FileInUse, Test-LinkOrPlaceholder,
    Resolve-CacheRootSpec, Resolve-BrowserCachePaths, Get-DiskDaysToFull, Get-StableHash, Get-SpecValue
