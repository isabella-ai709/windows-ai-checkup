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
    if ($Command -match '^\s*"([^"\r\n]+\.(?:exe|com))"(?=\s|$)') { $target=$Matches[1] }
    elseif ($Command -match '^\s*([^\s"\r\n]+\.(?:exe|com))(?=\s|$)') { $target=$Matches[1] }
    if (-not $target) { return $null }
    $target=[Environment]::ExpandEnvironmentVariables($target)
    if ($target -notmatch '^[A-Za-z]:\\' -or $target.Substring(2).Contains(':')) { return $null }
    return [IO.Path]::GetFullPath($target)
}

function New-TaskResultFinding([string]$Id, [uint32]$Result, [string]$State) {
    if ($State -eq 'Running' -or $Result -eq 0 -or $Result -in (0x41300..0x41308)) { return $null }
    $disabled=$State -eq 'Disabled'
    $code='0x{0:X8}' -f $Result
    $message=if ($disabled) { $Id+' 已禁用；停用前最后结果为 '+$code+'，不是当前运行故障。' } else { $Id+' 最后运行未返回成功（'+$code+'）；需核对记录和实际产出，不能直接认定持续故障。' }
    return @{ id=('task-result:'+$Id); severity=$(if ($disabled) { 'review' } else { 'warning' }); check='scheduled-tasks'; message=$message; fingerprint=([string]$Result+'|disabled='+$disabled) }
}

function Add-LargestCandidate([Collections.Generic.List[object]]$Candidates, [object]$Candidate, [int]$Limit=20) {
    $Candidates.Add($Candidate)
    if ($Candidates.Count -gt $Limit) {
        $smallest=0
        for ($i=1; $i -lt $Candidates.Count; $i++) {
            if ($Candidates[$i].logicalBytes -lt $Candidates[$smallest].logicalBytes) { $smallest=$i }
        }
        $Candidates.RemoveAt($smallest)
    }
}

function Compare-StartupInventory([array]$Current, [hashtable]$Previous) {
    $old=@{}
    if ($Previous) {
        if ($Previous.ContainsKey('entries')) { $old=$Previous.entries }
        elseif ($Previous.ContainsKey('items')) { foreach ($key in $Previous.items) { $old[$key]=$null } }
    }
    $entries=@{}; $delta=[Collections.Generic.List[object]]::new()
    foreach ($item in $Current) {
        $key=$item.location+'|'+$item.name
        $target=$item.executable
        if ($Previous -and -not $old.ContainsKey($key)) {
            $delta.Add(@{ check='startup'; type='added'; item=$key; notify=$true })
        } elseif ($Previous -and $old[$key] -and $target -and $old[$key] -ine $target) {
            $delta.Add(@{ check='startup'; type='target_changed'; item=$key; before=$old[$key]; after=$target; notify=$true })
        }
        $entries[$key]=if ($target) { $target } elseif ($old.ContainsKey($key)) { $old[$key] } else { $null }
    }
    foreach ($key in $old.Keys) {
        if (-not $entries.ContainsKey($key)) { $delta.Add(@{ check='startup'; type='removed'; item=$key; notify=$true }) }
    }
    return @{ snapshot=@{ entries=$entries }; changes=@($delta) }
}

function Compare-ListenerInventory([array]$Current, [hashtable]$Previous) {
    $old=@{}
    if ($Previous) {
        if ($Previous.ContainsKey('entries')) { $old=$Previous.entries }
        elseif ($Previous.ContainsKey('items')) {
            foreach ($line in $Previous.items) {
                $parts=$line -split '\|',3
                if ($parts.Count -ne 3) { continue }
                $exe=if ($parts[0] -match '^[A-Za-z]:\\') { $parts[0] } else { $null }
                $name=if ($exe) { [IO.Path]::GetFileNameWithoutExtension($exe) } else { $parts[0] }
                $key=($name+'|'+$parts[1]+'|'+$parts[2]).ToLowerInvariant()
                $old[$key]=@{ executable=$exe; observations=2; introduced=$false }
            }
        }
    }
    $entries=@{}; $delta=[Collections.Generic.List[object]]::new()
    foreach ($item in $Current) {
        $key=($item.process+'|'+$item.address+'|'+$item.port).ToLowerInvariant()
        if ($entries.ContainsKey($key)) { continue }
        $parsed=$null
        $loopback=[Net.IPAddress]::TryParse($item.address,[ref]$parsed) -and [Net.IPAddress]::IsLoopback($parsed)
        $unknown=-not $item.process -or $item.process -eq 'unknown'
        $entry=@{ executable=$item.executable; observations=2; introduced=$false }
        if ($Previous -and -not $old.ContainsKey($key)) {
            $notify=-not $loopback -or $unknown
            $entry.observations=1; $entry.introduced=-not $notify
            $delta.Add(@{ check='listeners'; type='added'; item=$key; notify=$notify })
        } elseif ($old.ContainsKey($key)) {
            $prior=$old[$key]
            if ($prior.executable -and $entry.executable -and $prior.executable -ine $entry.executable) {
                $delta.Add(@{ check='listeners'; type='target_changed'; item=$key; before=$prior.executable; after=$entry.executable; notify=$true })
            }
            if (-not $entry.executable) { $entry.executable=$prior.executable }
            $entry.observations=[Math]::Min(2,1+[int]$prior.observations)
            if ($prior.introduced -and $entry.observations -ge 2) {
                $delta.Add(@{ check='listeners'; type='observed_again'; item=$key; notify=$true })
            }
        }
        $entries[$key]=$entry
    }
    foreach ($key in $old.Keys) {
        if (-not $entries.ContainsKey($key)) { $delta.Add(@{ check='listeners'; type='removed'; item=$key; notify=$false }) }
    }
    return @{ snapshot=@{ entries=$entries }; changes=@($delta) }
}

function Get-FindingDelta([array]$Current, [hashtable]$PreviousRecords, [hashtable]$Outcomes) {
    $records=@{}; $new=[Collections.Generic.List[string]]::new(); $changed=[Collections.Generic.List[string]]::new(); $recovered=[Collections.Generic.List[string]]::new(); $pending=[Collections.Generic.List[string]]::new()
    foreach ($f in $Current) { $records[$f.id]=$f }
    foreach ($id in @($records.Keys)) {
        if (-not $PreviousRecords.ContainsKey($id)) { $new.Add($id) }
        elseif ($PreviousRecords[$id].fingerprint -and $PreviousRecords[$id].fingerprint -ne $records[$id].fingerprint) { $changed.Add($id) }
    }
    foreach ($id in $PreviousRecords.Keys) {
        if ($records.ContainsKey($id)) { continue }
        $old=$PreviousRecords[$id]
        $status=if ($Outcomes.ContainsKey($old.check)) { $Outcomes[$old.check] } else { 'not_checked' }
        if ($status -eq 'ok') { $recovered.Add($id) }
        elseif ($id.StartsWith('coverage:') -and $status -in @('partial','error','refused','missing')) {
            # A changed failure category replaces the old failure, without claiming recovery.
        } else { $records[$id]=$old; $pending.Add($id) }
    }
    return @{ records=$records; new=@($new); changed=@($changed); recovered=@($recovered); pending=@($pending) }
}

Export-ModuleMember -Function Get-SystemPowerTool,Get-StartupExecutable,New-TaskResultFinding,Add-LargestCandidate,Compare-StartupInventory,Compare-ListenerInventory,Get-FindingDelta
