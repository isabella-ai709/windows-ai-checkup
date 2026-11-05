# Rule engine: turns measurements into graded reclaim candidates.
# Dot-source from Invoke-WindowsCheckup.ps1; expects Get-AllocationSize / Test-FileInUse
# / Test-LinkOrPlaceholder / Resolve-BrowserCachePaths from Checkup.Logic.psm1.

$script:GradeByCacheName = @{
    'npm'          = @{ grade = 'A'; category = 'cache-pkg';        regenerate = '下次 npm install 时重新下载'; restore = '隔离区还原' }
    'pip'          = @{ grade = 'A'; category = 'cache-pkg';        regenerate = '下次 pip install 时重新下载'; restore = '隔离区还原' }
    'uv'           = @{ grade = 'A'; category = 'cache-pkg';        regenerate = '下次 uv 安装时重新下载'; restore = '隔离区还原' }
    'playwright'   = @{ grade = 'B'; category = 'cache-browser-bin'; regenerate = 'playwright install 重新下载浏览器'; restore = '隔离区还原' }
    'pnpm-store'   = @{ grade = 'B'; category = 'cache-pkg-shared'; regenerate = '各项目 pnpm install 重新链接'; restore = '隔离区还原' }
    'temp'         = @{ grade = 'A'; category = 'temp';             regenerate = '程序需要时自动重建'; restore = '隔离区还原' }
}

function ConvertTo-WildcardRegex([string]$Pattern) {
    $escaped = [Regex]::Escape($Pattern)
    $escaped = $escaped -replace '\\\*\\\*', '.*'
    $escaped = $escaped -replace '\\\*', '[^\\]*'
    return '^' + $escaped + '$'
}

function Test-PathWhitelisted([string]$Path, [array]$Patterns) {
    foreach ($p in $Patterns) {
        if (-not $p) { continue }
        if ($Path -match (ConvertTo-WildcardRegex ([string]$p))) { return $true }
    }
    return $false
}

function New-Candidate([string]$Path, [string]$Category, [string]$Grade, [string]$Reason,
                      [string]$Regenerate, [string]$Restore, [long]$Logical, [int]$BlockSize,
                      [datetime]$LastWrite, [switch]$DirectDelete, [string]$SuggestedAction) {
    return [ordered]@{
        id              = ('cand:' + (Get-StableHash ($Path + '|' + $Category)))
        path            = $Path
        category        = $Category
        grade           = $Grade
        logicalBytes    = $Logical
        allocationBytes = (Get-AllocationSize $Logical $BlockSize)
        lastWriteUtc    = $LastWrite.ToUniversalTime().ToString('o')
        reason          = $Reason
        regenerate      = $Regenerate
        restore         = $Restore
        directDelete    = [bool]$DirectDelete
        suggestedAction = $SuggestedAction
        # null means "not checked". Only files get a lock probe; a directory cannot be
        # tested this way, and claiming false for it would read as "confirmed idle".
        inUse           = $null
        inUseChecked    = $false
        seenCount       = 1
    }
}

function Get-DirStats([string]$Path) {
    $m = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum)
    $bytes = [long]0; $files = 0
    if ($m.Count -gt 0) {
        if ($null -ne $m[0].Sum) { $bytes = [long]$m[0].Sum }
        $files = [int]$m[0].Count
    }
    return @{ bytes = $bytes; files = $files }
}

function Get-ReclaimCandidates {
    param(
        [hashtable]$Config,
        [array]$CacheSpecs,
        [array]$WorkspaceResults,
        [hashtable]$State,
        [int]$BlockSize = 4096
    )

    $items = [Collections.Generic.List[object]]::new()
    $excluded = [Collections.Generic.List[object]]::new()
    $rules = $Config.rules
    $whitelist = @($Config.cleanup.whitelist)

    # ---- cache roots -------------------------------------------------------
    foreach ($spec in $CacheSpecs) {
        if (-not $spec.path) {
            $excluded.Add([ordered]@{ path = [string]$spec.name; reason = '内置命名表中没有该缓存，或路径不存在' })
            continue
        }
        if (-not (Test-Path -LiteralPath $spec.path)) {
            $excluded.Add([ordered]@{ path = $spec.path; reason = '路径不存在' })
            continue
        }
        if (Test-PathWhitelisted $spec.path $whitelist) {
            $excluded.Add([ordered]@{ path = $spec.path; reason = '命中白名单' })
            continue
        }

        # Browsers: expand to per-profile cache folders.
        if ($spec.name -in @('chrome', 'edge')) {
            $browserName = if ($spec.name -eq 'chrome') { 'Chrome' } else { 'Edge' }
            foreach ($bc in (Resolve-BrowserCachePaths $spec.path $browserName)) {
                if (Test-PathWhitelisted $bc.path $whitelist) { continue }
                $s = Get-DirStats $bc.path
                $items.Add((New-Candidate $bc.path 'cache-browser' 'A' '浏览器缓存，可由网页重新下载' `
                    '重新访问时自动重建' '隔离区还原' $s.bytes $BlockSize (Get-Item -LiteralPath $bc.path).LastWriteTime -DirectDelete))
            }
            continue
        }

        # Runtime-style folders: install leftovers and previous versions live one level down.
        $children = @(Get-ChildItem -LiteralPath $spec.path -Directory -Force -ErrorAction SilentlyContinue)
        $hasRuntimeChildren = @($children | Where-Object { $_.Name -match '(?i)(-install-|\.previous-)' }).Count -gt 0
        $looksLikeRuntimeRoot = ($spec.name -match '(?i)runtime') -or
            @($children | Where-Object { $_.Name -match '(?i)-runtime$' }).Count -gt 0

        if ($hasRuntimeChildren) {
            $keep = [int]$rules.keepPreviousRuntimes
            $previous = @($children | Where-Object { $_.Name -match '(?i)\.previous-' } | Sort-Object LastWriteTime -Descending)
            $keepIds = @()
            if ($keep -gt 0) { $keepIds = @($previous | Select-Object -First $keep | ForEach-Object { $_.FullName }) }

            foreach ($child in $children) {
                if ($child.Name -match '(?i)-install-') {
                    $ageHours = ((Get-Date) - $child.LastWriteTime).TotalHours
                    if ($ageHours -lt [double]$rules.installLeftoverMinAgeHours) {
                        $excluded.Add([ordered]@{ path = $child.FullName; reason = ('安装刚发生（' + [int]$ageHours + ' 小时内），可能仍在使用') })
                        continue
                    }
                    $s = Get-DirStats $child.FullName
                    $items.Add((New-Candidate $child.FullName 'install-leftover' 'A' `
                        '安装器的解压/下载临时目录，运行时已解包到同级目录' `
                        '安装器需要时重新下载' '隔离区还原' $s.bytes $BlockSize $child.LastWriteTime -DirectDelete))
                } elseif ($child.Name -match '(?i)\.previous-') {
                    if ($keepIds -contains $child.FullName) { continue }
                    $s = Get-DirStats $child.FullName
                    $items.Add((New-Candidate $child.FullName 'runtime-previous' 'A' `
                        ('旧版本运行时备份（保留最近 ' + $keep + ' 份，当前为非保留项）') `
                        '升级时重新生成' '隔离区还原（失去回滚到该版本的能力）' $s.bytes $BlockSize $child.LastWriteTime -DirectDelete))
                }
            }
            continue
        }

        if ($looksLikeRuntimeRoot) {
            # The runtime body itself is in use; never offer it as a whole-directory candidate.
            $excluded.Add([ordered]@{ path = $spec.path; reason = '运行时本体目录，正在被使用，不作为整目录候选；只清理其中的安装残留与旧版本' })
            continue
        }

        # Plain cache directory.
        $map = if ($script:GradeByCacheName.ContainsKey($spec.name)) { $script:GradeByCacheName[$spec.name] }
               else { @{ grade = 'B'; category = 'cache-other'; regenerate = '重新下载'; restore = '隔离区还原' } }

        if ($spec.name -eq 'temp') {
            $cutoff = (Get-Date).AddDays(-[double]$rules.tempOlderThanDays)
            $entries = @(Get-ChildItem -LiteralPath $spec.path -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff })
            foreach ($e in $entries) {
                if (Test-PathWhitelisted $e.FullName $whitelist) { continue }
                $logical = if ($e.PSIsContainer) { (Get-DirStats $e.FullName).bytes } else { [long]$e.Length }
                $c = New-Candidate $e.FullName 'temp' 'A' `
                    ('用户临时目录，最后修改早于 ' + $rules.tempOlderThanDays + ' 天') `
                    '程序需要时自动重建' '隔离区还原' $logical $BlockSize $e.LastWriteTime -DirectDelete
                if (-not $e.PSIsContainer) {
                    $c.inUse = Test-FileInUse $e.FullName
                    $c.inUseChecked = $true
                }
                $items.Add($c)
            }
            continue
        }

        $s = Get-DirStats $spec.path
        $note = if ($map.category -eq 'cache-pkg-shared') { '共享存储，建议使用专用 prune 命令而不是整目录删除' } else { '缓存目录，删除后由工具重新生成' }
        $items.Add((New-Candidate $spec.path $map.category $map.grade $note $map.regenerate $map.restore `
            $s.bytes $BlockSize (Get-Item -LiteralPath $spec.path).LastWriteTime -DirectDelete:($map.grade -eq 'A') `
            -SuggestedAction $(if ($map.category -eq 'cache-pkg-shared') { 'pnpm store prune' } else { '' })))
    }

    # ---- workspace results -------------------------------------------------
    foreach ($root in $WorkspaceResults) {
        foreach ($dep in @($root.dependencies)) {
            if (-not $dep) { continue }
            if (Test-PathWhitelisted $dep.path $whitelist) { continue }
            $projectDir = Split-Path -Parent $dep.path
            $projAge = 999.0
            try { $projAge = ((Get-Date) - (Get-Item -LiteralPath $projectDir).LastWriteTime).TotalDays } catch { }
            if ($projAge -lt [double]$rules.staleDependencyDays) { continue }
            $items.Add((New-Candidate $dep.path 'dependency' 'B' `
                ('依赖目录，所在项目已 ' + [int]$projAge + ' 天未修改') `
                '重新安装依赖（npm install / 重建虚拟环境）' '隔离区还原' $dep.logicalBytes $BlockSize (Get-Item -LiteralPath $dep.path).LastWriteTime -DirectDelete))
        }
        foreach ($f in @($root.largeFiles)) {
            if (-not $f) { continue }
            if (Test-PathWhitelisted $f.path $whitelist) { continue }
            $items.Add((New-Candidate $f.path 'large-file' 'C' '体积较大，但缺少足够依据判断是否无用' `
                '无' '隔离区还原' $f.logicalBytes $BlockSize ([datetime]$f.modifiedUtc)))
        }
        foreach ($log in @($root.logs)) {
            if (-not $log) { continue }
            if (Test-PathWhitelisted $log.path $whitelist) { continue }
            $items.Add((New-Candidate $log.path 'log' 'B' `
                ('日志文件超过 ' + $rules.logFileMB + ' MB 且超过 ' + $rules.logOlderThanDays + ' 天未修改') `
                '无（内容不再产生）' '隔离区还原（内容可能仍有排查价值）' $log.logicalBytes $BlockSize ([datetime]$log.modifiedUtc) -DirectDelete))
        }
    }

    # ---- drop candidates too small to be worth the operation -----------------
    # A cache folder holding one stray 1-byte .gitignore costs a whole cluster and gets
    # recreated instantly. Keeping such entries only lengthens the plan and hides the ones
    # that matter, so they move to excluded with the reason recorded.
    $floorBytes = [long]([double]$rules.minCandidateMB * 1MB)
    for ($i = $items.Count - 1; $i -ge 0; $i--) {
        if ([long]$items[$i].allocationBytes -lt $floorBytes) {
            $excluded.Add([ordered]@{
                path = $items[$i].path
                reason = ('可回收空间小于 ' + $rules.minCandidateMB + ' MiB，清理收益低于操作成本')
            })
            $items.RemoveAt($i)
        }
    }

    # ---- seenCount from previous state ------------------------------------
    $prevCandidates = @{}
    if ($State -and $State.ContainsKey('candidates') -and $State.candidates) { $prevCandidates = $State.candidates }
    foreach ($item in $items) {
        $key = $item.path
        if ($prevCandidates.ContainsKey($key)) {
            $item.seenCount = 1 + [int](Get-SpecValue $prevCandidates[$key] 'seenCount')
        }
    }

    return @{ items = @($items); excluded = @($excluded) }
}
