# 清理规则库

配合 `scripts/Get-ReclaimCandidates.ps1` 使用，代码与人读版需保持一致。

## 分级

| 等级 | 定义 | 是否进计划 |
|---|---|---|
| A 可再生 | 删除后由系统或软件自动重建，无语义损失 | 是 |
| B 有代价 | 重新下载/安装，或可能含用户内容，需逐项确认 | 是 |
| C 仅提示 | 体积大但依据不足，或有风险 | 否 |
| blocked | 正在使用、属于数据、命中白名单或保护区 | 否 |

冲突处理：一条路径命中多条规则时，取**最保守**的等级。

## 规则表

| 类别 | 匹配 | 判据 | 等级 | 再生 / 恢复 |
|---|---|---|---|---|
| `temp` | `%LOCALAPPDATA%\Temp\*` | 最后写入早于 `tempOlderThanDays` 且未被占用 | A | 程序自建 / 隔离区还原 |
| `cache-browser` | `*\Cache`、`*\Code Cache`、`*\GPUCache`、`*\Service Worker\CacheStorage` | 仅限配置中的浏览器配置目录 | A | 重新访问时重建 |
| `cache-pkg` | npm / pip / uv | 整目录 | A | 重新下载 |
| `cache-pkg-shared` | pnpm store | **禁止整目录删除**，只给 `prune` 建议 | B | 重新 install |
| `cache-browser-bin` | playwright 浏览器 | 整目录 | B | `playwright install` 重下 |
| `install-leftover` | `*-install-*` | 同级已存在解包后的运行时，且目录超过 `installLeftoverMinAgeHours`（默认 24 小时）未修改 | A | 安装器重下 |
| `runtime-previous` | `*.previous-*` | 保留最近 `keepPreviousRuntimes` 份，其余 | A | 失去回滚能力 |
| `log` | `*.log`、`*.out`、`*.err` | 大于 `logFileMB` 且超过 `logOlderThanDays` 未修改 | B | 内容可能仍有排查价值 |
| `dependency` | `node_modules`、`.venv`、`venv`、`__pycache__` | 所在项目超过 `staleDependencyDays` 未修改 | B | 重新安装依赖 |
| `large-file` | 任意大于 `largeFileMB` | — | C | 仅提示 |
| `blocked-data` | 保护区、白名单、`.git`、用户文档 | — | blocked | 不参与清理 |

体积下限：任何候选的可回收空间小于 `minCandidateMB`（默认 1 MiB）时直接转入 `excluded`，理由记作"清理收益低于操作成本"。一个只剩下 1 字节 `.gitignore` 的缓存目录属于此类——移走它要动一整个簇，下次启动又被重建。

## 占用检测的边界

`inUse` 只有三种取值，含义必须分清：

| 值 | 含义 |
|---|---|
| `true` | 文件已确认被占用（独占打开失败） |
| `false` | 文件已确认未被占用 |
| `null` | **未检测**。目录候选一律是这个值 |

目录无法用打开文件句柄的方式判定占用，所以体检阶段不会给它任何结论。把它写成 `false` 会被读成"已确认空闲"，这是错的。

默认 dry-run 对文件只用**只读句柄探测**（以读权限开、立即关，不请求写权限，只读文件不会被误报为占用），对目录则如实返回 `movable: null` —— 不猜。真正的移动可行性由 `-Apply` 本身逐项回答：`Move-Item` 失败的那一项进 `failed`，不会移一半。

需要提前确认目录可移动时，才显式加 `-ProbeMovable`，对目标做一次**同卷改名再改回**。这一步**不是只读的**：改名期间原路径不存在，按路径打开它的程序会失败；若还原失败或进程被强杀在两次调用之间，目标会留在 `<名字>.checkup-probe-*`，需要在结果里读出来并手工改回。

## 硬规则

1. 每条候选必须带 `reason`、`regenerate`、`restore`，缺一即降为 C
2. 同一路径连续 2 次体检被识别为候选才进计划（除非配置 `skipObservationCheck=true`）
3. `inUse=true` 的文件不进入计划；`null` 不等同于空闲，文件由 dry-run 的只读句柄探测复核，目录由 `-Apply` 逐项尝试
4. 单次默认上限 200 项 / 5 GB
5. 只移动不删除，隔离区保留 7 天
6. 跨盘不移动：隔离区必须与源文件同一磁盘
7. 执行时大小偏差超过 5% 直接跳过
8. dry-run 默认零副作用；`-ProbeMovable` 才做改名探测，且不得与 `-Apply` 同用；探测后无法还原时立即中止该项并报告残留路径
9. 清单是写前日志：先 `pending` 再移动，移完改 `moved`，原子写入；`status` 为 `in-progress` / `completed` / `completed-with-failures`
10. `-Undo` 不信任清单：清单必须物理位于它声明的隔离区内（新清单父目录 = `quarantineRunRoot`，旧清单在其下）；源必须在隔离区内，目标不得落入系统目录，体积与记录不符则拒绝；路径先 `GetFullPath` 规范化再判断，`..` 不能绕过
11. `cleanup.enabled=false` 时不生成计划、不写 plan.json，`plan.enabled=false`
12. 计划必须位于自身声明的 `outDirectory` 内；传 `-ConfigPath` 时条目须在 `workspaceRoots`/`cacheRoots` 之内、`protectedRoots` 之外，一条不合规整单拒绝
