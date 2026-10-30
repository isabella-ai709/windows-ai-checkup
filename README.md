# Windows 只读电脑体检

`windows-ai-checkup` 是给本地 AI 助手使用的 Windows Skill：在明确授权的范围内盘点空间和运行状态，比较变化，生成中文 Markdown 报告与 JSON 证据。处理方式由使用者决定。

## 可以检查什么

- 固定磁盘余量、当前内存快照和系统报告的启动时间。
- 指定工作区、缓存目录的逻辑文件大小、顶层分布、开发依赖，以及已扫描范围内最大的文件/日志候选。
- 指定独立 Skill 目录的同名候选、说明哈希；不推测真实使用频率。
- 启动项名称、位置和可可靠提取的可执行目标。
- 监听端口、可见程序路径，以及配置选中的计划任务、服务和输出文件更新时间。
- 当前电源请求；权限不足时列为缺口，不自动提权。

变化记录和通知分开：任务换了错误码可以提示；已知程序的新本地监听先记录，再次观察到后提示一次。查询失败会保留尚未复核的历史告警。两个观测点不证明程序期间持续运行。

## 运行要求

- Windows，已有 PowerShell 7.2 或更新版本。Windows 自带的 Windows PowerShell 5.1 不满足此脚本要求。
- 不需要 Node.js 或第三方 PowerShell 模块。运行检查器不需要 Python；测试使用 Python 标准库。
- 系统查询的覆盖范围取决于本机权限与可用系统模块。

## 在 AI 助手中使用

安装前审阅 Skill 和脚本；如果你的环境有 `skill-inspector`，先完成安全审查。

将整个仓库文件夹作为 `windows-ai-checkup` 放入 AI 工具认可的 Skill 目录。保留 `SKILL.md`、`agents/`、`scripts/`、`references/` 和 `config.example.json`，尤其不要漏掉脚本旁的 `Checkup.Logic.psm1`。

然后告诉助手：

```text
使用 $windows-ai-checkup，在我确认的目录和系统检查范围内做一次只读体检。
先说明检查范围，给我中文报告，不做清理，不自动安装工具或申请管理员权限。
```

不同助手的 Skill 发现和定期任务能力不同。这个仓库不附带任何个人自动化，也不创建后台服务。

## 手动运行

1. 把 `config.example.json` 复制到你选择的位置，命名为 `config.json`，不要覆盖已有配置。
2. 按需填写 `workspaceRoots`、`cacheRoots`、`skillRoots` 和 `protectedRoots` 的本机绝对路径。空数组表示没有选中该类目录。
3. 选择独立的报告目录。它可以位于扫描根下面，但不能等于扫描根或包含扫描根。
4. 将下面的示例路径替换为你核实过的实际路径后运行：

```powershell
& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -NonInteractive -File 'C:\YourSkills\windows-ai-checkup\scripts\Invoke-WindowsCheckup.ps1' -ConfigPath 'C:\Checkup\config.json' -OutDirectory 'C:\Checkup\reports' -SaveState
```

PowerShell 7 的路径需按本机实际位置修改；不要依赖不明确来源的同名程序。检查器内部的 `powercfg.exe` 固定从 Windows 系统目录调用。

参数：

| 参数 | 作用 |
|---|---|
| `-ConfigPath` | 必须明确提供的个人配置文件绝对路径 |
| `-OutDirectory` | 可选的报告目录；指定后生成中文 Markdown 与完整 JSON |
| `-SaveState` | 保存供下次比较的状态；须同时指定报告目录 |
| `-SkipSystemChecks` | 只盘点配置选中的目录，跳过系统查询 |

不指定报告目录时，只向标准输出返回完整 JSON。指定报告目录时，标准输出返回摘要；从 `evidence` 对应的文件读取完整 `findings`、`pendingFindings`、`changes` 和 `coverage`。

## 配置与报告

| 配置项 | 用途 |
|---|---|
| `workspaceRoots` / `cacheRoots` | 明确选中的工作区与缓存目录 |
| `skillRoots` | 明确选中的独立 Skill 根目录 |
| `protectedRoots` | 不得扫描或写入的保护目录 |
| `taskPathPrefixes` | 系统任务计划路径前缀，不是 AI 应用的自动化列表 |
| `serviceNames` | 要检查的准确服务名称，不支持通配符 |
| `outputProbes` | 输出文件或目录的存在性与修改时间，例如 `{"path":"C:\\YourWorkspace\\output.txt","maxAgeDays":7}` |
| `limits` | 文件数量、目录深度及单根扫描时间上限 |

报告明确区分已完成、受限、失败、未配置和未检查。容量是逻辑字节，不是可回收空间；不同根、硬链接或嵌套依赖可能重复，不能直接相加。

历史状态为 version=2，支持迁移旧版 version=1。损坏状态不会被重置覆盖；输出目录的独占锁防止两个检查同时更新历史。报告文件使用唯一名称，不覆盖旧报告。

## 只读与隐私边界

“只读”指不修改受检对象。明确选择的输出目录可写入报告、锁文件和对比状态。

- 不删除、移动受检文件，不清空回收站，不结束进程，不停止服务或修改系统设置。
- 不下载或安装工具，不自动提权，不上传报告。
- 文件盘点只读取元数据；Skill 对比额外读取直接子目录中的 `SKILL.md`。
- 不读取项目正文、私人聊天或运行进程的完整命令行。启动配置只在内存中提取首个可执行路径，不保存或展示参数和原文。
- 跳过敏感名称、联接、符号链接和云端占位标记；拒绝整盘、用户主目录、宽泛系统目录和网络路径。
- 报告包含本机路径与系统元数据，应留在本机，不应作为仓库文件提交。

回收站汇总、已删除仍被程序占用的空间、浏览活动、备份恢复能力、AI 应用私有自动化等没有自动覆盖。完整边界见 [检查清单](references/checklist.md) 和 [安全说明](SECURITY.md)。

## 定期使用

由你选择的宿主定期任务工具运行同一命令。先明确频率、时间、范围和报告目录，再启用。

脚本成功且 `hasActionableChanges=false` 时可以保持安静；需要审阅时再通知。`changeCount` 只是记录量，不能代替通知条件。脚本不自行创建计划任务、启动项或常驻服务；本地任务运行还取决于电脑、宿主应用和权限状态。

## 测试与验证状态

```powershell
python -m unittest discover -s tests -v
```

本版在 Windows 上使用 PowerShell 7 和 Python 3.12 验证了 23 项样例测试。测试包含文件保护、范围拒绝、目录联接、最大候选、任务错误变化、启动目标、端口通知、并发保护、历史保留和格式迁移；不修改真实系统任务或进程，也不需要真实的个人配置或报告。

安全检查为人工源码审查；未执行 SkillSpector 自动扫描。Skill Creator 官方快速校验器在本地因缺少 PyYAML 未运行，元数据结构与引用已人工检查。这些验证不证明所有 Windows 版本和权限组合都已覆盖。

## 来源

检查方法参考 [Jianing1117/mac-ai-checkup](https://github.com/Jianing1117/mac-ai-checkup)，来源版本为 `d8bedc8dedcd240b5bacb8058e6b35512b64d7dc`。Windows 检查脚本为重新编写，没有把 Mac 脚本改路径后直接运行。

上游 MIT 许可声明保留在 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
