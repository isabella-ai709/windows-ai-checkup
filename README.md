# Windows 只读体检与可回退清理

`windows-ai-checkup` 是给本地 AI 助手使用的 Windows Skill：盘点空间与运行状态，把可回收项分成 A/B/C 三级，生成中文报告、JSON 证据与一份清理计划。清理由独立脚本按计划执行，文件移入隔离区，可撤销。

## 能力

- 磁盘余量、内存快照、启动时间、按历史外推的写满时间
- 配置目录的逻辑/分配大小、顶层分布、依赖、大文件、大日志
- 缓存：npm、pip、uv、pnpm store、Playwright、Chrome、Edge、用户临时目录
- 运行时安装残留与旧版本备份识别
- 启动项、监听端口、计划任务、服务
- 系统日志错误、应用崩溃、页面文件、句柄数、启动耗时、磁盘健康
- 同名 Skill 差异（只报内容不一致的）

## 运行要求

- Windows + PowerShell 7.2 或更新（自带的 5.1 不满足）
- 零第三方依赖
- 系统查询覆盖范围取决于本机权限

## 使用

```powershell
& '<pwsh>' -NoProfile -File 'scripts\Invoke-WindowsCheckup.ps1' `
  -ConfigPath 'C:\Checkup\config.json' -OutDirectory 'C:\Checkup\reports' -SaveState
```

清理（默认 dry-run）：

```powershell
& '<pwsh>' -NoProfile -File 'scripts\Invoke-Cleanup.ps1' `
  -PlanPath 'C:\Checkup\reports\<stamp>-plan.json' -QuarantineRoot 'C:\Checkup\quarantine' `
  -ConfigPath 'config.json'
```

`-ConfigPath` 可选；传入时清理器逐条独立复核计划：条目必须在配置允许的根内、不在保护目录内，一条不合规即整单拒绝。

撤销：

```powershell
& '<pwsh>' -NoProfile -File 'scripts\Invoke-Cleanup.ps1' -Undo 'C:\Checkup\quarantine\<runId>\manifest.json'
```

`cleanup.enabled=false` 时体检不生成计划、不写 plan.json（`plan.enabled=false`，`plan.path=null`）。清单是写前日志；`-Undo` 要求清单物理位于它声明的隔离区内、源路径也在其中，路径先规范化再判断，`..` 绕不过去。

配置说明见 `config.example.json`，规则见 `references/cleanup-rules.md`。

## 边界

- 体检脚本不修改受检对象；只写报告目录
- 清理脚本只移动，不删除；不碰注册表、服务、电源计划、回收站
- 跨盘移动拒绝、大小偏差 >5% 跳过、系统与文档目录拒绝
- 报告含本机路径与系统元数据，应留在本机，不要提交到仓库

## 测试

```powershell
python -m unittest discover -s tests -v
```

需要 `pwsh` 在 PATH，或设置环境变量 `CHECKUP_PWSH` 指向 pwsh 可执行文件。

## 来源

检查方法参考 [Jianing1117/mac-ai-checkup](https://github.com/Jianing1117/mac-ai-checkup)，Windows 脚本为重新编写。上游许可声明见 `THIRD_PARTY_NOTICES.md`。
