"""Behavior checks using owned fixtures; does not query live system state."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / 'scripts' / 'Invoke-WindowsCheckup.ps1'
LOGIC = SCRIPT.with_name('Checkup.Logic.psm1')
PWSH = shutil.which('pwsh')


class CheckupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='windows-checkup-test-')
        self.root = Path(self.temp.name)
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir()
        self.reports = self.root / 'reports'
        self.config_file = self.root / 'config.json'
        self.config = {
            'version': 1, 'workspaceRoots': [str(self.workspace)], 'cacheRoots': [],
            'skillRoots': [], 'protectedRoots': [], 'taskPathPrefixes': [],
            'serviceNames': [], 'outputProbes': [],
            'limits': {'maxEntries': 1000, 'maxDepth': 10, 'maxSecondsPerRoot': 10},
        }
        self.junctions = []

    def tearDown(self):
        self.assertEqual(self.root.resolve().parent, Path(tempfile.gettempdir()).resolve())
        self.assertTrue(self.root.name.startswith('windows-checkup-test-'))
        # Only remove junction directory entries created in this owned fixture.
        for junction in self.junctions:
            if junction.exists():
                os.rmdir(junction)
        self.temp.cleanup()

    def run_check(self, save=False, output=True, ok=True):
        self.config_file.write_text(json.dumps(self.config), encoding='utf-8')
        args = [PWSH, '-NoProfile', '-NonInteractive', '-File', str(SCRIPT),
                '-ConfigPath', str(self.config_file), '-SkipSystemChecks']
        if output:
            args += ['-OutDirectory', str(self.reports)]
        if save:
            args += ['-SaveState']
        result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', timeout=60)
        if not ok:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            return result
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        detail = json.loads(Path(summary['evidence']).read_text(encoding='utf-8')) if output else summary
        return summary, detail

    def run_logic(self, body, payload=None):
        helper = self.root / 'logic-test.ps1'
        data_file = self.root / 'logic-input.json'
        data_file.write_text(json.dumps(payload or {}), encoding='utf-8')
        helper.write_text('param($ModulePath,$DataPath)\n'
                          'Set-StrictMode -Version Latest\n$ErrorActionPreference="Stop"\n'
                          'Import-Module $ModulePath -Force\n'
                          '$fixture=Get-Content -LiteralPath $DataPath -Raw | ConvertFrom-Json -AsHashtable\n'
                          + body + '\n', encoding='utf-8')
        result = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-File', str(helper),
                                 str(LOGIC), str(data_file)], capture_output=True, text=True,
                                encoding='utf-8', timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_metadata_only_and_sensitive_exclusions(self):
        ordinary = self.workspace / 'plain.txt'
        ordinary.write_bytes(b'a' * 123)
        (self.workspace / '.env').write_bytes(b'not-a-real-secret' * 100)
        credentials = self.workspace / 'credentials'
        credentials.mkdir()
        (credentials / 'anything.txt').write_bytes(b'x' * 500)
        before = {p: (p.stat().st_size, p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
                  for p in self.workspace.rglob('*') if p.is_file()}
        summary, detail = self.run_check(output=False)
        measured = detail['data']['directories'][0]
        self.assertEqual(measured['logicalBytes'], 123)
        self.assertEqual(measured['stats']['skipped'], 2)
        self.assertFalse(measured['complete'])
        self.assertFalse(self.reports.exists())
        after = {p: (p.stat().st_size, p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
                 for p in self.workspace.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_unchanged_run_is_quiet_and_reports_unique(self):
        (self.workspace / 'a.txt').write_text('abc')
        first, _ = self.run_check(save=True)
        second, detail = self.run_check(save=True)
        self.assertTrue(first['hasActionableChanges'])
        self.assertFalse(second['hasActionableChanges'])
        self.assertNotEqual(first['report'], second['report'])
        self.assertTrue(Path(first['report']).exists())
        self.assertEqual(detail['newFindingIds'], [])

    def test_partial_scan_does_not_replace_last_good_size(self):
        (self.workspace / 'a.txt').write_bytes(b'abcd')
        self.run_check(save=True)
        before = json.loads((self.reports / '.last-checkup.json').read_text(encoding='utf-8'))
        self.config['limits']['maxEntries'] = 1
        summary, detail = self.run_check(save=True)
        after = json.loads((self.reports / '.last-checkup.json').read_text(encoding='utf-8'))
        key = 'workspace:' + str(self.workspace)
        self.assertEqual(summary['status'], 'incomplete')
        self.assertEqual(before['snapshots'][key], after['snapshots'][key])
        self.assertTrue(any(c['status'] == 'partial' for c in detail['coverage']))

    def test_missing_and_protected_roots_are_not_zero(self):
        protected = self.root / 'protected'
        protected.mkdir()
        self.config['workspaceRoots'] = [str(self.root / 'missing'), str(protected)]
        self.config['protectedRoots'] = [str(protected)]
        _, detail = self.run_check()
        self.assertEqual(detail['data']['directories'], [])
        states = {c['status'] for c in detail['coverage']}
        self.assertIn('missing', states)
        self.assertIn('refused', states)

    def test_refuse_drive_user_network_and_parent_junction(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'b.txt').write_bytes(b'x' * 500)
        junction = self.workspace / 'link'
        # Use a parameterized script file to avoid command-string interpolation.
        helper = self.root / 'junction.ps1'
        helper.write_text('param($Link,$Target)\nNew-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n')
        created = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-File', str(helper),
                                  str(junction), str(outside)], capture_output=True, text=True)
        self.assertEqual(created.returncode, 0, created.stderr)
        self.junctions.append(junction)
        self.config['workspaceRoots'] = [str(self.workspace), str(junction),
                                         self.workspace.drive + '\\', str(Path.home()), r'\\server\share']
        _, detail = self.run_check()
        self.assertEqual(detail['data']['directories'][0]['logicalBytes'], 0)
        self.assertGreaterEqual(sum(c['status'] == 'refused' for c in detail['coverage']), 4)

    def test_corrupt_state_is_preserved(self):
        self.reports.mkdir()
        state = self.reports / '.last-checkup.json'
        state.write_text('broken-state', encoding='utf-8')
        self.run_check(save=True, ok=False)
        self.assertEqual(state.read_text(), 'broken-state')
        self.assertEqual(list(self.reports.glob('*体检*')), [])

    def test_skill_same_name_is_only_a_candidate(self):
        left = self.root / 'skills-a'
        right = self.root / 'skills-b'
        for root in (left, right):
            folder = root / 'sample'
            folder.mkdir(parents=True)
            (folder / 'SKILL.md').write_text('---\nname: sample\ndescription: fixture\n---\n', encoding='utf-8')
        self.config['skillRoots'] = [str(left), str(right)]
        _, detail = self.run_check()
        duplicate = detail['data']['duplicateSkills'][0]
        self.assertTrue(duplicate['sameInstructions'])
        self.assertEqual(duplicate['wholeDirectoryEquality'], 'not_checked')
        self.assertTrue(all(s['lastUsed'] is None for s in detail['data']['skills']))

    def test_native_tool_is_absolute_even_with_untrusted_path(self):
        fake = self.root / 'tools'
        fake.mkdir()
        (fake / 'powercfg.exe').write_bytes(b'not executable; must never be started')
        result = self.run_logic('''
$env:PATH=$fixture.fakePath
$tool=Get-SystemPowerTool
@{tool=$tool;expected=(Join-Path ([Environment]::SystemDirectory) 'powercfg.exe')} | ConvertTo-Json
''', {'fakePath': str(fake)})
        self.assertEqual(result['tool'].lower(), result['expected'].lower())
        self.assertNotIn(str(fake).lower(), result['tool'].lower())

    def test_task_error_change_and_recovery_are_distinct(self):
        result = self.run_logic('''
$f=New-TaskResultFinding 'Example' 5 'Ready'
$first=Get-FindingDelta @($f) @{} @{'scheduled-tasks'='ok'}
$g=New-TaskResultFinding 'Example' 32 'Ready'
$second=Get-FindingDelta @($g) $first.records @{'scheduled-tasks'='ok'}
$third=Get-FindingDelta @($g) $second.records @{'scheduled-tasks'='ok'}
$fourth=Get-FindingDelta @() $third.records @{'scheduled-tasks'='ok'}
@{first=$first;second=$second;third=$third;fourth=$fourth} | ConvertTo-Json -Depth 12
''')
        self.assertEqual(result['first']['new'], ['task-result:Example'])
        self.assertEqual(result['second']['changed'], ['task-result:Example'])
        self.assertEqual(result['second']['new'], [])
        self.assertEqual(result['third']['changed'], [])
        self.assertEqual(result['fourth']['recovered'], ['task-result:Example'])

    def test_normal_running_and_disabled_task_results_are_classified(self):
        result = self.run_logic('''
@{success=(New-TaskResultFinding 'Example' 0 'Ready');running=(New-TaskResultFinding 'Example' 5 'Running');notYetRun=(New-TaskResultFinding 'Example' 0x41303 'Ready');disabled=(New-TaskResultFinding 'Example' 5 'Disabled')} | ConvertTo-Json -Depth 8
''')
        self.assertIsNone(result['success'])
        self.assertIsNone(result['running'])
        self.assertIsNone(result['notYetRun'])
        self.assertEqual(result['disabled']['severity'], 'review')

    def test_startup_target_change_without_name_change_is_detected(self):
        result = self.run_logic('''
$a=@{name='Example';location='HKCU Run';executable='C:\\Tools\\old.exe'}
$first=Compare-StartupInventory @($a) $null
$b=@{name=$a.name;location=$a.location;executable='C:\\Tools\\new.exe'}
$second=Compare-StartupInventory @($b) $first.snapshot
$second | ConvertTo-Json -Depth 10
''')
        self.assertEqual(result['changes'][0]['type'], 'target_changed')
        self.assertTrue(result['changes'][0]['notify'])

    def test_startup_parser_discards_arguments_and_ambiguous_targets(self):
        marker = 'FAKE-TOKEN-FOR-TEST'
        result = self.run_logic('''
$targets=@(foreach($command in $fixture.commands){Get-StartupExecutable $command})
@{targets=$targets;ambiguous=(Get-StartupExecutable 'C:\\Program Files\\App\\app.exe /arg')} | ConvertTo-Json
''', {'commands': [f'"C:\\Program Files\\App\\app.exe" --token={marker}',
                          f'C:\\Tools\\app.exe --token={marker}']})
        self.assertEqual(result['targets'], [r'C:\Program Files\App\app.exe', r'C:\Tools\app.exe'])
        self.assertIsNone(result['ambiguous'])
        self.assertNotIn(marker, json.dumps(result))

    def test_local_temporary_ports_are_recorded_without_notification(self):
        result = self.run_logic('''
$a=@{process='Example';executable='C:\\Tools\\app.exe';address='127.0.0.1';port=4001}
$first=Compare-ListenerInventory @($a) @{'entries'=@{}}
$b=@{process=$a.process;executable=$a.executable;address=$a.address;port=4002}
$second=Compare-ListenerInventory @($b) $first.snapshot
@{first=$first;second=$second} | ConvertTo-Json -Depth 12
''')
        self.assertEqual(len(result['first']['changes']), 1)
        self.assertTrue(all(not c['notify'] for c in result['first']['changes']))
        self.assertTrue(all(not c['notify'] for c in result['second']['changes']))

    def test_repeated_local_listener_notifies_once(self):
        result = self.run_logic('''
$a=@{process='Example';executable='C:\\Tools\\app.exe';address='::1';port=4001}
$first=Compare-ListenerInventory @($a) @{'entries'=@{}}
$second=Compare-ListenerInventory @($a) $first.snapshot
$third=Compare-ListenerInventory @($a) $second.snapshot
@{second=$second;third=$third} | ConvertTo-Json -Depth 12
''')
        self.assertEqual(result['second']['changes'][0]['type'], 'observed_again')
        self.assertTrue(result['second']['changes'][0]['notify'])
        self.assertEqual(result['third']['changes'], [])

    def test_external_and_unknown_listeners_still_notify(self):
        result = self.run_logic('''
$a=@{process='Example';executable='C:\\Tools\\app.exe';address='0.0.0.0';port=4001}
$b=@{process='unknown';executable=$null;address='127.0.0.1';port=4002}
Compare-ListenerInventory @($a,$b) @{'entries'=@{}} | ConvertTo-Json -Depth 10
''')
        self.assertEqual(len(result['changes']), 2)
        self.assertTrue(all(c['notify'] for c in result['changes']))

    def test_transient_listener_path_unavailable_does_not_change_identity(self):
        result = self.run_logic('''
$a=@{process='Example';executable='C:\\Tools\\app.exe';address='127.0.0.1';port=4001}
$first=Compare-ListenerInventory @($a) $null
$b=@{process=$a.process;executable=$null;address=$a.address;port=$a.port}
Compare-ListenerInventory @($b) $first.snapshot | ConvertTo-Json -Depth 10
''')
        self.assertEqual(result['changes'], [])
        self.assertEqual(result['snapshot']['entries']['example|127.0.0.1|4001']['executable'], r'C:\Tools\app.exe')

    def test_largest_candidate_can_arrive_after_first_hundred(self):
        result = self.run_logic('''
$candidates=[Collections.Generic.List[object]]::new()
foreach($i in 1..100){Add-LargestCandidate $candidates @{path=('file-'+$i);logicalBytes=[long]$i}}
Add-LargestCandidate $candidates @{path='last-and-largest';logicalBytes=[long]10000}
@{count=$candidates.Count;largest=(@($candidates | Sort-Object logicalBytes -Descending)[0]);smallest=(@($candidates | Sort-Object logicalBytes)[0])} | ConvertTo-Json -Depth 8
''')
        self.assertEqual(result['count'], 20)
        self.assertEqual(result['largest']['path'], 'last-and-largest')
        self.assertEqual(result['smallest']['logicalBytes'], 82)

    def test_output_equal_to_or_above_scan_root_is_refused(self):
        for output in (self.workspace, self.root):
            with self.subTest(output=output):
                self.reports = output
                self.run_check(save=True, ok=False)
                self.assertFalse((output / '.last-checkup.json').exists())

    def test_output_below_scan_root_is_allowed_and_excluded(self):
        self.reports = self.workspace / 'reports'
        (self.workspace / 'plain.txt').write_bytes(b'abc')
        self.run_check(save=True)
        second, detail = self.run_check(save=True)
        self.assertEqual(detail['data']['directories'][0]['logicalBytes'], 3)
        self.assertFalse(second['hasActionableChanges'])

    def test_concurrent_state_access_stops_without_overwrite(self):
        self.run_check(save=True)
        state = self.reports / '.last-checkup.json'
        before = state.read_bytes()
        before_reports = set(self.reports.glob('*体检*'))
        with (self.reports / '.checkup.lock').open('rb'):
            self.run_check(save=True, ok=False)
        self.assertEqual(before, state.read_bytes())
        self.assertEqual(before_reports, set(self.reports.glob('*体检*')))
        second, _ = self.run_check(save=True)
        self.assertFalse(second['hasActionableChanges'])

    def test_failed_probe_preserves_warning_until_successful_recheck(self):
        probe = self.root / 'probe.txt'
        probe.write_text('fixture')
        old = time.time() - 3 * 86400
        os.utime(probe, (old, old))
        self.config['outputProbes'] = [{'path': str(probe), 'maxAgeDays': 1}]
        self.run_check(save=True)
        stale_id = 'stale-output:' + str(probe)
        probe.unlink()
        _, failed = self.run_check(save=True)
        self.assertIn(stale_id, [f['id'] for f in failed['pendingFindings']])
        saved = json.loads((self.reports / '.last-checkup.json').read_text(encoding='utf-8'))
        self.assertIn(stale_id, saved['findingRecords'])
        probe.write_text('fixture')
        os.utime(probe, (old, old))
        summary, _ = self.run_check(save=True)
        self.assertNotIn(stale_id, summary['newFindingIds'])

    def test_old_state_is_migrated_without_removing_previous_snapshots(self):
        self.reports.mkdir()
        previous = {'version': 1, 'measuredAtUtc': '2026-10-29T00:00:00Z',
                    'snapshots': {'unqueried-check': {'items': ['kept']}}, 'findingIds': []}
        state = self.reports / '.last-checkup.json'
        state.write_text(json.dumps(previous))
        summary, _ = self.run_check(save=True)
        saved = json.loads(state.read_text(encoding='utf-8'))
        self.assertTrue(summary['stateMigrated'])
        self.assertEqual(saved['version'], 2)
        self.assertEqual(saved['snapshots']['unqueried-check'], {'items': ['kept']})

    def test_legacy_startup_and_listener_baselines_do_not_create_false_changes(self):
        result = self.run_logic('''
$startup=@{name='Example';location='HKCU Run';executable='C:\\Tools\\app.exe'}
$oldStartup=@{items=@('HKCU Run|Example')}
$listener=@{process='app';executable='C:\\Tools\\app.exe';address='127.0.0.1';port=4001}
$oldListeners=@{items=@('C:\\Tools\\app.exe|127.0.0.1|4001')}
@{startup=(Compare-StartupInventory @($startup) $oldStartup);listeners=(Compare-ListenerInventory @($listener) $oldListeners)} | ConvertTo-Json -Depth 10
''')
        self.assertEqual(result['startup']['changes'], [])
        self.assertEqual(result['listeners']['changes'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
