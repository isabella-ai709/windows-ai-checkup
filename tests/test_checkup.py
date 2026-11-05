"""Behavior checks for windows-ai-checkup v3.

Uses owned fixtures only: never touches real system tasks, processes or user files.
Requires PowerShell 7.2+. Set CHECKUP_PWSH to the executable if it is not on PATH.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
CHECKUP = PROJECT / 'scripts' / 'Invoke-WindowsCheckup.ps1'
CLEANUP = PROJECT / 'scripts' / 'Invoke-Cleanup.ps1'
CLEANUP_MODULE = PROJECT / 'scripts' / 'Checkup.Cleanup.psm1'
PWSH = os.environ.get('CHECKUP_PWSH') or shutil.which('pwsh')


def write_bytes(path: Path, size: int, age_days: int = 0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'x' * size)
    if age_days:
        ts = path.stat().st_mtime - age_days * 86400
        os.utime(path, (ts, ts))


def touch_dir(path: Path, age_days: int):
    ts = path.stat().st_mtime - age_days * 86400
    os.utime(path, (ts, ts))


@unittest.skipUnless(PWSH, 'pwsh not found; set CHECKUP_PWSH')
class CheckupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='checkup-v3-test-')
        self.root = Path(self.temp.name)
        self.workspace = self.root / 'workspace'
        self.cache = self.root / 'cache'
        self.reports = self.root / 'reports'
        self.quarantine = self.root / 'quarantine'
        self.workspace.mkdir()
        self.cache.mkdir()
        self.config_path = self.root / 'config.json'
        self.config = {
            'version': 2,
            'workspaceRoots': [str(self.workspace)],
            'cacheRoots': [{'kind': 'path', 'path': str(self.cache)}],
            'skillRoots': [], 'protectedRoots': [], 'taskPathPrefixes': [],
            'serviceNames': [], 'outputProbes': [],
            'cleanup': {'enabled': True, 'quarantineRoot': str(self.quarantine),
                        'skipObservationCheck': False, 'whitelist': []},
            'rules': {'tempOlderThanDays': 3, 'logOlderThanDays': 7, 'logFileMB': 1,
                      'largeFileMB': 1, 'staleDependencyDays': 1, 'keepPreviousRuntimes': 1,
                      'installLeftoverMinAgeHours': 0, 'minCandidateMB': 0},
            'limits': {'maxEntries': 5000, 'maxDepth': 8, 'maxSecondsPerRoot': 10},
        }

    def tearDown(self):
        self.assertEqual(Path(self.root).resolve().parent, Path(tempfile.gettempdir()).resolve())
        self.assertTrue(self.root.name.startswith('checkup-v3-test-'))
        self.temp.cleanup()

    def run_check(self, save=True, output=True, config=None):
        self.config_path.write_text(json.dumps(config or self.config), encoding='utf-8')
        args = [PWSH, '-NoProfile', '-NonInteractive', '-File', str(CHECKUP),
                '-ConfigPath', str(self.config_path), '-SkipSystemChecks']
        if output:
            args += ['-OutDirectory', str(self.reports)]
        if save:
            args += ['-SaveState']
        res = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
        self.assertEqual(res.returncode, 0, res.stderr)
        if output:
            summary = json.loads(res.stdout)
            detail = json.loads(Path(summary['evidence']).read_text(encoding='utf-8'))
            return summary, detail
        return json.loads(res.stdout), None

    def run_cleanup(self, plan, apply=False, quarantine=None, probe_movable=False, config=None):
        args = [PWSH, '-NoProfile', '-NonInteractive', '-File', str(CLEANUP),
                '-PlanPath', str(plan), '-QuarantineRoot', str(quarantine or self.quarantine)]
        if config is not None:
            self.config_path.write_text(json.dumps(config), encoding='utf-8')
            args += ['-ConfigPath', str(self.config_path)]
        if apply:
            args.append('-Apply')
        if probe_movable:
            args.append('-ProbeMovable')
        res = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(res.stdout)

    def run_cleanup_raw(self, plan, quarantine=None, config=None):
        args = [PWSH, '-NoProfile', '-NonInteractive', '-File', str(CLEANUP),
                '-PlanPath', str(plan), '-QuarantineRoot', str(quarantine or self.quarantine)]
        if config is not None:
            self.config_path.write_text(json.dumps(config), encoding='utf-8')
            args += ['-ConfigPath', str(self.config_path)]
        return subprocess.run(args, capture_output=True, text=True, encoding='utf-8',
                              errors='replace', timeout=120)

    # -- measurement ------------------------------------------------------
    def test_allocation_rounds_up(self):
        write_bytes(self.cache / 'pkg' / 'a.bin', 5000)
        summary, detail = self.run_check()
        # A plain path cache root without a known name is graded B (needs confirmation).
        confirm = detail['reclaim']['confirm']
        self.assertEqual(confirm['items'], 1)
        self.assertGreaterEqual(confirm['bytes'], 5000)
        self.assertEqual(confirm['bytes'] % 4096, 0)

    def test_install_leftover_graded_a(self):
        rt = self.cache / 'rt'
        write_bytes(rt / 'codex-primary-runtime' / 'node.exe', 100)
        write_bytes(rt / 'codex-runtime-install-x' / 'node-runtime.tar.gz', 600000)
        self.config['cacheRoots'] = [{'kind': 'path', 'path': str(rt)}]
        summary, detail = self.run_check()
        cats = {(c['category'], c['grade']) for c in detail['data']['candidates']}
        self.assertIn(('install-leftover', 'A'), cats)

    def test_previous_runtime_keeps_newest(self):
        rt = self.cache / 'rt'
        write_bytes(rt / 'codex-primary-runtime' / 'node.exe', 100)
        old = rt / 'codex-primary-runtime.previous-old'
        new = rt / 'codex-primary-runtime.previous-new'
        write_bytes(old / 'node.exe', 100)
        write_bytes(new / 'node.exe', 100)
        touch_dir(old, 30)
        touch_dir(new, 1)
        self.config['cacheRoots'] = [{'kind': 'path', 'path': str(rt)}]
        summary, detail = self.run_check()
        paths = [c['path'] for c in detail['data']['candidates'] if c['category'] == 'runtime-previous']
        self.assertTrue(any('previous-old' in p for p in paths))
        self.assertFalse(any('previous-new' in p for p in paths))

    def test_temp_age_filter(self):
        self.config['cacheRoots'] = [{'kind': 'named', 'name': 'temp'}]
        summary, detail = self.run_check(config=self.config)
        # named temp resolves to the real user temp; assert no crash and category exists if any
        self.assertIn('reclaim', detail)

    def test_dependency_graded_b_when_project_stale(self):
        write_bytes(self.workspace / 'proj' / 'node_modules' / 'p' / 'a.bin', 2000)
        touch_dir(self.workspace / 'proj', 40)
        summary, detail = self.run_check()
        cats = {(c['category'], c['grade']) for c in detail['data']['candidates']}
        self.assertIn(('dependency', 'B'), cats)

    # -- two-observation rule ---------------------------------------------
    def test_first_run_has_no_plan_second_run_does(self):
        rt = self.cache / 'rt'
        write_bytes(rt / 'codex-primary-runtime' / 'node.exe', 100)
        write_bytes(rt / 'codex-runtime-install-x' / 'node-runtime.tar.gz', 5000)
        self.config['cacheRoots'] = [{'kind': 'path', 'path': str(rt)}]
        s1, _ = self.run_check()
        self.assertEqual(s1['planItemCount'], 0)
        s2, d2 = self.run_check()
        self.assertGreaterEqual(s2['planItemCount'], 1)
        plan = json.loads(Path(s2['plan']).read_text(encoding='utf-8'))
        self.assertTrue(plan['items'])
        self.assertTrue(all(i['seenCount'] >= 2 for i in plan['items']))

    def test_whitelist_excludes(self):
        self.config['cleanup']['whitelist'] = [str(self.cache)]
        write_bytes(self.cache / 'pkg' / 'a.bin', 5000)
        summary, detail = self.run_check()
        self.assertEqual(detail['reclaim']['safe']['items'], 0)
        self.assertEqual(detail['reclaim']['confirm']['items'], 0)
        self.assertTrue(any('白名单' in e['reason'] for e in detail['reclaim']['excluded']))

    def test_directory_candidate_inuse_is_unknown(self):
        # A directory cannot be lock-probed, so inUse must stay null instead of reading
        # as a confirmed "not in use".
        write_bytes(self.cache / 'pkg' / 'a.bin', 5000)
        summary, detail = self.run_check()
        cands = detail['data']['candidates']
        self.assertTrue(cands)
        dirs = [c for c in cands if Path(c['path']).is_dir()]
        self.assertTrue(dirs)
        for c in dirs:
            self.assertIsNone(c['inUse'])
            self.assertFalse(c['inUseChecked'])

    def test_tiny_candidate_excluded(self):
        self.config['rules']['minCandidateMB'] = 1
        write_bytes(self.cache / 'tiny' / '.gitignore', 1)
        summary, detail = self.run_check()
        paths = [c['path'] for c in detail['data']['candidates']]
        self.assertFalse(any(p.endswith('tiny') for p in paths))
        self.assertTrue(any('清理收益' in e['reason'] for e in detail['reclaim']['excluded']))

    # -- cleanup ----------------------------------------------------------
    def _make_plan(self, items):
        plan = self.root / 'plan.json'
        # The cleaner refuses a plan that sits outside the output directory it names.
        plan.write_text(json.dumps({'version': 1, 'outDirectory': str(self.root),
                                    'items': items}, ensure_ascii=False), encoding='utf-8')
        return plan

    def _item(self, path: Path, size: int):
        return {'path': str(path), 'category': 'cache-pkg', 'grade': 'A',
                'logicalBytes': size, 'allocationBytes': size, 'reason': 'test',
                'regenerate': 'x', 'restore': 'y', 'directDelete': True,
                'inUse': False, 'seenCount': 2}

    def test_dry_run_moves_nothing(self):
        target = self.cache / 'pkg' / 'a.bin'
        write_bytes(target, 5000)
        plan = self._make_plan([self._item(target, 5000)])
        out = self.run_cleanup(plan)
        # Read-only dry-run: no rename probe ran, the file is only lock-checked.
        self.assertEqual(out['probeMode'], 'readonly')
        self.assertFalse(out['movableProbed'])
        self.assertEqual(out['movedCount'], 1)
        self.assertTrue(out['items'][0]['movable'])
        self.assertEqual(out['items'][0]['movableSource'], 'handle-probe')
        self.assertTrue(target.exists())
        self.assertFalse(self.quarantine.exists() and any(self.quarantine.rglob('*')))
        self.assertEqual(list(target.parent.glob('a.bin.checkup-probe-*')), [])

    def test_dry_run_does_not_rename_directory(self):
        # A directory cannot be judged move-able without mutating its name, so the default
        # dry-run must say "unknown" rather than rename it behind the user's back.
        target = self.cache / 'pkgdir'
        write_bytes(target / 'a.bin', 5000)
        plan = self._make_plan([self._item(target, 5000)])
        out = self.run_cleanup(plan)
        self.assertEqual(out['probeMode'], 'readonly')
        self.assertEqual(out['movedCount'], 1)
        self.assertIsNone(out['items'][0]['movable'])
        self.assertEqual(out['items'][0]['movableSource'], 'unknown')
        self.assertTrue(target.is_dir())
        self.assertTrue((target / 'a.bin').exists())
        self.assertEqual(list(target.parent.glob('pkgdir.checkup-probe-*')), [])

    def test_dry_run_reports_locked_file_readonly(self):
        target = self.cache / 'pkg' / 'a.bin'
        write_bytes(target, 5000)
        plan = self._make_plan([self._item(target, 5000)])
        with open(target, 'rb') as held:
            out = self.run_cleanup(plan)
        self.assertEqual(out['movedCount'], 0)
        self.assertIn('占用', out['failed'][0]['reason'])
        self.assertTrue(target.exists())

    def test_probe_movable_is_opt_in_and_restores_name(self):
        # -ProbeMovable is the only path that renames a target, and it puts the name back.
        target = self.cache / 'pkgdir'
        write_bytes(target / 'a.bin', 5000)
        plan = self._make_plan([self._item(target, 5000)])
        out = self.run_cleanup(plan, probe_movable=True)
        self.assertEqual(out['probeMode'], 'rename')
        self.assertTrue(out['movableProbed'])
        self.assertEqual(out['movedCount'], 1)
        self.assertTrue(out['items'][0]['movable'])
        self.assertEqual(out['items'][0]['movableSource'], 'rename-probe')
        self.assertTrue(target.is_dir())
        self.assertTrue((target / 'a.bin').exists())
        self.assertEqual(list(target.parent.glob('pkgdir.checkup-probe-*')), [])

    def test_probe_movable_refused_with_apply(self):
        target = self.cache / 'pkg' / 'a.bin'
        write_bytes(target, 5000)
        plan = self._make_plan([self._item(target, 5000)])
        res = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-File', str(CLEANUP),
                              '-PlanPath', str(plan), '-QuarantineRoot', str(self.quarantine),
                              '-Apply', '-ProbeMovable'],
                             capture_output=True, text=True, encoding='utf-8',
                             errors='replace', timeout=60)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('ProbeMovable', res.stderr)
        self.assertTrue(target.exists())

    def test_movable_probe_on_missing_path(self):
        code = ("Import-Module '{}' -Force; $r = Test-PathMovable '{}'; "
                "Write-Output ($r.movable.ToString() + '|' + $r.reason)").format(
                    CLEANUP_MODULE, self.cache / 'does-not-exist')
        res = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-Command', code],
                             capture_output=True, text=True, encoding='utf-8',
                             errors='replace', timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(res.stdout.strip().startswith('False|'), res.stdout)

    def run_undo(self, manifest):
        res = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-File', str(CLEANUP),
                              '-Undo', str(manifest)], capture_output=True, text=True,
                             encoding='utf-8', errors='replace', timeout=120)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(res.stdout)

    def test_apply_then_undo(self):
        target = self.cache / 'pkg' / 'a.bin'
        write_bytes(target, 5000)
        plan = self._make_plan([self._item(target, 5000)])
        out = self.run_cleanup(plan, apply=True)
        self.assertEqual(out['movedCount'], 1)
        self.assertFalse(target.exists())
        manifest = Path(out['manifest'])
        self.assertTrue(manifest.exists())
        undo = self.run_undo(manifest)
        self.assertEqual(undo['restored'], 1)
        self.assertTrue(target.exists())

    def test_manifest_is_journal_written_before_move(self):
        target = self.cache / 'pkg' / 'a.bin'
        write_bytes(target, 5000)
        plan = self._make_plan([self._item(target, 5000)])
        out = self.run_cleanup(plan, apply=True)
        data = json.loads(Path(out['manifest']).read_text(encoding='utf-8'))
        self.assertEqual(data['status'], 'completed')
        # The run directory is recorded so undo can bound the source to it.
        self.assertTrue(data['quarantineRunRoot'])
        self.assertEqual(data['movedCount'], 1)
        entry = data['items'][0]
        self.assertEqual(entry['state'], 'moved')
        self.assertEqual(entry['originalPath'], str(target))
        self.assertTrue(Path(entry['quarantinePath']).exists())

    def test_undo_restores_from_in_progress_manifest(self):
        # A run killed mid-way leaves state=pending; undo must still consume it.
        target = self.cache / 'pkg' / 'a.bin'
        write_bytes(target, 5000)
        plan = self._make_plan([self._item(target, 5000)])
        out = self.run_cleanup(plan, apply=True)
        manifest = Path(out['manifest'])
        data = json.loads(manifest.read_text(encoding='utf-8'))
        data['status'] = 'in-progress'
        data['items'][0]['state'] = 'pending'
        data['items'][0]['movedAtUtc'] = None
        manifest.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
        undo = self.run_undo(manifest)
        self.assertEqual(undo['restored'], 1)
        self.assertTrue(undo['incomplete'])
        self.assertTrue(target.exists())

    def test_undo_rejects_source_outside_quarantine(self):
        # A hand-edited manifest must not turn -Undo into a general file mover.
        outsider = self.root / 'outsider.txt'
        outsider.write_bytes(b'x' * 10)
        planted = self.root / 'planted' / 'x.bin'
        manifest = self.quarantine / 'run9' / 'manifest.json'
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({
            'version': 1, 'runId': 'forged', 'retentionDays': 7,
            'quarantineRoot': str(self.quarantine),
            'items': [{'originalPath': str(planted), 'quarantinePath': str(outsider), 'bytes': 10}]
        }, ensure_ascii=False), encoding='utf-8')
        out = self.run_undo(manifest)
        self.assertEqual(out['restored'], 0)
        self.assertTrue(outsider.exists())
        self.assertFalse(planted.exists())
        self.assertIn('隔离区', out['failedItems'][0]['reason'])

    def test_undo_rejects_restore_into_system_dir(self):
        qfile = self.quarantine / 'run1' / '0001' / 'a.bin'
        write_bytes(qfile, 5000)
        forbidden = Path(r'C:\Windows\System32\__checkup_probe__.bin')
        manifest = self.quarantine / 'run8' / 'manifest.json'
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({
            'version': 1, 'runId': 'forged', 'retentionDays': 7,
            'quarantineRoot': str(self.quarantine),
            'items': [{'originalPath': str(forbidden), 'quarantinePath': str(qfile), 'bytes': 5000}]
        }, ensure_ascii=False), encoding='utf-8')
        out = self.run_undo(manifest)
        self.assertEqual(out['restored'], 0)
        self.assertIn('系统目录', out['failedItems'][0]['reason'])
        self.assertTrue(qfile.exists())
        self.assertFalse(forbidden.exists())

    def test_undo_rejects_volume_root_bound(self):
        # Declaring the quarantine as "C:\" would make every path on the volume look legit.
        qfile = self.quarantine / 'run1' / 'a.bin'
        write_bytes(qfile, 5000)
        manifest = self.root / 'forged4.json'
        manifest.write_text(json.dumps({
            'version': 1, 'runId': 'forged', 'retentionDays': 7,
            'quarantineRoot': 'C:\\',
            'items': [{'originalPath': str(self.cache / 'x.bin'), 'quarantinePath': str(qfile), 'bytes': 5000}]
        }, ensure_ascii=False), encoding='utf-8')
        out = self.run_undo(manifest)
        self.assertEqual(out['restored'], 0)
        self.assertIn('整盘根', out['failedItems'][0]['reason'])

    def test_undo_rejects_changed_content(self):
        qfile = self.quarantine / 'run1' / '0001' / 'a.bin'
        write_bytes(qfile, 5000)
        original = self.cache / 'pkg' / 'a.bin'
        manifest = self.quarantine / 'run7' / 'manifest.json'
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({
            'version': 1, 'runId': 'forged', 'retentionDays': 7,
            'quarantineRoot': str(self.quarantine),
            'items': [{'originalPath': str(original), 'quarantinePath': str(qfile), 'bytes': 999999}]
        }, ensure_ascii=False), encoding='utf-8')
        out = self.run_undo(manifest)
        self.assertEqual(out['restored'], 0)
        self.assertIn('字节', out['failedItems'][0]['reason'])

    def test_undo_rejects_manifest_outside_declared_root(self):
        # The declared quarantine must be where the manifest physically lives, otherwise a
        # forged manifest can name any directory as its "quarantine" and act as a mover.
        victim = self.root / 'victim' / 'secret.txt'
        write_bytes(victim, 5000)
        planted = self.root / 'planted' / 'secret.txt'
        manifest = self.root / 'forged' / 'manifest.json'
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({
            'version': 1, 'status': 'completed',
            'quarantineRunRoot': str(victim.parent),
            'items': [{'originalPath': str(planted), 'quarantinePath': str(victim), 'bytes': 5000}]
        }, ensure_ascii=False), encoding='utf-8')
        res = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-File', str(CLEANUP),
                              '-Undo', str(manifest)], capture_output=True, text=True,
                             encoding='utf-8', errors='replace', timeout=60)
        self.assertNotEqual(res.returncode, 0)
        self.assertTrue(victim.exists())
        self.assertFalse(planted.exists())

    def test_undo_rejects_dotdot_escape(self):
        # "run\..\..\victim" starts with the quarantine prefix but resolves outside it.
        q_run = self.quarantine / 'run6'
        victim = self.root / 'victim2' / 'secret.txt'
        write_bytes(victim, 5000)
        planted = self.root / 'planted2' / 'secret.txt'
        manifest = q_run / 'manifest.json'
        q_run.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({
            'version': 1, 'status': 'completed',
            'quarantineRoot': str(self.quarantine),
            'items': [{'originalPath': str(planted),
                       'quarantinePath': str(q_run) + r'\..\..\victim2\secret.txt', 'bytes': 5000}]
        }, ensure_ascii=False), encoding='utf-8')
        out = self.run_undo(manifest)
        self.assertEqual(out['restored'], 0)
        self.assertIn('隔离区', out['failedItems'][0]['reason'])
        self.assertTrue(victim.exists())
        self.assertFalse(planted.exists())

    def test_undo_accepts_legacy_manifest_in_declared_root(self):
        # Manifests written before run directories were recorded still restore, as long as
        # they sit below the root they name.
        qfile = self.quarantine / 'run5' / '0001' / 'a.bin'
        write_bytes(qfile, 5000)
        original = self.cache / 'pkg' / 'a.bin'
        manifest = self.quarantine / 'run5' / 'manifest.json'
        manifest.write_text(json.dumps({
            'version': 1, 'status': 'completed', 'quarantineRoot': str(self.quarantine),
            'items': [{'originalPath': str(original), 'quarantinePath': str(qfile), 'bytes': 5000}]
        }, ensure_ascii=False), encoding='utf-8')
        out = self.run_undo(manifest)
        self.assertEqual(out['restored'], 1)
        self.assertTrue(original.exists())

    def test_dry_run_reports_readonly_file_movable(self):
        # The handle probe opens for read: a read-only file is not "in use".
        target = self.cache / 'pkg' / 'ro.bin'
        write_bytes(target, 5000)
        os.chmod(target, 0o444)
        try:
            plan = self._make_plan([self._item(target, 5000)])
            out = self.run_cleanup(plan)
            self.assertEqual(out['movedCount'], 1)
            self.assertTrue(out['items'][0]['movable'])
            self.assertEqual(out['items'][0]['movableSource'], 'handle-probe')
        finally:
            os.chmod(target, 0o666)

    def test_plan_must_live_in_declared_outdirectory(self):
        target = self.cache / 'pkg' / 'a.bin'
        write_bytes(target, 5000)
        plan_dir = self.root / 'elsewhere'
        plan = plan_dir / 'plan.json'
        plan_dir.mkdir(parents=True, exist_ok=True)
        plan.write_text(json.dumps({'version': 1, 'outDirectory': str(self.root / 'out'),
                                    'items': [self._item(target, 5000)]},
                                   ensure_ascii=False), encoding='utf-8')
        res = self.run_cleanup_raw(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('outDirectory', res.stderr)
        self.assertTrue(target.exists())

    def test_config_rejects_item_outside_allowed_roots(self):
        target = self.root / 'outside' / 'a.bin'
        write_bytes(target, 5000)
        plan = self._make_plan([self._item(target, 5000)])
        res = self.run_cleanup_raw(plan, config=self.config)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('允许的根目录', res.stderr)
        self.assertTrue(target.exists())

    def test_config_rejects_item_in_protected_root(self):
        guard = self.cache / 'protected'
        target = guard / 'a.bin'
        write_bytes(target, 5000)
        cfg = json.loads(json.dumps(self.config))
        cfg['protectedRoots'] = [str(guard)]
        plan = self._make_plan([self._item(target, 5000)])
        res = self.run_cleanup_raw(plan, config=cfg)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('保护目录', res.stderr)
        self.assertTrue(target.exists())

    def test_config_allows_item_under_cache_root(self):
        target = self.cache / 'pkg' / 'a.bin'
        write_bytes(target, 5000)
        plan = self._make_plan([self._item(target, 5000)])
        out = self.run_cleanup(plan, config=self.config)
        self.assertEqual(out['movedCount'], 1)

    def test_system_dir_refused(self):
        plan = self._make_plan([self._item(Path(r'C:\Windows\System32\drivers\etc\hosts'), 100)])
        out = self.run_cleanup(plan)
        self.assertEqual(out['movedCount'], 0)
        self.assertIn('系统', out['failed'][0]['reason'])

    def test_size_mismatch_skipped(self):
        target = self.cache / 'pkg' / 'a.bin'
        write_bytes(target, 5000)
        plan = self._make_plan([self._item(target, 999999)])
        out = self.run_cleanup(plan)
        self.assertEqual(out['movedCount'], 0)
        self.assertIn('大小', out['failed'][0]['reason'])

    def _plan_worthy_fixture(self):
        # Leaf name "temp" switches the cache root to per-entry temp rules, which yield
        # grade-A direct-delete candidates - i.e. entries that really would enter a plan.
        tmp = self.root / 'temp'
        write_bytes(tmp / 'old-pkg' / 'a.bin', 5000, age_days=40)
        touch_dir(tmp / 'old-pkg', 40)
        self.config['cacheRoots'] = [{'kind': 'path', 'path': str(tmp)}]

    def test_cleanup_disabled_writes_no_plan(self):
        self._plan_worthy_fixture()
        self.config['cleanup']['enabled'] = False
        self.run_check(save=True)
        summary, detail = self.run_check(save=True)
        self.assertIsNone(summary['plan'])
        self.assertFalse(detail['data']['plan']['enabled'])
        self.assertEqual(detail['data']['plan']['itemCount'], 0)
        self.assertEqual([p.name for p in self.reports.glob('*-plan.json')], [])
        md = sorted(self.reports.glob('*-体检.md'))[-1].read_text(encoding='utf-8')
        self.assertIn('没有生成 plan.json', md)

    def test_cleanup_enabled_writes_plan(self):
        self._plan_worthy_fixture()
        self.run_check(save=True)
        summary, detail = self.run_check(save=True)
        self.assertIsNotNone(summary['plan'])
        self.assertTrue(detail['data']['plan']['enabled'])
        self.assertEqual(detail['data']['plan']['itemCount'], 1)
        self.assertEqual(len(list(self.reports.glob('*-plan.json'))), 2)

    def test_journal_records_failed_item(self):
        good = self.cache / 'pkg' / 'a.bin'
        bad = self.cache / 'pkg2' / 'b.bin'
        write_bytes(good, 5000)
        write_bytes(bad, 5000)
        plan = self._make_plan([self._item(good, 5000), self._item(bad, 5000)])
        # Second item is locked while apply runs: the move must fail, but the journal has to
        # keep the record and the run must finish with completed-with-failures.
        with open(bad, 'rb'):
            out = self.run_cleanup(plan, apply=True)
        self.assertEqual(out['movedCount'], 1)
        self.assertEqual(out['failedCount'], 1)
        data = json.loads(Path(out['manifest']).read_text(encoding='utf-8'))
        self.assertEqual(data['status'], 'completed-with-failures')
        self.assertEqual(data['failedCount'], 1)
        self.assertFalse(good.exists())

    # -- config -----------------------------------------------------------
    def test_v1_config_accepted(self):
        legacy = {
            'version': 1,
            'workspaceRoots': [str(self.workspace)],
            'cacheRoots': [str(self.cache)],
            'skillRoots': [], 'protectedRoots': [], 'taskPathPrefixes': [],
            'serviceNames': [], 'outputProbes': [],
            'limits': {'maxEntries': 5000, 'maxDepth': 8, 'maxSecondsPerRoot': 10},
        }
        summary, _ = self.run_check(config=legacy, save=False, output=False)
        self.assertEqual(summary['version'], 3)

    def test_report_sections(self):
        write_bytes(self.cache / 'pkg' / 'a.bin', 5000)
        summary, _ = self.run_check()
        report = Path(summary['report']).read_text(encoding='utf-8')
        for section in ['## 可回收空间', '## 清理计划', '## 覆盖范围与缺口', '## 判断边界']:
            self.assertIn(section, report)


if __name__ == '__main__':
    unittest.main()
