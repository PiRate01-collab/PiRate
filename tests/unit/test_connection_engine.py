import copy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from gate_core.engine import ConnectionEngine, EngineError
from gate_core.executor import MockExecutor, CommandResult
from gate_core.journal import PersistentJournal, JournalError, canonical, resource_name
from gate_core.network_policy import NetworkPolicy, PolicyError
from gate_core.openvpn_config import validate_openvpn, ConfigurationError
from gate_core.plans import ConnectionPlan, ConnectionLifecycle, ConnectionState, TRANSITIONS
from gate_core.process_lock import ProcessLock, LockTimeout
from gate_core.recovery import RecoveryManager

CONFIG = '''client
dev tun
remote 192.0.2.10 1194 udp
proto udp
remote-cert-tls server
verify-x509-name vpn.example name
<ca>
SYNTHETIC_CA
</ca>
'''


def fixtures(directory, executor=None):
    executor = executor or MockExecutor()
    engine = ConnectionEngine(directory, executor)
    plan = ConnectionPlan.from_profile({'name': 'Simulation', 'type': 'openvpn', 'server': '192.0.2.10', 'port': 1194, 'dns_mode': 'tunnel'})
    return engine, plan, NetworkPolicy('192.0.2.10', 1194, 'udp', 'tun0'), validate_openvpn(CONFIG)


def start_child(directory, ready, outcomes):
    ready.wait(2)
    engine, plan, policy, config = fixtures(directory)
    try:
        outcomes.put(engine.start(plan, policy, config)['state'])
    except (EngineError, LockTimeout):
        outcomes.put('blocked')


def lock_child(path, ready, crash):
    with ProcessLock(path):
        ready.set()
        if crash:
            os._exit(7)
        time.sleep(5)


class JournalTests(unittest.TestCase):
    def test_roundtrip_unique_ids_private_atomic_files(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = PersistentJournal.create(directory), PersistentJournal.create(directory)
            self.assertNotEqual(a.data['operation_id'], b.data['operation_id'])
            self.assertEqual(a.data, PersistentJournal.load(directory, a.data['operation_id']).data)
            self.assertEqual(a.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(directory).glob('.journal-*')), [])

    def test_failed_replace_preserves_last_durable_record(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = PersistentJournal.create(directory)
            before = journal.path.read_bytes()
            identifier = journal.data['operation_id']
            with patch('gate_core.journal.os.replace', side_effect=OSError('SYNTHETIC_SECRET')):
                with self.assertRaises(JournalError) as error: journal.transition('preparing')
            self.assertNotIn('SYNTHETIC_SECRET', str(error.exception))
            self.assertEqual(journal.path.read_bytes(), before)
            self.assertEqual(PersistentJournal.load(directory, identifier).data['state'], 'planned')
            with self.assertRaises(JournalError): journal.data
            self.assertEqual(list(Path(directory).glob('.journal-*')), [])

    def test_failed_fsync_requires_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = PersistentJournal.create(directory)
            with patch('gate_core.journal.os.fsync', side_effect=OSError('disk')):
                with self.assertRaises(JournalError): journal.transition('preparing')
            self.assertFalse(journal.valid)

    def test_truncated_tampered_and_duplicate_records(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = PersistentJournal.create(directory)
            original = journal.path.read_bytes()
            identifier = journal.data['operation_id']
            data = json.loads(original)
            data['data']['state'] = 'connecting'
            for content in (b'{', json.dumps(data).encode(), b'{"data":{},"data":{}}'):
                journal.path.write_bytes(content)
                with self.assertRaises(JournalError): PersistentJournal.load(directory, identifier)
            journal.path.write_bytes(original)

    def test_unknown_fields_resources_and_foreign_names_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = PersistentJournal.create(directory)
            for kind, name in (('command', 'rm -rf /'), ('namespace', 'foreign')):
                data = journal.data
                data['resources'].append({'kind': kind, 'name': name, 'status': 'pending'})
                with self.assertRaises(JournalError): journal.save(data)
            data = journal.data; data['argv'] = ['evil']
            with self.assertRaises(JournalError): journal.save(data)

    def test_symlink_journal_and_directory_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = PersistentJournal.create(root / 'real')
            (root / 'alias').symlink_to(root / 'real', target_is_directory=True)
            with self.assertRaises(JournalError): PersistentJournal.load(root / 'alias', journal.data['operation_id'])
            other = root / 'other'; other.write_text('{}')
            journal.path.unlink(); journal.path.symlink_to(other)
            with self.assertRaises(JournalError): PersistentJournal.load(root / 'real', journal.data['operation_id'])

    def test_snapshot_mutation_does_not_modify_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = PersistentJournal.create(directory)
            data = journal.data; data['state'] = 'connected'
            self.assertEqual(journal.data['state'], 'planned')


class ProcessLockTests(unittest.TestCase):
    def test_second_holder_times_out_then_can_acquire(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lock'
            with ProcessLock(path):
                begin = time.monotonic()
                with self.assertRaises(LockTimeout):
                    with ProcessLock(path, timeout=.03): pass
                self.assertGreaterEqual(time.monotonic() - begin, .025)
            with ProcessLock(path): pass

    def test_process_death_releases_lock(self):
        ctx = multiprocessing.get_context('fork')
        for crash in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                path = str(Path(directory) / 'lock')
                ready = ctx.Event()
                child = ctx.Process(target=lock_child, args=(path, ready, crash))
                child.start()
                try:
                    self.assertTrue(ready.wait(2))
                    if not crash:
                        with self.assertRaises(LockTimeout):
                            with ProcessLock(path): pass
                        child.terminate()
                    child.join(2)
                    self.assertFalse(child.is_alive())
                    with ProcessLock(path): pass
                finally:
                    if child.is_alive(): child.kill(); child.join(2)

    def test_lock_rejects_symlink_and_bad_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lock'
            path.symlink_to(Path(directory) / 'other')
            with self.assertRaises(OSError):
                with ProcessLock(path): pass
        for timeout in (-1, float('nan'), float('inf')):
            with self.assertRaises(ValueError): ProcessLock('/unused', timeout)


class StateTests(unittest.TestCase):
    def test_every_allowed_and_disallowed_transition(self):
        for source in ConnectionState:
            for target in ConnectionState:
                lifecycle = ConnectionLifecycle(); lifecycle.state = source
                if target in TRANSITIONS[source] or source == target == ConnectionState.STOPPED:
                    lifecycle.transition(target)
                    self.assertEqual(lifecycle.state, target)
                else:
                    with self.assertRaises(ValueError): lifecycle.transition(target)
                    self.assertEqual(lifecycle.state, source)


class EngineRecoveryTests(unittest.TestCase):
    def test_connected_stop_repeat_and_restart_new_id(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, plan, policy, config = fixtures(directory)
            first = engine.start(plan, policy, config)
            self.assertEqual(first['state'], 'connected')
            with self.assertRaises(EngineError): engine.start(plan, policy, config)
            self.assertEqual(engine.stop(first['operation_id']), 'stopped')
            count = len(engine.executor.calls)
            self.assertEqual(engine.stop(first['operation_id']), 'stopped')
            self.assertEqual(len(engine.executor.calls), count)
            second = engine.start(plan, policy, config)
            self.assertNotEqual(first['operation_id'], second['operation_id'])

    def test_concurrent_operation_blocked_before_executor(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, plan, policy, config = fixtures(directory)
            with ProcessLock(Path(directory) / 'operation.lock'):
                with self.assertRaises(LockTimeout): engine.start(plan, policy, config)
            self.assertEqual(engine.executor.calls, [])

    def test_executor_failure_redacted_then_recovery(self):
        for outcome in (RuntimeError('SYNTHETIC_SECRET'), CommandResult(returncode=1, stderr='SYNTHETIC_SECRET')):
            with tempfile.TemporaryDirectory() as directory:
                executor = MockExecutor([outcome])
                engine, plan, policy, config = fixtures(directory, executor)
                with self.assertRaises(EngineError) as error: engine.start(plan, policy, config)
                self.assertNotIn('SYNTHETIC_SECRET', str(error.exception))
                journal = RecoveryManager(directory, executor).discover()[0][0]
                self.assertEqual(journal.data['state'], 'failed')
                self.assertNotIn('SYNTHETIC_SECRET', journal.path.read_text())
                report = RecoveryManager(directory, executor).recover()
                self.assertEqual(report['state'], 'stopped')

    def test_crash_between_create_and_record_then_recover_reverse_order(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = MockExecutor()
            journal = PersistentJournal.create(directory)
            journal.transition('preparing')
            identifier = journal.data['operation_id']
            for kind in ('namespace', 'link', 'nft_table'):
                journal.intend(kind)
                executor.resource('create', identifier, kind)
                if kind != 'nft_table': journal.mark(kind, 'acquired')
            # Restart manager with same simulated world, new journal object.
            report = RecoveryManager(directory, executor).recover()
            self.assertEqual(report['state'], 'stopped')
            self.assertEqual([call[1][1] for call in executor.calls if call[0] == 'cleanup'], ['nft_table', 'link', 'namespace'])
            self.assertEqual(executor.resources, {})
            before = len(executor.calls)
            self.assertEqual(RecoveryManager(directory, executor).recover()['state'], 'stopped')
            self.assertEqual(before, len(executor.calls))

    def test_failed_cleanup_is_retryable(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, plan, policy, config = fixtures(directory)
            data = engine.start(plan, policy, config)
            engine.executor.outcomes = [RuntimeError('synthetic')]
            self.assertEqual(engine.stop(data['operation_id']), 'cleanup_failed')
            self.assertEqual(engine.stop(data['operation_id']), 'stopped')

    def test_foreign_resource_requires_recovery_and_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, plan, policy, config = fixtures(directory)
            data = engine.start(plan, policy, config)
            key = ('link', resource_name(data['operation_id'], 'link'))
            engine.executor.resources[key] = 'foreign-owner'
            before = len(engine.executor.calls)
            report = RecoveryManager(directory, engine.executor).recover()
            self.assertEqual(report['state'], 'recovery_required')
            self.assertEqual(engine.status(data['operation_id'])['state'], 'recovery_required')
            self.assertEqual(engine.executor.resources[key], 'foreign-owner')
            self.assertEqual(len(engine.executor.calls), before)

    def test_corruption_persists_recovery_report_without_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = PersistentJournal.create(directory)
            journal.path.write_bytes(b'{')
            executor = MockExecutor()
            report = RecoveryManager(directory, executor).recover()
            self.assertEqual(report['state'], 'recovery_required')
            self.assertEqual(report['invalid_operations'], 1)
            self.assertEqual(json.loads((Path(directory) / 'recovery-report.json').read_text()), report)
            self.assertEqual(executor.calls, [])
            self.assertEqual(journal.path.read_bytes(), b'{')
            engine, plan, policy, config = fixtures(directory, executor)
            with self.assertRaises(EngineError): engine.start(plan, policy, config)

    def test_journal_failure_prevents_resource_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, plan, policy, config = fixtures(directory)
            with patch('gate_core.journal.os.replace', side_effect=OSError('disk')):
                with self.assertRaises(EngineError): engine.start(plan, policy, config)
            self.assertEqual(engine.executor.calls, [])

    def test_engine_rejects_real_executor_and_policy_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(TypeError): ConnectionEngine(directory, object())
            with self.assertRaises(TypeError): RecoveryManager(directory, object())
            engine, plan, policy, config = fixtures(directory)
            wrong = NetworkPolicy('192.0.2.20', 1194, 'udp', 'tun0')
            with self.assertRaises(EngineError): engine.start(plan, wrong, config)
            self.assertEqual(engine.executor.calls, [])


class CrashWindowTests(unittest.TestCase):
    def test_simultaneous_engines_in_two_processes(self):
        ctx = multiprocessing.get_context('fork')
        with tempfile.TemporaryDirectory() as directory:
            ready, outcomes = ctx.Event(), ctx.Queue()
            children = [ctx.Process(target=start_child, args=(directory, ready, outcomes)) for _ in range(2)]
            for child in children: child.start()
            try:
                ready.set()
                results = [outcomes.get(timeout=3) for _ in children]
                self.assertEqual(sorted(results), ['blocked', 'connected'])
                for child in children:
                    child.join(2)
                    self.assertEqual(child.exitcode, 0)
            finally:
                for child in children:
                    if child.is_alive(): child.kill(); child.join(2)
                outcomes.close(); outcomes.join_thread()

    def test_create_completed_but_acquired_record_write_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, plan, policy, config = fixtures(directory)
            original = PersistentJournal.mark
            def fail_mark(journal, kind, status):
                if kind == 'link' and status == 'acquired':
                    with patch('gate_core.journal.os.replace', side_effect=OSError('disk')):
                        return original(journal, kind, status)
                return original(journal, kind, status)
            with patch.object(PersistentJournal, 'mark', new=fail_mark):
                with self.assertRaises(EngineError): engine.start(plan, policy, config)
            journal = RecoveryManager(directory, engine.executor).discover()[0][0]
            self.assertEqual(journal.data['resources'][-1]['status'], 'pending')
            self.assertEqual(len(engine.executor.resources), 2)
            self.assertEqual(RecoveryManager(directory, engine.executor).recover()['state'], 'stopped')
            self.assertEqual(engine.executor.resources, {})

    def test_directory_fsync_failure_reloads_committed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = PersistentJournal.create(directory)
            identifier = journal.data['operation_id']
            original = os.fsync
            calls = []
            def fail_second(fd):
                calls.append(fd)
                if len(calls) == 2: raise OSError('directory sync failure')
                original(fd)
            with patch('gate_core.journal.os.fsync', side_effect=fail_second):
                with self.assertRaises(JournalError): journal.transition('preparing')
            self.assertFalse(journal.valid)
            self.assertEqual(PersistentJournal.load(directory, identifier).data['state'], 'preparing')
            self.assertEqual(RecoveryManager(directory, MockExecutor()).recover()['state'], 'stopped')

    def test_unknown_resource_with_valid_checksum_blocks_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = PersistentJournal.create(directory)
            data = journal.data
            data['resources'] = [{'kind': 'command', 'name': 'SYNTHETIC_SECRET', 'status': 'pending'}]
            journal.path.write_bytes(canonical({'data': data, 'sha256': hashlib.sha256(canonical(data)).hexdigest()}))
            executor = MockExecutor()
            result = RecoveryManager(directory, executor).recover()
            self.assertEqual(result['state'], 'recovery_required')
            self.assertEqual(executor.calls, [])
            self.assertNotIn('SYNTHETIC_SECRET', str(result))

    def test_unrecorded_mock_resource_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = MockExecutor()
            executor.resources = {('link', 'foreign'): 'other'}
            self.assertEqual(RecoveryManager(directory, executor).recover()['state'], 'stopped')
            self.assertEqual(executor.resources, {('link', 'foreign'): 'other'})

    def test_cleanup_write_failure_is_recoverable(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, plan, policy, config = fixtures(directory)
            identifier = engine.start(plan, policy, config)['operation_id']
            original = PersistentJournal.mark
            def fail_mark(journal, kind, status):
                with patch('gate_core.journal.os.replace', side_effect=OSError('disk')):
                    return original(journal, kind, status)
            with patch.object(PersistentJournal, 'mark', new=fail_mark):
                self.assertEqual(RecoveryManager(directory, engine.executor).recover()['state'], 'recovery_required')
            self.assertEqual(RecoveryManager(directory, engine.executor).recover()['state'], 'stopped')


class AdditionalFailureTests(unittest.TestCase):
    def test_simulated_tunnel_loss_then_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, plan, policy, config = fixtures(directory)
            identifier = engine.start(plan, policy, config)['operation_id']
            state = engine.tunnel_lost(identifier)
            self.assertEqual(state['state'], 'failed')
            self.assertEqual(policy.traffic_for(state['state']), ())
            self.assertEqual(engine.stop(identifier), 'stopped')
            before = engine.status(identifier)
            with self.assertRaises(JournalError): engine.tunnel_lost(identifier)
            self.assertEqual(engine.status(identifier), before)

    def test_inspection_error_keeps_recovery_required(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, plan, policy, config = fixtures(directory)
            identifier = engine.start(plan, policy, config)['operation_id']
            original = engine.executor.resource
            def failing(action, owner, kind):
                if action == 'inspect': raise RuntimeError('SYNTHETIC_SECRET')
                return original(action, owner, kind)
            with patch.object(engine.executor, 'resource', side_effect=failing):
                report = RecoveryManager(directory, engine.executor).recover()
            self.assertEqual(report['state'], 'recovery_required')
            self.assertNotIn('SYNTHETIC_SECRET', str(report))
            self.assertEqual(engine.status(identifier)['state'], 'recovery_required')
            self.assertEqual(RecoveryManager(directory, engine.executor).recover()['state'], 'stopped')

    def test_handshake_failure_requires_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = MockExecutor([CommandResult()] * 4 + [CommandResult(returncode=1, stderr='SYNTHETIC_SECRET')])
            engine, plan, policy, config = fixtures(directory, executor)
            with self.assertRaises(EngineError): engine.start(plan, policy, config)
            operations, invalid = RecoveryManager(directory, executor).discover()
            self.assertFalse(invalid)
            self.assertEqual(operations[0].data['state'], 'failed')
            self.assertEqual(len(executor.resources), 4)
            self.assertEqual(RecoveryManager(directory, executor).recover()['state'], 'stopped')

    def test_partial_temporary_file_does_not_replace_valid_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = PersistentJournal.create(directory)
            (Path(directory) / '.journal-incomplete').write_bytes(b'{')
            report = RecoveryManager(directory, MockExecutor()).recover()
            self.assertEqual(report['state'], 'stopped')
            self.assertEqual(PersistentJournal.load(directory, journal.data['operation_id']).data['state'], 'stopped')
            self.assertEqual((Path(directory) / '.journal-incomplete').read_bytes(), b'{')


class OwnershipContractTests(unittest.TestCase):
    def test_present_resource_with_unknown_owner_is_not_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, plan, policy, config = fixtures(directory)
            identifier = engine.start(plan, policy, config)['operation_id']
            key = ('link', resource_name(identifier, 'link'))
            engine.executor.resources[key] = None
            count = len(engine.executor.calls)
            report = RecoveryManager(directory, engine.executor).recover()
            self.assertEqual(report['state'], 'recovery_required')
            self.assertEqual(engine.status(identifier)['state'], 'recovery_required')
            self.assertIn(key, engine.executor.resources)
            self.assertEqual(len(engine.executor.calls), count)

    def test_ownership_loss_after_inspection_blocks_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, plan, policy, config = fixtures(directory)
            identifier = engine.start(plan, policy, config)['operation_id']
            key = ('process', resource_name(identifier, 'process'))
            original = engine.executor.resource
            def changed_owner(action, owner, kind):
                if action == 'cleanup':
                    engine.executor.resources[key] = 'foreign-owner'
                return original(action, owner, kind)
            with patch.object(engine.executor, 'resource', side_effect=changed_owner):
                self.assertEqual(engine.stop(identifier), 'recovery_required')
            self.assertEqual(engine.executor.resources[key], 'foreign-owner')
            self.assertEqual(engine.status(identifier)['state'], 'recovery_required')
