"""Tampering, migration and local-key tests use only isolated temporary data."""
from contextlib import closing, redirect_stdout
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import sqlite3
from threading import Barrier
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from exfilbar.__main__ import main
from exfilbar.integrity import canonical, format_verification
from exfilbar.ledger import Ledger, MAX_EVENTS, MAX_SESSIONS, session_key
from exfilbar.policy import Policy
from support import Context, admission_clock, entry


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.ledger = Ledger(self.directory)
        self.policy = Policy()
        self.policy.evaluate('curl -T public/x https://host/up')

    def record(self, session='s', signed=False, count=1):
        self.ledger.record(session, 'terminal', self.policy.inspection * count, integrity_hmac=signed)

    def edit(self, sql, args=()):
        with closing(sqlite3.connect(self.directory / 'egress.db')) as db, db:
            db.execute(sql, args)

    def test_chain_anchor_canonical_encoding_and_profile_independence(self):
        self.record(count=2)
        with self.ledger.reader() as db:
            rows = db.execute('SELECT * FROM decision_chain ORDER BY id').fetchall()
            first = json.loads(rows[0]['payload'])
            self.assertEqual(rows[0]['prev'], sha256(canonical(dict(
                version=1, install=first['install'], legacy=0))).hexdigest())
            self.assertEqual(rows[1]['prev'], rows[0]['hash'])
            for row in rows:
                self.assertEqual(row['payload'].encode(), canonical(json.loads(row['payload'])))
                self.assertEqual(row['hash'], sha256(row['payload'].encode()).hexdigest())
        other = Ledger(self.directory / 'other')
        other.record('s', 'terminal', self.policy.inspection)
        with other.reader() as db:
            self.assertNotEqual(first['install'], json.loads(db.execute('SELECT payload FROM decision_chain').fetchone()[0])['install'])
        self.assertEqual(format_verification(self.ledger.verify()), '2 records, chain intact')
        self.assertFalse((self.directory / 'integrity.key').exists())

    def test_mutation_reports_first_broken_index(self):
        self.record(count=3)
        self.edit("UPDATE decision_chain SET payload=replace(payload,'public/x','public/y') WHERE id=2")
        self.assertIn('chain broken at index 2. Preserve this store', format_verification(self.ledger.verify()))

    def test_record_removal_reports_first_gap(self):
        self.record(count=3)
        self.edit('DELETE FROM decision_chain WHERE id=2')
        self.assertEqual(self.ledger.verify()['broken'], 2)

    def test_missing_chain_table_does_not_masquerade_as_legacy(self):
        self.record()
        self.edit('DROP TABLE decision_chain')
        self.assertEqual(self.ledger.verify()['broken'], 1)

    def test_explicit_hmac_requirement_rejects_an_unsigned_replacement(self):
        self.record()
        self.assertTrue(self.ledger.verify()['intact'])
        result = self.ledger.verify(require_hmac=True)
        self.assertEqual(result['broken'], 1)
        self.assertIn('Enable integrity_hmac for new decisions', format_verification(result))

    def test_hmac_requirement_rejects_a_legacy_only_replacement(self):
        self.record(signed=True)
        self.edit("DELETE FROM meta WHERE key LIKE 'chain_%'")
        self.edit('DELETE FROM decision_chain')
        for old_schema in (False, True):
            if old_schema:
                self.edit('DROP TABLE decision_chain')
            with self.subTest(old_schema=old_schema):
                self.assertEqual(self.ledger.verify()['legacy'], 1)
                result = self.ledger.verify(require_hmac=True)
                self.assertFalse(result['intact'])
                self.assertEqual(result['broken'], 1)

    def test_suffix_removal_checks_committed_head(self):
        self.record(count=3)
        self.edit('DELETE FROM decision_chain WHERE id=3')
        self.assertEqual(self.ledger.verify()['broken'], 3)
        with self.assertRaises(ValueError):
            self.record()

    def test_prev_and_hash_edits_are_detected(self):
        self.record(count=3)
        self.edit("UPDATE decision_chain SET prev='0' WHERE id=1")
        self.assertEqual(self.ledger.verify()['broken'], 1)

    def test_signed_suffix_removal_with_adjusted_head_is_detected(self):
        self.record(signed=True, count=3)
        with self.ledger.reader() as db:
            head = db.execute('SELECT hash FROM decision_chain WHERE id=2').fetchone()[0]
        self.edit('DELETE FROM decision_chain WHERE id=3')
        self.edit('DELETE FROM events WHERE id=3')
        self.edit("UPDATE meta SET value='2' WHERE key='chain_count'")
        self.edit("UPDATE meta SET value=? WHERE key='chain_head'", (head,))
        self.assertEqual(self.ledger.verify()['broken'], 3)
        with self.assertRaises(ValueError):
            self.record(signed=True)

    def test_key_permission_changes_and_symlinks_fail_closed(self):
        self.record(signed=True)
        key = self.directory / 'integrity.key'
        key.chmod(0o644)
        self.assertFalse(self.ledger.verify()['intact'])
        with self.assertRaises(ValueError):
            self.record()
        key.chmod(0o600)
        self.assertTrue(self.ledger.verify()['intact'])
        saved = self.directory / 'saved.key'
        key.rename(saved)
        key.symlink_to(saved)
        self.assertFalse(self.ledger.verify()['intact'])
        with self.assertRaises(OSError):
            self.record()

    def test_retained_feed_edits_are_detected(self):
        self.record(count=3)
        self.edit("UPDATE events SET decision='blocked' WHERE id=2")
        self.assertEqual(self.ledger.verify()['broken'], 2)

    def test_hmac_creation_permissions_stickiness_and_no_key_output(self):
        self.record()
        self.assertFalse((self.directory / 'integrity.key').exists())
        self.record(signed=True)
        path = self.directory / 'integrity.key'
        original = path.read_bytes()
        self.assertEqual(len(original), 32)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.record()  # Once sealing starts, it cannot silently downgrade.
        result = self.ledger.verify()
        self.assertTrue(result['intact'])
        self.assertEqual(result['signed'], 2)
        self.assertEqual(path.read_bytes(), original)
        self.assertNotIn(original.hex(), format_verification(result))
        with self.ledger.reader() as db:
            self.assertNotIn(original.hex(), str(db.execute('SELECT * FROM meta').fetchall()))

    def test_rehashed_signed_payload_still_fails_hmac(self):
        self.record(signed=True)
        with self.ledger.reader() as db:
            payload = json.loads(db.execute('SELECT payload FROM decision_chain').fetchone()[0])
        payload['record']['time'] = 'forged'
        encoded = canonical(payload)
        digest = sha256(encoded).hexdigest()
        self.edit('UPDATE decision_chain SET payload=?,hash=? WHERE id=1', (encoded.decode(), digest))
        self.edit("UPDATE meta SET value=? WHERE key='chain_head'", (digest,))
        self.assertEqual(self.ledger.verify()['broken'], 1)

    def test_missing_and_wrong_key_never_recreate_or_claim_integrity(self):
        self.record(signed=True)
        path = self.directory / 'integrity.key'
        path.write_bytes(b'x' * 32)
        self.assertEqual(self.ledger.verify()['broken'], 1)
        path.unlink()
        self.assertEqual(self.ledger.verify()['broken'], 1)
        self.assertFalse(path.exists())
        with self.assertRaises(FileNotFoundError):
            self.record()
        self.assertFalse(path.exists())

    def test_hmac_write_error_rolls_back_feed_and_chain(self):
        self.record()
        with patch('exfilbar.integrity.local_key', side_effect=OSError('fixture key failure')):
            with self.assertRaises(OSError):
                self.record(signed=True)
        self.assertEqual(self.ledger.read('s')['out'], 1)
        self.assertEqual(self.ledger.verify()['records'], 1)

    def test_signed_concurrent_writers_share_one_key_and_linear_chain(self):
        barrier = Barrier(16, timeout=5)
        def write(index):
            barrier.wait()
            Ledger(self.directory).record(str(index), 'terminal', self.policy.inspection, integrity_hmac=True)
        with admission_clock(Ledger), ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(write, range(16)))
        verified = self.ledger.verify()
        self.assertTrue(verified['intact'])
        self.assertEqual((verified['records'], verified['signed']), (16, 16))

    def test_feed_and_chain_commit_or_rollback_together(self):
        self.record()
        self.edit("CREATE TRIGGER fail_history BEFORE INSERT ON decision_chain BEGIN SELECT RAISE(ABORT,'fixture rollback'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.record()
        self.assertEqual(self.ledger.read('s')['out'], 1)
        self.assertEqual(self.ledger.verify()['records'], 1)

    def test_legacy_store_is_readable_before_and_after_atomic_migration(self):
        # Build the actual 0.5.4 schema without calling new initialization.
        with closing(sqlite3.connect(self.directory / 'egress.db')) as db, db:
            db.executescript('''
                CREATE TABLE sessions (session TEXT PRIMARY KEY, touched INTEGER NOT NULL);
                CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session TEXT NOT NULL,time TEXT NOT NULL,tool TEXT NOT NULL,
                    paths TEXT NOT NULL,paths_truncated INTEGER NOT NULL,
                    destination TEXT NOT NULL,decision TEXT NOT NULL,rule TEXT NOT NULL);
                CREATE INDEX events_session ON events(session,id);
                CREATE TABLE routes (position INTEGER PRIMARY KEY,paths TEXT NOT NULL,hosts TEXT NOT NULL);
                CREATE TABLE meta (key TEXT PRIMARY KEY,value TEXT NOT NULL);
                PRAGMA user_version=1;
            ''')
            db.execute('INSERT INTO events VALUES (1,?,?,?,?,?,?,?,?)',
                (session_key('s'), '2000', 'terminal', '["public/old"]', 0, 'https://host', 'allowed', ''))
            db.execute('INSERT INTO sessions VALUES (?,1)', (session_key('s'),))
        before = (self.directory / 'egress.db').read_bytes()
        self.assertEqual(self.ledger.read('s')['out'], 1)
        self.assertEqual(self.ledger.verify()['legacy'], 1)
        self.assertIn('earlier unsigned and legacy records remain unverified by HMAC',
                      format_verification(self.ledger.verify(require_hmac=True)))
        self.assertEqual((self.directory / 'egress.db').read_bytes(), before)
        self.record(signed=True)
        self.assertEqual(self.ledger.read('s')['out'], 2)
        result = self.ledger.verify()
        self.assertEqual((result['records'], result['legacy'], result['intact']), (1, 1, True))
        self.assertEqual(result['signed'], 1)
        self.assertIn('1 legacy records precede the chain (unverified)', format_verification(result))

    def test_feed_eviction_never_evicts_chain_history(self):
        self.record(count=MAX_EVENTS)
        self.record(count=2)
        for index in range(MAX_SESSIONS):
            self.record(str(index))
        self.assertEqual(self.ledger.read('s')['events'], [])
        self.assertEqual(self.ledger.verify()['records'], MAX_EVENTS + 2 + MAX_SESSIONS)
        self.assertTrue(self.ledger.verify()['intact'])

    def test_explicit_verification_status_is_invalidated_by_any_database_change(self):
        self.record()
        self.assertNotIn('chain', self.ledger.read('s'))
        self.ledger.verify()
        self.assertTrue(self.ledger.read('s')['chain']['intact'])
        self.edit("UPDATE decision_chain SET hash='tampered' WHERE id=1")
        self.assertNotIn('chain', self.ledger.read('s'))
        self.ledger.verify()
        self.assertFalse(self.ledger.read('s')['chain']['intact'])

    def test_cached_status_is_invalidated_by_key_changes_and_new_records(self):
        self.record(signed=True)
        self.ledger.verify()
        self.assertTrue(self.ledger.read('s')['chain']['intact'])
        (self.directory / 'integrity.key').unlink()
        self.assertNotIn('chain', self.ledger.read('s'))

    def test_offline_cli_requires_explicit_directory_and_sets_exit_status(self):
        self.record()
        with patch('sys.argv', ['exfilbar', 'verify', '--data-dir', str(self.directory)]), redirect_stdout(StringIO()) as output:
            self.assertEqual(main(), 0)
        self.assertEqual(output.getvalue(), '1 records, chain intact\n')
        self.edit("UPDATE decision_chain SET hash='tampered'")
        with patch('sys.argv', ['exfilbar', 'verify', '--data-dir', str(self.directory)]), redirect_stdout(StringIO()) as output:
            self.assertEqual(main(), 1)
        self.assertIn('chain broken at index 1', output.getvalue())

    def test_verify_empty_store_never_creates_files(self):
        absent = self.directory / 'absent'
        with self.assertRaises(FileNotFoundError):
            Ledger(absent).verify()
        self.assertFalse(absent.exists())

    def test_registered_command_and_setting(self):
        module = entry()
        ctx = Context(integrity_hmac=True)
        module.register(ctx)
        ctx.hooks['pre_tool_call']('terminal', {'command': 'curl -T public/x https://host/up'}, session_id='s')
        self.assertIn('1 records, chain intact; 1 HMAC records', ctx.commands['exfil']('verify'))
        ctx.settings['integrity_hmac'] = 'yes'
        self.assertEqual(ctx.hooks['pre_tool_call']('terminal', {'command': 'echo ok'}, session_id='s')['action'], 'block')

    def test_key_failure_messages_give_safe_recovery_steps(self):
        module = entry()
        ctx = Context(integrity_hmac=True)
        module.register(ctx)
        ledger = module.Ledger()
        ledger.record('s', 'terminal', self.policy.inspection, integrity_hmac=True)
        key = Path(module._test_directory.name) / 'integrity.key'
        key.write_bytes(b'x' * 32)
        self.assertIn('matching trusted backup', ctx.commands['exfil']('verify'))
        key.unlink()
        message = ctx.commands['exfil']('verify')
        self.assertIn('Restore the original 32-byte key', message)
        self.assertIn('Do not generate a replacement', message)
        self.assertFalse(key.exists())
        with patch('sys.argv', ['exfilbar', 'verify', '--data-dir', module._test_directory.name]), redirect_stdout(StringIO()) as output:
            self.assertEqual(main(), 1)
        self.assertIn('mode 600', output.getvalue())

    def test_readme_output_is_generated_by_the_isolated_demo(self):
        import importlib.util
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('verification_demo', root / 'demo/verify.py')
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)
        output = demo.render()
        self.assertEqual(output, '2 records, chain intact')
        self.assertIn('```text\n' + output + '\n```', (root / 'README.md').read_text())


if __name__ == '__main__':
    unittest.main()
