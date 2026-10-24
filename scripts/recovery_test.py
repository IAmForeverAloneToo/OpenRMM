"""Run inside WSL as root: python3 -m unittest discover -s scripts -p recovery_test.py."""
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import recovery


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root filesystem checks')
class RecoveryChecks(unittest.TestCase):
    def test_checksums_and_private_ancestors_fail_closed(self):
        with tempfile.TemporaryDirectory(dir='/var/lib', prefix='openrmm-recovery-test-') as temp:
            base = Path(temp) / 'backups'
            path = recovery.new_directory(base, 'test')
            recovery.write_json(path / 'runtime.json', {'test': True})
            recovery.write_json(path / 'manifest.json', {'format': 1, 'files': recovery.file_inventory(path)})
            with patch.object(recovery, 'BACKUPS', base):
                recovery.checked_backup(base, 'test')
                (path / 'runtime.json').write_text('{}')
                with self.assertRaises(recovery.RecoveryError):
                    recovery.checked_backup(base, 'test')
            os.chmod(base, 0o755)
            with self.assertRaises(recovery.RecoveryError):
                recovery.private_base(base)

    def test_restore_reconciles_revocation_without_resurrecting_bearers(self):
        with tempfile.TemporaryDirectory(dir='/var/lib', prefix='openrmm-recovery-test-') as temp:
            directory = Path(temp)
            device = 'a' * 32
            with sqlite3.connect(directory / 'openrmm.db') as db:
                db.executescript('''
                    CREATE TABLE devices(id TEXT PRIMARY KEY,revoked_at INTEGER,previous_fingerprint TEXT,previous_until INTEGER);
                    CREATE TABLE event_log_queries(result_json TEXT); INSERT INTO event_log_queries VALUES ('private old event');
                    CREATE TABLE device_script_support(last_status TEXT,support_json TEXT); INSERT INTO device_script_support VALUES('ok','old support');
                    CREATE TABLE script_schedules(state TEXT,revision INTEGER,updated_at INTEGER);
                    INSERT INTO script_schedules VALUES('active',1,100),('paused',2,100),('cancelled',3,100),('completed',1,100);
                    CREATE TABLE script_schedule_occurrences(outcome TEXT); INSERT INTO script_schedule_occurrences VALUES('old');
                    CREATE TABLE script_batches(restored INTEGER); INSERT INTO script_batches VALUES(0);
                    CREATE TABLE script_runs(status TEXT,finished_at INTEGER,result_json TEXT);
                    INSERT INTO script_runs VALUES('queued',NULL,''),('dispatched',NULL,''),('running',NULL,''),('succeeded',100,'private output');
                    CREATE TABLE file_jobs(status TEXT,payload BLOB,reserve_bytes INTEGER,result_json TEXT,payload_until INTEGER,finished_at INTEGER);
                    INSERT INTO file_jobs VALUES('queued',X'0102',2,'old',999,NULL),('dispatched',X'03',1,'old',999,NULL),('succeeded',X'04',1,'old',999,100);
                    CREATE TABLE agent_upgrade_jobs(status TEXT,finished_at INTEGER,result_json TEXT);
                    INSERT INTO agent_upgrade_jobs VALUES('queued',NULL,'sensitive'),('dispatched',NULL,'sensitive'),('succeeded',100,'sensitive');
                    CREATE TABLE device_agent_upgrade_support(last_status TEXT,support_json TEXT);
                    INSERT INTO device_agent_upgrade_support VALUES('ok','old update support');
                    CREATE TABLE device_file_support(last_status TEXT,support_json TEXT); INSERT INTO device_file_support VALUES('ok','old folder permission');
                    CREATE TABLE application_deployments(status TEXT,finished_at INTEGER,result_json TEXT);
                    INSERT INTO application_deployments VALUES('queued',NULL,''),('running',NULL,''),('succeeded',100,'old verified registration');
                    CREATE TABLE device_processes(last_status TEXT); INSERT INTO device_processes VALUES('ok');
                    CREATE TABLE process_actions(status TEXT,finished_at INTEGER);
                    INSERT INTO process_actions VALUES('queued',NULL),('dispatched',NULL),('succeeded',100);
                    CREATE TABLE device_software(baseline_ready INTEGER,last_status TEXT,snapshot_json TEXT);
                    INSERT INTO device_software VALUES(1,'ok','retained stale software');
                    CREATE TABLE software_changes(value TEXT); INSERT INTO software_changes VALUES('old observation');
                    CREATE TABLE alert_runtime(mail_paused INTEGER,last_sweep INTEGER,mail_config TEXT,gap INTEGER);
                    INSERT INTO alert_runtime VALUES(0,250,'old-config',0);
                    CREATE TABLE alert_samples(value TEXT); INSERT INTO alert_samples VALUES('old reading');
                    CREATE TABLE alert_deliveries(value TEXT); INSERT INTO alert_deliveries VALUES('old notice');
                    CREATE TABLE alert_states(state_json TEXT);
                    INSERT INTO alert_states VALUES('Unknown placeholder');
                    CREATE TABLE patch_policies(state TEXT,revision INTEGER,updated_at INTEGER);
                    INSERT INTO patch_policies VALUES('active',1,100),('paused',2,100),('archived',3,100);
                    CREATE TABLE patch_device_guards(hold TEXT,revision INTEGER);
                    INSERT INTO patch_device_guards VALUES('mutation_running',1),('restart_requested',2);
                    CREATE TABLE patch_runs(status TEXT,detail TEXT,finished_at INTEGER);
                    INSERT INTO patch_runs VALUES('installing','',NULL),('approved_complete','verified',100);
                    CREATE TABLE metric_buckets(value TEXT); INSERT INTO metric_buckets VALUES('historical aggregate');
                    CREATE TABLE metric_receipts(last_at INTEGER); INSERT INTO metric_receipts VALUES(100);
                    CREATE TABLE update_jobs(status TEXT,finished_at INTEGER);
                    INSERT INTO update_jobs VALUES ('queued',NULL),('dispatched',NULL),('succeeded',100);
                    CREATE TABLE service_actions(status TEXT,finished_at INTEGER);
                    INSERT INTO service_actions VALUES ('queued',NULL),('dispatched',NULL),('succeeded',100);
                    CREATE TABLE health_checks(response INTEGER,revision INTEGER);
                    INSERT INTO health_checks VALUES(1,2),(0,3);
                    CREATE TABLE health_samples(value TEXT); INSERT INTO health_samples VALUES('stale');
                    CREATE TABLE health_states(state_json TEXT);
                    INSERT INTO health_states VALUES('{"condition":"bad","since":100,"samples":2,"last_sample":250,"incident":"keep-health"}');
                    CREATE TABLE technicians(enabled INTEGER,revision INTEGER,invitation_hash TEXT,invitation_until INTEGER,last_totp_step INTEGER);
                    INSERT INTO technicians VALUES(1,3,'old-invitation',1000,0);
                    CREATE TABLE technician_recovery_codes(code TEXT); INSERT INTO technician_recovery_codes VALUES('spent-tech-code');
                    CREATE TABLE sessions(token TEXT); CREATE TABLE enrollment_tokens(token TEXT);
                    CREATE TABLE recovery_codes(code TEXT); CREATE TABLE administrators(last_totp_step INTEGER);
                    CREATE TABLE audit_events(id INTEGER PRIMARY KEY,occurred_at TEXT,actor TEXT,action TEXT,outcome TEXT,target TEXT);
                    INSERT INTO sessions VALUES ('old-session'); INSERT INTO enrollment_tokens VALUES ('old-token');
                    INSERT INTO recovery_codes VALUES ('old-code'); INSERT INTO administrators VALUES (0);
                ''')
                db.execute('INSERT INTO devices VALUES (?,NULL,?,?)', (device, 'old-fingerprint', 999999))
            with sqlite3.connect(directory / 'openrmm.db') as db:
                db.execute('UPDATE alert_states SET state_json=?', (json.dumps(dict(condition='bad',since=100,samples=2,value=95,incident='keep-open')),))
            recovery.reconcile(directory, 'instance', {'format': 1, 'instance_id': 'instance', 'revoked': {device: 100}}, 300)
            with sqlite3.connect(directory / 'openrmm.db') as db:
                self.assertEqual(db.execute('SELECT revoked_at,previous_fingerprint,previous_until FROM devices').fetchone(), (100, '', 0))
                for table in ['sessions', 'enrollment_tokens', 'recovery_codes','event_log_queries','alert_deliveries','alert_samples']:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 0)
                self.assertEqual(db.execute('SELECT enabled,revision,invitation_hash,invitation_until,last_totp_step FROM technicians').fetchone(), (0,4,None,None,10))
                self.assertEqual(db.execute('SELECT COUNT(*) FROM technician_recovery_codes').fetchone()[0], 0)
                self.assertEqual(db.execute('SELECT mail_paused,last_sweep,mail_config FROM alert_runtime').fetchone(), (1,0,''))
                self.assertEqual(db.execute('SELECT baseline_ready,last_status,snapshot_json FROM device_software').fetchone(), (0,'failed','retained stale software'))
                self.assertEqual(db.execute('SELECT COUNT(*) FROM software_changes').fetchone()[0], 0)
                state=json.loads(db.execute('SELECT state_json FROM alert_states').fetchone()[0])
                self.assertEqual((state['condition'],state['since'],state['samples'],state['incident']), ('unknown',0,0,'keep-open'))
                self.assertEqual(db.execute('SELECT last_totp_step FROM administrators').fetchone()[0], 10)
                self.assertEqual(db.execute('SELECT action FROM audit_events').fetchone()[0], 'restore_reconciled')
                self.assertEqual(db.execute('SELECT restored FROM script_batches').fetchall(), [(1,)])
                self.assertEqual(db.execute('SELECT status,finished_at,result_json FROM script_runs').fetchall(), [('cancelled',300,''),('unknown',300,''),('unknown',300,''),('succeeded',100,'')])
                self.assertEqual(db.execute('SELECT state,revision,updated_at FROM script_schedules').fetchall(), [('paused',2,300),('paused',3,300),('cancelled',3,100),('completed',1,100)])
                self.assertEqual(db.execute('SELECT COUNT(*) FROM script_schedule_occurrences').fetchone()[0], 0)
                self.assertEqual(db.execute('SELECT last_status,support_json FROM device_script_support').fetchone(), ('failed',''))
                self.assertEqual(db.execute('SELECT status,finished_at,result_json FROM application_deployments').fetchall(),[('cancelled',300,''),('unknown',300,''),('succeeded',100,'')])
                self.assertEqual(db.execute('SELECT status,length(payload),reserve_bytes,result_json,payload_until FROM file_jobs').fetchall(), [('cancelled',0,0,'',0),('unknown',0,0,'',0),('succeeded',0,0,'',0)])
                self.assertEqual(db.execute('SELECT * FROM metric_buckets').fetchall(), [('historical aggregate',)])
                self.assertEqual(db.execute('SELECT * FROM metric_receipts').fetchall(), [(100,)])
                self.assertEqual(db.execute('SELECT * FROM patch_policies').fetchall(), [('paused',2,300),('paused',3,300),('archived',3,100)])
                self.assertEqual(db.execute('SELECT * FROM patch_device_guards').fetchall(), [('needs_review',2),('restart_requested',2)])
                self.assertEqual(db.execute('SELECT * FROM patch_runs').fetchall(), [('unknown','server_restore',300),('approved_complete','verified',100)])
                self.assertEqual(db.execute('SELECT status,finished_at,result_json FROM agent_upgrade_jobs').fetchall(),[('cancelled',300,''),('unknown',300,''),('succeeded',100,'')])
                self.assertEqual(db.execute('SELECT last_status,support_json FROM device_agent_upgrade_support').fetchone(),('failed',''))
                self.assertEqual(db.execute('SELECT last_status,support_json FROM device_file_support').fetchone(),('failed',''))
                self.assertEqual(db.execute('SELECT last_status FROM device_processes').fetchone()[0], 'failed')
                self.assertEqual(db.execute('SELECT status,finished_at FROM process_actions').fetchall(), [('cancelled',300),('unknown',300),('succeeded',100)])
                self.assertEqual(db.execute('SELECT status,finished_at FROM service_actions').fetchall(), [('cancelled',300),('unknown',300),('succeeded',100)])
                self.assertEqual(db.execute('SELECT response,revision FROM health_checks').fetchall(),[(0,3),(0,4)])
                self.assertEqual(db.execute('SELECT COUNT(*) FROM health_samples').fetchone()[0],0)
                health=json.loads(db.execute('SELECT state_json FROM health_states').fetchone()[0])
                self.assertEqual((health['condition'],health['since'],health['samples'],health['last_sample'],health['incident']),('unknown',0,0,0,'keep-health'))
                self.assertEqual(db.execute('SELECT status,finished_at FROM update_jobs').fetchall(), [('cancelled',300),('unknown',300),('succeeded',100)])
            with self.assertRaises(recovery.RecoveryError):
                recovery.reconcile(directory, 'instance', {'format': 1, 'instance_id': 'another', 'revoked': {}}, 300)
            with self.assertRaises(recovery.RecoveryError):
                recovery.reconcile(directory, 'instance', {'format': 1, 'instance_id': 'instance', 'revoked': {'invalid': 100}}, 300)


if __name__ == '__main__':
    unittest.main()
