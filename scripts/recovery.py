"""Stopped-container backup and staged restore for the local Linux deployment.

Python standard library and the already installed Docker CLI only. Run through
WSL as root. Never reads .env, prints keys, or replaces an existing deployment.
"""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import time

BACKUPS = Path('/var/lib/openrmm-backups')
KEYS = Path('/var/lib/openrmm-key-backups')
RESTORES = Path('/var/lib/openrmm-restores')
PROJECT = re.compile(r'[a-z0-9][a-z0-9-]{1,62}\Z')
RESTORE_PROJECT = re.compile(r'openrmm-restored-[a-z0-9][a-z0-9-]{0,31}\Z')
NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}\Z')
DEVICE = re.compile(r'[0-9a-f]{32}\Z')


class RecoveryError(Exception):
    pass


def command(args, timeout=180):
    # Copies of the evidence volume can take far longer than 180 s.
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RecoveryError('Docker/system operation failed: ' + args[0] + ' ' + args[1])
    return result.stdout


def docker(*args, timeout=180):
    return command(['docker', *map(str, args)], timeout=timeout)


def inspect(container):
    return json.loads(docker('inspect', container))[0]


def private_base(path):
    # Fixed Linux roots; no caller-controlled recursive filesystem targets.
    for ancestor in [*reversed(path.parents), path]:
        if ancestor.exists() or ancestor.is_symlink():
            info = ancestor.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RecoveryError('Recovery paths must have root-owned, non-writable ancestors.')
        else:
            ancestor.mkdir(mode=0o700)
    if path.stat().st_mode & 0o077:
        raise RecoveryError('Recovery base directory must be root-only (0700).')


def new_directory(base, name):
    private_base(base)
    path = base / name
    path.mkdir(mode=0o700)  # Existing paths, including links, are refused.
    return path


def write_json(path, value):
    with path.open('x', encoding='utf-8') as output:
        os.chmod(path, 0o600)
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n')


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise RecoveryError('Recovery metadata is missing, linked, or oversized.')
    return json.loads(path.read_text(encoding='utf-8'))


def hash_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def file_inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise RecoveryError('Backup trees may contain only ordinary files and directories.')
        if path.name == 'manifest.json' and path.parent == root:
            continue
        if path.is_file():
            result[str(path.relative_to(root))] = hash_file(path)
    return result


def checked_backup(base, name):
    private_base(base)
    path = base / name
    if path.is_symlink() or not path.is_dir() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise RecoveryError('Backup set must be a root-owned, root-only directory.')
    manifest = read_json(path / 'manifest.json')
    if manifest.get('format') != 1 or manifest.get('files') != file_inventory(path):
        raise RecoveryError('Backup checksum/format validation failed; no deployment was changed.')
    return path, manifest


def database_info(directory):
    with closing(sqlite3.connect((directory / 'openrmm.db').as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise RecoveryError('Snapshot database integrity check failed.')
        row = db.execute('SELECT instance_id,created_at FROM server_state WHERE id=1').fetchone()
        version = db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0]
        revoked = {row[0]: row[1] for row in db.execute('SELECT id,revoked_at FROM devices WHERE revoked_at IS NOT NULL')}
    return dict(instance_id=row[0], created_at=row[1], schema_version=version), revoked


def runtime_config(info):
    if info['Config']['User'] != '10001:10001' or info['Config']['Entrypoint'] != ['/openrmm-server'] or info['Config'].get('Cmd'):
        raise RecoveryError('Backup supports the documented OpenRMM container layout only.')
    mounts = {item['Destination']: item for item in info['Mounts']}
    # Newer deployments add an evidence volume; older ones have three.
    evidence = '/evidence' in mounts
    if set(mounts) - {'/evidence'} != {'/data', '/tls', '/secrets'} or any(item['Type'] != 'volume' for item in mounts.values()):
        raise RecoveryError('Expected the named application volumes (data, tls, secrets and optionally evidence).')
    env = dict(item.split('=', 1) for item in info['Config']['Env'] if item.startswith('OPENRMM_'))
    expected = {'OPENRMM_SERVER_DATABASE': '/data/openrmm.db', 'OPENRMM_SERVER_ENCRYPTION_KEY': '/secrets/admin-key.bin',
                'OPENRMM_SERVER_DEVICE_AUTHORITY': '/secrets/device-ca/authority.pem',
                'OPENRMM_SERVER_TLS_CERT': '/tls/local/server.pem', 'OPENRMM_SERVER_TLS_KEY': '/tls/local/server-key.pem'}
    if evidence:
        expected['OPENRMM_SERVER_EVIDENCE_DIR'] = '/evidence'
    if any(env.get(key) != value for key, value in expected.items()):
        raise RecoveryError('Backup requires the documented database/key/TLS/evidence paths.')
    ports = info['HostConfig']['PortBindings']
    if set(ports) != {'8443/tcp', '8444/tcp'} or any(len(values) != 1 or values[0]['HostIp'] != '127.0.0.1' for values in ports.values()):
        raise RecoveryError('Backup supports the localhost-only two-listener deployment.')
    return dict(image=info['Image'], environment=env, admin_port=int(ports['8443/tcp'][0]['HostPort']),
                agent_port=int(ports['8444/tcp'][0]['HostPort']), evidence=evidence)


def backup(project, name):
    containers = docker('ps', '-a', '--filter', 'label=com.docker.compose.project=' + project,
                        '--filter', 'label=com.docker.compose.service=server', '--format', '{{.ID}}').splitlines()
    if len(containers) != 1:
        raise RecoveryError('Expected exactly one existing server container for the source project.')
    container = containers[0]
    info = inspect(container)
    runtime = runtime_config(info)
    if info['State']['Paused'] or info['State']['Restarting']:
        raise RecoveryError('Source server is paused/restarting; stabilize it before backup.')
    main = new_directory(BACKUPS, name)
    keys = new_directory(KEYS, name)
    set_id = secrets.token_hex(16)
    # Save the immutable image before stopping the server, keeping downtime short.
    docker('image', 'save', '-o', main / 'server-image.tar', runtime['image'])
    os.chmod(main / 'server-image.tar', 0o600)
    was_running = info['State']['Running']
    try:
        if was_running:
            docker('stop', '--time', '10', container)
        if inspect(container)['State']['Running']:
            raise RecoveryError('Server did not stop; snapshot was not taken.')
        for volume in ['data', 'tls'] + (['evidence'] if runtime['evidence'] else []):
            docker('cp', '-a', container + ':/' + volume, main / volume, timeout=None if volume == 'evidence' else 180)
        docker('cp', '-a', container + ':/secrets', keys / 'secrets')
        instance, revoked = database_info(main / 'data')
        captured = datetime.now(timezone.utc).isoformat()
        write_json(main / 'runtime.json', runtime)
        write_json(main / 'revocations.json', dict(format=1, instance_id=instance['instance_id'], captured_at=captured, revoked=revoked))
        shared = dict(format=1, set_id=set_id, captured_at=captured, source_project=project, instance=instance)
        write_json(keys / 'manifest.json', dict(**shared, files=file_inventory(keys)))
        write_json(main / 'manifest.json', dict(**shared, files=file_inventory(main)))
    finally:
        if was_running:
            docker('start', container)
    return dict(backup=str(main), key_backup=str(keys), source_restarted=was_running)


def reconcile(directory, instance_id, revocations, now):
    if revocations.get('format') != 1 or revocations.get('instance_id') != instance_id or not isinstance(revocations.get('revoked'), dict):
        raise RecoveryError('Reviewed revocations must match this installation.')
    entries = revocations['revoked']
    if len(entries) > 100000 or any(not DEVICE.fullmatch(key) or type(value) is not int or value <= 0 for key, value in entries.items()):
        raise RecoveryError('Reviewed revocation list is invalid.')
    with closing(sqlite3.connect(directory / 'openrmm.db')) as db, db:
        for device, revoked_at in entries.items():
            db.execute('UPDATE devices SET revoked_at=COALESCE(revoked_at,?) WHERE id=?', (revoked_at, device))
        # Rollback must not resurrect bearer sessions, pending tokens, spent
        # recovery codes, a current TOTP step, or superseded-certificate overlap.
        # An old backup must never resurrect a remote service command.
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='patch_policies'").fetchone():
            db.execute("UPDATE patch_policies SET state='paused',revision=revision+1,updated_at=? WHERE state IN('active','paused')", (now,))
            db.execute("UPDATE patch_device_guards SET hold='needs_review',revision=revision+1 WHERE hold='mutation_running'")
            db.execute("UPDATE patch_runs SET status='unknown',detail='server_restore',finished_at=? WHERE finished_at IS NULL", (now,))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='script_schedules'").fetchone():
            db.execute("UPDATE script_schedules SET state='paused',revision=revision+1,updated_at=? WHERE state IN('active','paused')", (now,))
            db.execute("DELETE FROM script_schedule_occurrences")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='agent_upgrade_jobs'").fetchone():
            db.execute("UPDATE agent_upgrade_jobs SET status=CASE WHEN status='queued' THEN 'cancelled' WHEN status='dispatched' THEN 'unknown' ELSE status END,result_json='',finished_at=COALESCE(finished_at,?)", (now,))
            db.execute("UPDATE device_agent_upgrade_support SET last_status='failed',support_json='' ")
        # A restored evidence collection is never resumed or re-dispatched; its
        # end is visible in the job list (no custody entry is written here).
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_jobs'").fetchone():
            db.execute("UPDATE evidence_jobs SET status='failed',outcome='server_restore',finished_at=? WHERE status IN('queued','dispatched','uploading','verifying')", (now,))
            db.execute("DELETE FROM evidence_chunks")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='file_jobs'").fetchone():
            db.execute("UPDATE file_jobs SET status=CASE WHEN status IN('staged','queued') THEN 'cancelled' WHEN status='dispatched' THEN 'unknown' ELSE status END,payload=X'',reserve_bytes=0,result_json='',payload_until=0,finished_at=COALESCE(finished_at,?)", (now,))
            db.execute("UPDATE device_file_support SET last_status='failed',support_json='' ")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='application_deployments'").fetchone():
            db.execute("UPDATE application_deployments SET status=CASE WHEN status='queued' THEN 'cancelled' WHEN status IN('dispatched','running') THEN 'unknown' ELSE status END,result_json='',finished_at=COALESCE(finished_at,?)", (now,))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='script_runs'").fetchone():
            db.execute("UPDATE script_runs SET status=CASE WHEN status='queued' THEN 'cancelled' ELSE 'unknown' END,finished_at=?,result_json='' WHERE status IN('queued','dispatched','running')",(now,))
            db.execute("UPDATE script_runs SET result_json='' ")
            db.execute("UPDATE device_script_support SET last_status='failed',support_json='' ")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='script_batches'").fetchone():
            db.execute("UPDATE script_batches SET restored=1")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_processes'").fetchone():
            db.execute("UPDATE device_processes SET last_status='failed'")
            db.execute("UPDATE process_actions SET status=CASE WHEN status='dispatched' THEN 'unknown' ELSE 'cancelled' END,finished_at=? WHERE status IN ('queued','dispatched')", (now,))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_software'").fetchone():
            db.execute("DELETE FROM software_changes")
            db.execute("UPDATE device_software SET baseline_ready=0,last_status='failed'")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alert_runtime'").fetchone():
            db.execute("DELETE FROM alert_deliveries")
            db.execute("DELETE FROM alert_samples")
            db.execute("UPDATE alert_states SET state_json=json_set(state_json,'$.condition','unknown','$.since',0,'$.samples',0,'$.value',NULL)")
            db.execute("UPDATE alert_runtime SET mail_paused=1,last_sweep=0,mail_config='',gap=0")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='update_jobs'").fetchone():
            db.execute("UPDATE update_jobs SET status=CASE WHEN status='dispatched' THEN 'unknown' ELSE 'cancelled' END,finished_at=? WHERE status IN ('queued','dispatched')", (now,))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='health_checks'").fetchone():
            db.execute("UPDATE health_checks SET response=0,revision=revision+1")
            db.execute("DELETE FROM health_samples")
            db.execute("UPDATE health_states SET state_json=json_set(state_json,'$.condition','unknown','$.since',0,'$.samples',0,'$.last_sample',0)")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='service_actions'").fetchone():
            db.execute("UPDATE service_actions SET status=CASE WHEN status='dispatched' THEN 'unknown' ELSE 'cancelled' END,finished_at=? WHERE status IN ('queued','dispatched')", (now,))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_log_queries'").fetchone():
            db.execute("DELETE FROM event_log_queries")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='technicians'").fetchone():
            db.execute("UPDATE technicians SET enabled=0,revision=revision+1,invitation_hash=NULL,invitation_until=NULL,last_totp_step=MAX(last_totp_step,?)", (now // 30,))
            db.execute("DELETE FROM technician_recovery_codes")
        db.execute('DELETE FROM sessions')
        db.execute('DELETE FROM enrollment_tokens')
        db.execute('DELETE FROM recovery_codes')
        db.execute('UPDATE administrators SET last_totp_step=MAX(last_totp_step,?)', (now // 30,))
        db.execute("UPDATE devices SET previous_fingerprint='',previous_until=0")
        db.execute('INSERT INTO audit_events(occurred_at,actor,action,outcome,target) VALUES (?,?,?,?,?)',
                   (datetime.fromtimestamp(now, timezone.utc).isoformat(), 'local_recovery', 'restore_reconciled', 'success', ''))
        db.execute('DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT 1000)')


def normalized_private_tree(root):
    for path in [root, *root.rglob('*')]:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise RecoveryError('Restore trees may contain only ordinary files/directories.')
        os.chown(path, 10001, 10001)
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def restore(name, target, revocations_path, admin_port=None, agent_port=None):
    main, metadata = checked_backup(BACKUPS, name)
    keys, key_metadata = checked_backup(KEYS, name)
    if metadata['set_id'] != key_metadata['set_id'] or metadata['instance'] != key_metadata['instance']:
        raise RecoveryError('Data and key backups are from different sets.')
    revocations = read_json(Path(revocations_path))
    runtime = read_json(main / 'runtime.json')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', runtime['image']):
        raise RecoveryError('Backup must name an immutable local image ID.')
    if docker('ps', '-a', '--filter', 'label=com.docker.compose.project=' + target, '--format', '{{.ID}}').strip():
        raise RecoveryError('Restore refuses an existing target project.')
    evidence = bool(runtime.get('evidence'))
    copied = ['data', 'tls'] + (['evidence'] if evidence else [])
    volumes = copied + ['secrets']
    existing_volumes = set(docker('volume', 'ls', '--format', '{{.Name}}').splitlines())
    if any(target + '_' + name in existing_volumes for name in volumes):
        raise RecoveryError('Restore refuses pre-existing target volumes.')
    stage = new_directory(RESTORES, target)
    for volume in copied:
        shutil.copytree(main / volume, stage / volume)
    shutil.copytree(keys / 'secrets', stage / 'secrets')
    reconcile(stage / 'data', metadata['instance']['instance_id'], revocations, int(time.time()))
    for volume in volumes:
        normalized_private_tree(stage / volume)
    docker('image', 'load', '-i', main / 'server-image.tar')
    docker('image', 'inspect', runtime['image'])
    admin_port = admin_port or runtime['admin_port']
    agent_port = agent_port or runtime['agent_port']
    if not 1 <= admin_port <= 65535 or not 1 <= agent_port <= 65535 or admin_port == agent_port:
        raise RecoveryError('Restore ports must be distinct and between 1 and 65535.')
    service = dict(image=runtime['image'], pull_policy='never', restart='unless-stopped', user='10001:10001',
                   environment=runtime['environment'], ports=[f'127.0.0.1:{admin_port}:8443', f'127.0.0.1:{agent_port}:8444'],
                   volumes=['data:/data', 'tls:/tls:ro', 'secrets:/secrets'] + (['evidence:/evidence'] if evidence else []), read_only=True, cap_drop=['ALL'],
                   security_opt=['no-new-privileges:true'], pids_limit=64, mem_limit='256m', cpus=1.0, stop_grace_period='10s',
                   healthcheck=dict(test=['CMD', '/openrmm-agent', '-server', 'https://127.0.0.1:8443', '-ca', '/tls/local/ca.pem', '-ready'],
                                    interval='10s', timeout='5s', retries=3, start_period='5s'),
                   logging=dict(driver='json-file', options={'max-size':'5m', 'max-file':'2'}))
    config = stage / 'compose.json'
    write_json(config, dict(name=target, services={'server':service}, volumes={name: {} for name in volumes}))
    base = ['docker', 'compose', '--env-file', 'deploy/local.env', '-f', str(config), '-p', target]
    command([*base, 'create', 'server'])
    container = command([*base, 'ps', '-a', '-q', 'server']).strip()
    if not re.fullmatch(r'[0-9a-f]{12,64}', container) or inspect(container)['State']['Running']:
        raise RecoveryError('Restore target must remain stopped.')
    # TLS is deliberately read-only on the final server. Populate its named
    # volumes through a never-started helper with writable volume mounts instead
    # of weakening the server configuration or using a new helper image.
    mounts = {item['Destination']: item['Name'] for item in inspect(container)['Mounts']}
    helper_args = ['create', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges:true', '--entrypoint', '/openrmm-agent']
    for volume in volumes:
        helper_args += ['--mount', 'type=volume,src=' + mounts['/' + volume] + ',dst=/' + volume]
    helper = docker(*helper_args, runtime['image'], '-help').strip()
    if not re.fullmatch(r'[0-9a-f]{12,64}', helper):
        raise RecoveryError('Cannot create the stopped volume-population helper.')
    try:
        for volume in volumes:
            try:
                docker('cp', '-a', str(stage / volume) + '/.', helper + ':/' + volume + '/', timeout=None if volume == 'evidence' else 180)
            except RecoveryError:
                raise RecoveryError('Cannot populate staged ' + volume + ' volume.') from None
    finally:
        docker('rm', helper)
    write_json(stage / 'restore.json', dict(format=1, source_set_id=metadata['set_id'], project=target,
                                         instance=metadata['instance'], activation_required=True))
    return dict(project=target, compose_file=str(config), state='stopped; review configuration before starting')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    create = sub.add_parser('backup')
    create.add_argument('--project', default='openrmm-local')
    create.add_argument('--name', default=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(3))
    recover = sub.add_parser('restore')
    recover.add_argument('--name', required=True)
    recover.add_argument('--project', required=True)
    recover.add_argument('--revocations', required=True, help='Reviewed current revocation JSON for the matching installation')
    recover.add_argument('--admin-port', type=int)
    recover.add_argument('--agent-port', type=int)
    verify = sub.add_parser('verify')
    verify.add_argument('--name', required=True)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        raise RecoveryError('Run this local recovery tool inside Linux/WSL as root.')
    if not NAME.fullmatch(args.name):
        raise RecoveryError('Backup names must be short letters, digits, underscores, or hyphens.')
    if args.action == 'backup':
        if not PROJECT.fullmatch(args.project):
            raise RecoveryError('Invalid source project name.')
        result = backup(args.project, args.name)
    elif args.action == 'restore':
        if not RESTORE_PROJECT.fullmatch(args.project):
            raise RecoveryError('New restore project names must start with openrmm-restored-.')
        result = restore(args.name, args.project, args.revocations, args.admin_port, args.agent_port)
    else:
        _, first = checked_backup(BACKUPS, args.name)
        _, second = checked_backup(KEYS, args.name)
        if first['set_id'] != second['set_id'] or first['instance'] != second['instance']:
            raise RecoveryError('Data and key backups are from different sets.')
        result = dict(verified=True, schema_version=first['instance']['schema_version'])
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except (RecoveryError, OSError, ValueError, KeyError, sqlite3.Error, subprocess.SubprocessError) as failure:
        # Docker/SQLite exception text can contain paths or untrusted data. Keep
        # CLI errors fixed; private backup contents never enter diagnostics.
        if isinstance(failure, RecoveryError):
            print(str(failure), file=sys.stderr)
        else:
            import traceback
            location = traceback.extract_tb(failure.__traceback__)[-1]
            print('Recovery failure: ' + type(failure).__name__ + ' at line ' + str(location.lineno), file=sys.stderr)
        print('Existing deployments were not replaced. Inspect prerequisites and private staging paths.', file=sys.stderr)
        sys.exit(1)
