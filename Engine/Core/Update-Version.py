#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import json
import os
import subprocess
import re
from datetime import datetime, timezone

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
root_version_file = os.path.join(ROOT_DIR, 'version.json')
data_version_file = os.path.join(ROOT_DIR, 'Data', 'version.json')
version_file = root_version_file if os.path.exists(root_version_file) else data_version_file
readme_file = os.path.join(ROOT_DIR, 'README.md')
contributing_file = os.path.join(ROOT_DIR, 'CONTRIBUTING.md')
security_file = os.path.join(ROOT_DIR, '.github', 'SECURITY.md')

ALLOWED_CHANNELS = ['DEV', 'INTERNAL', 'PILOT', 'PRODUCTION']

is_check = '--check' in sys.argv
is_dry_run = '--dry-run' in sys.argv

if not os.path.exists(version_file):
    vdata = {
        'version': '2.5.10',
        'release': 'v2.5.10-PILOT',
        'build': datetime.now().strftime('%Y.%m.%d.10'),
        'channel': 'pilot',
        'build_number': 10,
        'last_updated': datetime.now().strftime('%Y-%m-%dT%H:%M:%S+03:00'),
        'environment': 'pilot',
        'productionReady': False,
        'agent_name': 'CloudShield DevSecOps Autonomous Agent',
        'changelog': []
    }
else:
    with open(version_file, 'r', encoding='utf-8') as f:
        vdata = json.load(f)

current_ver = vdata.get('version', '2.5.10')
channel_in = os.environ.get('CLOUDSHIELD_RELEASE_CHANNEL', vdata.get('channel', 'pilot')).upper()
if channel_in not in ALLOWED_CHANNELS:
    channel_in = 'PILOT'
channel_normalized = channel_in.lower()

if is_check:
    payload = {
        'version': current_ver,
        'release': vdata.get('release', f'v{current_ver}-{channel_in}'),
        'build': vdata.get('build', '2026.09.10.10'),
        'channel': channel_normalized,
        'summary': 'version manifest check',
        'success': True
    }
    print(json.dumps(payload, ensure_ascii=False))
    sys.exit(0)

parts = current_ver.split('.')
try:
    major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
    patch += 1
    new_ver = f'{major}.{minor}.{patch}'
except Exception:
    new_ver = '2.5.11'

today_str = datetime.now().strftime('%Y.%m.%d')
current_build = vdata.get('build', '')
if current_build.startswith(today_str):
    try:
        build_seq = int(current_build.split('.')[-1]) + 1
    except Exception:
        build_seq = 1
else:
    build_seq = 1

new_build = f'{today_str}.{build_seq}'
new_release = f'v{new_ver}-{channel_in}'
now_iso = datetime.now().strftime('%Y-%m-%dT%H:%M:%S+03:00')

p = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True, cwd=ROOT_DIR)
changed_lines = [l.strip() for l in p.stdout.splitlines() if l.strip() and not l.endswith('version.json') and 'README.md' not in l]
changed_files = [l.split()[-1] for l in changed_lines]

summary_args = [a for a in sys.argv[1:] if not a.startswith('--')]
summary = summary_args[0] if summary_args else 'feat(agent): autonomous update and synchronization'

if not is_dry_run:
    vdata['version'] = new_ver
    vdata['release'] = new_release
    vdata['build'] = new_build
    vdata['channel'] = channel_normalized
    vdata['build_number'] = vdata.get('build_number', 1) + 1
    vdata['last_updated'] = now_iso
    if channel_normalized == 'production':
        vdata['productionReady'] = True
        vdata['environment'] = 'production'
    else:
        vdata['productionReady'] = False
        vdata['environment'] = channel_normalized

    changelog_entry = {
        'version': new_ver,
        'release': new_release,
        'build': new_build,
        'timestamp': now_iso,
        'commit': 'auto',
        'author': 'CloudShield Autonomous Agent',
        'summary': summary,
        'details': [f'Güncellenen dosya: {f}' for f in changed_files[:6]] if changed_files else ['Raporlama ve güvenlik motoru otonom senkronizasyonu']
    }

    vdata.setdefault('changelog', []).insert(0, changelog_entry)
    vdata['changelog'] = vdata['changelog'][:30]

    for vf in [root_version_file, data_version_file]:
        try:
            os.makedirs(os.path.dirname(vf), exist_ok=True)
            with open(vf, 'w', encoding='utf-8') as f:
                json.dump(vdata, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f'[WARN] Error saving {vf}: {e}', file=sys.stderr)

    if os.path.exists(readme_file):
        with open(readme_file, 'r', encoding='utf-8') as f:
            readme_content = f.read()

        readme_content = re.sub(r'badge/Release-v[\d\.]+-[A-Za-z]+-[a-zA-Z]+\.svg', f'badge/Release-{new_release}-brightgreen.svg', readme_content)
        readme_content = re.sub(r'releases/tag/v[\d\.]+-[A-Z]+', f'releases/tag/{new_release}', readme_content)
        # Fix: was using \v (vertical tab) instead of backtick — that never matched
        readme_content = re.sub(r'(\*\*Active Release:\*\*\s*)`v[\d\.]+-[A-Z]+-PILOT`', r'\g<1>' + f'`{new_release}`', readme_content)
        readme_content = re.sub(r'(\*\*Active Release:\*\*\s*)`v[\d\.]+-[A-Z]+`', r'\g<1>' + f'`{new_release}`', readme_content)

        recent_rows = []
        for item in vdata.get('changelog', [])[:5]:
            rel = item.get('release', '')
            bld = item.get('build', '')
            ts = item.get('timestamp', '')[:10]
            sm = item.get('summary', '').replace('|', '-')
            recent_rows.append(f'| **{rel}** | {bld} | {ts} | {sm} |')

        changelog_table = '\n'.join([
            '## 🚀 Recent Releases & Autonomous Changelog',
            '',
            '| Release Tag | Build | Date | Autonomous Agent Summary |',
            '| :--- | :--- | :--- | :--- |',
            *recent_rows,
            ''
        ])

        if '## 🚀 Recent Releases & Autonomous Changelog' in readme_content:
            readme_content = re.sub(
                r'## 🚀 Recent Releases & Autonomous Changelog[\s\S]*?(?=\n## |\n---|$)',
                changelog_table.strip(),
                readme_content
            )
        with open(readme_file, 'w', encoding='utf-8') as f:
            f.write(readme_content)

output_payload = {
    'version': new_ver,
    'release': new_release,
    'build': new_build,
    'channel': channel_normalized,
    'summary': summary,
    'success': True
}
print(json.dumps(output_payload, ensure_ascii=False))
