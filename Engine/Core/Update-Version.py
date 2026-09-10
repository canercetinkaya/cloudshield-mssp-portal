#!/usr/bin/env python3
import sys, json, os, subprocess
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
version_file = os.path.join(ROOT_DIR, 'Data', 'version.json')

if not os.path.exists(version_file):
    vdata = {
        'version': '2.5.1',
        'release': 'v2.5.1-LIVE',
        'build': datetime.now().strftime('%Y.%m.%d.1'),
        'build_number': 1,
        'last_updated': datetime.now().strftime('%Y-%m-%dT%H:%M:%S+03:00'),
        'environment': 'production',
        'agent_name': 'CloudShield DevSecOps Autonomous Agent',
        'changelog': []
    }
else:
    with open(version_file, 'r', encoding='utf-8') as f:
        vdata = json.load(f)

current_ver = vdata.get('version', '2.5.1')
parts = current_ver.split('.')
try:
    major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
    patch += 1
    new_ver = f'{major}.{minor}.{patch}'
except Exception:
    new_ver = '2.5.2'

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
new_release = f'v{new_ver}-LIVE'
now_iso = datetime.now().strftime('%Y-%m-%dT%H:%M:%S+03:00')

# Check git status for changed files
p = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True, cwd=ROOT_DIR)
changed_lines = [l.strip() for l in p.stdout.splitlines() if l.strip() and not l.endswith('version.json')]
changed_files = [l.split()[-1] for l in changed_lines]

summary = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].strip() else 'feat(agent): autonomous update and synchronization'

vdata['version'] = new_ver
vdata['release'] = new_release
vdata['build'] = new_build
vdata['build_number'] = vdata.get('build_number', 1) + 1
vdata['last_updated'] = now_iso

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

with open(version_file, 'w', encoding='utf-8') as f:
    json.dump(vdata, f, indent=2, ensure_ascii=False)

print(f'{new_release}|{new_build}|{summary}')
