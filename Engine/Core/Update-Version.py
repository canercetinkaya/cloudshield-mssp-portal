#!/usr/bin/env python3
import sys, json, os, subprocess, re
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
version_file = os.path.join(ROOT_DIR, 'Data', 'version.json')
readme_file = os.path.join(ROOT_DIR, 'README.md')
contributing_file = os.path.join(ROOT_DIR, 'CONTRIBUTING.md')
security_file = os.path.join(ROOT_DIR, '.github', 'SECURITY.md')

if not os.path.exists(version_file):
    vdata = {
        'version': '2.5.3',
        'release': 'v2.5.3-LIVE',
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

current_ver = vdata.get('version', '2.5.3')
parts = current_ver.split('.')
try:
    major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
    patch += 1
    new_ver = f'{major}.{minor}.{patch}'
except Exception:
    new_ver = '2.5.4'

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
changed_lines = [l.strip() for l in p.stdout.splitlines() if l.strip() and not l.endswith('version.json') and 'README.md' not in l]
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

# 1. Save Data/version.json
with open(version_file, 'w', encoding='utf-8') as f:
    json.dump(vdata, f, indent=2, ensure_ascii=False)

# 2. Update README.md (Badges, Live Production, Architecture Diagram, Changelog table)
if os.path.exists(readme_file):
    with open(readme_file, 'r', encoding='utf-8') as f:
        readme_content = f.read()

    readme_content = re.sub(r'badge/Release-v[0-9\.]+(-{1,2})LIVE-[a-zA-Z]+\.svg', f'badge/Release-{new_release}--LIVE-brightgreen.svg' if '-' in new_release else f'badge/Release-{new_release}-brightgreen.svg', readme_content)
    readme_content = re.sub(r'releases/tag/v[0-9\.]+(-LIVE)?', f'releases/tag/{new_release}', readme_content)
    readme_content = re.sub(r'\*\*Active Release:\*\* `v[0-9\.]+(-LIVE)?`', f'**Active Release:** `{new_release}`', readme_content)
    readme_content = re.sub(r'Live Release Badge: v[0-9\.]+(-LIVE)?', f'Live Release Badge: {new_release}', readme_content)

    # Build Recent Releases Markdown Table
    recent_rows = []
    for item in vdata.get('changelog', [])[:5]:
        rel = item.get('release', '')
        bld = item.get('build', '')
        ts = item.get('timestamp', '')[:10]
        sm = item.get('summary', '').replace('|', '-')
        recent_rows.append(f'| **{rel}** | `{bld}` | {ts} | {sm} |')

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
    else:
        if '## 📄 License & Governance' in readme_content:
            readme_content = readme_content.replace(
                '## 📄 License & Governance',
                changelog_table + '\n---\n\n## 📄 License & Governance'
            )
        else:
            readme_content += '\n\n' + changelog_table

    with open(readme_file, 'w', encoding='utf-8') as f:
        f.write(readme_content)

# 3. Update CONTRIBUTING.md (Production Branch Version)
if os.path.exists(contributing_file):
    with open(contributing_file, 'r', encoding='utf-8') as f:
        contrib_content = f.read()
    contrib_content = re.sub(r'`v[0-9\.]+(-LIVE)?`', f'`{new_release}`', contrib_content)
    with open(contributing_file, 'w', encoding='utf-8') as f:
        f.write(contrib_content)

# 4. Update .github/SECURITY.md (Supported Versions Table)
if os.path.exists(security_file):
    with open(security_file, 'r', encoding='utf-8') as f:
        sec_content = f.read()
    sec_content = re.sub(
        r'\| \*\*v[0-9\.]+x\*\* \| `v[0-9\.]+(-LIVE)?` \| \*\*Active Production\*\*',
        f'| **v{major}.{minor}.x** | `{new_release}` | **Active Production**',
        sec_content
    )
    with open(security_file, 'w', encoding='utf-8') as f:
        f.write(sec_content)

print(f'{new_release}|{new_build}|{summary}')
