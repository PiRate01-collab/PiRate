#!/usr/bin/env python3
"""Package functional MVP source, docs and smoke tests; never installs anything."""
import argparse
import gzip
import hashlib
import io
import json
import re
from pathlib import Path
import tarfile
ROOT=Path(__file__).resolve().parents[1]
VERSION=(ROOT/'VERSION').read_text().strip()
parser=argparse.ArgumentParser(description='Build PiRate functional MVP source archive')
parser.add_argument('--output',default=str(ROOT/'artifacts/releases'/('pirate-'+VERSION+'.tar.gz')))
args=parser.parse_args();output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
# Public source allowlist: no lab, archives, diagnostic evidence or old reports.
selected=[]
for directory in ('gate_core','web','lib'):
    selected.extend(p for p in (ROOT/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc','.pyo'))
selected.extend(ROOT/name for name in ('VERSION','README.md','INSTALL.md','CONFIGURATION.md',
    'TROUBLESHOOTING.md','SECURITY.md','CHANGELOG.md','LICENSE','CONTRIBUTING.md','.gitignore',
    'README.en.md','INSTALL.en.md','RELEASE_NOTES.md',
    '.github/ISSUE_TEMPLATE/bug_report.yml','.github/ISSUE_TEMPLATE/installation_help.yml',
    '.github/ISSUE_TEMPLATE/config.yml','docs/release-0.5.9-beta.1.md','site/index.html',
    'bin/pirate','bin/gate','install.sh','install-pi.sh','tools/install_pi.py','tools/build_mvp_release.py',
    'extra/pirate-ap.service','extra/pirate-lan-block.service','extra/gate-router.service'))
# Portable existing tests only; privileged lab fixtures and evidence are excluded.
selected.extend(ROOT/'tests/unit'/name for name in ('__init__.py','test_core.py',
    'test_connection_engine.py','test_api.py','test_public_candidate.py',
    'test_pi_installer.py','test_management_access.py'))
selected.extend(ROOT/name for name in ('tests/__init__.py','tests/ui/openvpn_import.cjs'))
# Only source files enter recursive selections. Fail closed on accidental state,
# credentials and symlinks instead of silently shipping them.
allowed={'.py','.js','.css','.html','.md','.sh','.service','.svg','.cjs','.yml'}
manifest={}
for path in sorted(set(selected)):
    relative=str(path.relative_to(ROOT))
    if path.is_symlink() or path.resolve()!=path.absolute():
        raise ValueError('Release symlink refused: '+relative)
    if path.suffix not in allowed and relative not in ('VERSION','LICENSE','.gitignore','bin/pirate','bin/gate'):
        raise ValueError('Non-source release member refused: '+relative)
    raw=path.read_bytes()
    if re.search(rb'^-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----$',raw,re.M):
        raise ValueError('Private key refused: '+relative)
    manifest[relative]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),
                        'mode':0o755 if path.stat().st_mode&0o111 else 0o644}
with output.open('xb') as destination:
    with gzip.GzipFile(filename='',mode='wb',fileobj=destination,mtime=0) as compressor:
        with tarfile.open(fileobj=compressor,mode='w|',format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(set(selected)):
                raw=path.read_bytes();member=tarfile.TarInfo('pirate-'+VERSION+'/'+str(path.relative_to(ROOT)))
                member.size=len(raw);member.mode=0o755 if path.stat().st_mode&0o111 else 0o644;member.uid=member.gid=0;member.mtime=0
                archive.addfile(member,io.BytesIO(raw))
            raw=(json.dumps({'schema':1,'version':VERSION,'files':manifest},sort_keys=True,indent=2)+'\n').encode()
            member=tarfile.TarInfo('pirate-'+VERSION+'/RELEASE-MANIFEST.json')
            member.size=len(raw);member.mode=0o644;member.uid=member.gid=0;member.mtime=0
            archive.addfile(member,io.BytesIO(raw))
output.with_suffix(output.suffix+'.sha256').write_text(hashlib.sha256(output.read_bytes()).hexdigest()+'  '+output.name+'\n')
output.with_name('pirate-'+VERSION+'.manifest.json').write_text(json.dumps({'schema':1,'version':VERSION,'files':manifest},sort_keys=True,indent=2)+'\n')
print(str(output))
print(hashlib.sha256(output.read_bytes()).hexdigest())
