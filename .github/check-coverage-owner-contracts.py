"""Invalidate coverage proofs when the actual resolved owner source changes."""
import hashlib
import json
import re
import sys
from pathlib import Path


def check(contracts, metadata):
    if not contracts or len({entry['package'] for entry in contracts}) != len(contracts):
        raise ValueError('Missing or duplicate owner contracts')
    for entry in contracts:
        name = entry['package']
        packages = [p for p in metadata['packages'] if p['name'] == name]
        if len(packages) != 1:
            raise ValueError(f'Missing or duplicate resolved owner: {name}')
        package = packages[0]
        source = rf'git\+https://github\.com/corbet-foss/{re.escape(name)}\?branch=main#[0-9a-f]{{40}}'
        if not re.fullmatch(source, package.get('source') or ''):
            raise ValueError(f'Owner must resolve from current main: {name}')
        root = Path(package['manifest_path']).resolve().parent
        if not entry['files']:
            raise ValueError(f'Missing owner source inventory: {name}')
        for relative, expected in entry['files'].items():
            relative = Path(relative)
            if relative.is_absolute() or '..' in relative.parts or relative.suffix != '.rs':
                raise ValueError('Invalid owner source path')
            path = (root / relative).resolve()
            path.relative_to(root)
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError(f'Owner coverage proof changed; review {name}/{relative}')


if __name__ == '__main__':
    try:
        check(json.loads(Path('.github/coverage-owner-contracts.json').read_text()),
              json.loads(Path(sys.argv[1]).read_text()))
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise SystemExit(f'Coverage owner contract: {error}')
    print('Resolved owner source matches the documented coverage proofs')
