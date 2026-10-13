"""Source changes and metadata substitution must invalidate an exception proof."""
import copy
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('owners', Path(__file__).with_name('check-coverage-owner-contracts.py'))
owners = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owners)


class Contracts(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / 'src').mkdir()
        self.file = self.root / 'src/lib.rs'
        self.file.write_text('closed invariant\n')
        self.contracts = [{'package': 'owner', 'files': {'src/lib.rs': hashlib.sha256(self.file.read_bytes()).hexdigest()}}]
        self.metadata = {'packages': [{'name': 'owner', 'manifest_path': str(self.root / 'Cargo.toml'),
                                      'source': 'git+https://github.com/corbet-foss/owner?branch=main#' + '1' * 40}]}

    def test_accepts_identical_source_on_another_main_revision(self):
        owners.check(self.contracts, self.metadata)
        self.metadata['packages'][0]['source'] = self.metadata['packages'][0]['source'][:-40] + '2' * 40
        owners.check(self.contracts, self.metadata)

    def test_rejects_changed_source(self):
        self.file.write_text('changed invariant\n')
        with self.assertRaises(ValueError):
            owners.check(self.contracts, self.metadata)

    def test_rejects_missing_duplicate_and_foreign_metadata(self):
        package = self.metadata['packages'][0]
        for packages in [[], [package, package], [{**package, 'source': None}],
                         [{**package, 'source': package['source'].replace('branch=main', 'rev=main')}]]:
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                owners.check(self.contracts, {'packages': packages})

    def test_rejects_empty_or_duplicate_contracts(self):
        for contracts in [[], self.contracts * 2, [{'package': 'owner', 'files': {}}]]:
            with self.subTest(contracts=contracts), self.assertRaises(ValueError):
                owners.check(contracts, self.metadata)

    def test_rejects_escaping_or_non_source_paths(self):
        for name in ['../outside.rs', str(self.file), 'Cargo.toml']:
            contracts = copy.deepcopy(self.contracts)
            contracts[0]['files'] = {name: '0' * 64}
            with self.subTest(name=name), self.assertRaises(ValueError):
                owners.check(contracts, self.metadata)

    def test_rejects_missing_and_escaping_symlink_sources(self):
        self.file.unlink()
        with self.assertRaises(OSError):
            owners.check(self.contracts, self.metadata)
        outside = self.root.parent / (self.root.name + '.rs')
        outside.write_text('closed invariant\n')
        self.addCleanup(outside.unlink)
        self.file.symlink_to(outside)
        with self.assertRaises(ValueError):
            owners.check(self.contracts, self.metadata)


if __name__ == '__main__':
    unittest.main()
