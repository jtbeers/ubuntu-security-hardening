import unittest
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hardening import SecurityHardener

class TestSecurityHardener(unittest.TestCase):
    def setUp(self):
        self.hardener = SecurityHardener(dry_run=True, backup_dir="/tmp/test-hardening-backups")

    def test_dry_run_execution(self):
        self.hardener.run_all()
        self.assertTrue(self.hardener.dry_run)

if __name__ == "__main__":
    unittest.main()
