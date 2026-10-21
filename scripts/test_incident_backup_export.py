from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SOURCE = (Path(__file__).resolve().parents[1] / "ansible/roles/incident_backup/templates"
          / "incident-backup-export.sh.j2")


class IncidentBackupExportTests(unittest.TestCase):
    def run_export(self, *, timer_active: bool, tar_failure: bool = False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            systemctl = root / "systemctl"
            systemctl.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$SYSTEMCTL_LOG\"\n"
                "if [ \"$1\" = is-active ]; then [ \"$TIMER_ACTIVE\" = 1 ]; fi\n"
            )
            systemctl.chmod(0o755)
            tar = root / "tar"
            tar.write_text("#!/bin/sh\n[ \"$TAR_FAILURE\" != 1 ]\n")
            tar.chmod(0o755)
            log = root / "systemctl.log"
            environment = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                           "SYSTEMCTL_LOG": str(log),
                           "TIMER_ACTIVE": "1" if timer_active else "0",
                           "TAR_FAILURE": "1" if tar_failure else "0"}
            result = subprocess.run(["bash", str(SOURCE)], env=environment,
                                    capture_output=True, text=True)
            return result, log.read_text().splitlines()

    def test_active_helix_timer_is_restored_after_success_and_failure(self):
        for tar_failure in (False, True):
            with self.subTest(tar_failure=tar_failure):
                result, calls = self.run_export(timer_active=True, tar_failure=tar_failure)
                self.assertEqual(result.returncode != 0, tar_failure)
                self.assertIn("start homelab-incidents-helix-sync.timer", calls)

    def test_inactive_helix_timer_stays_inactive(self):
        result, calls = self.run_export(timer_active=False)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("start homelab-incidents-helix-sync.timer", calls)


if __name__ == "__main__":
    unittest.main()
