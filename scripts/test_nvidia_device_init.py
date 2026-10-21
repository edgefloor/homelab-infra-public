import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import verify_nvidia_device_init as probe


class NvidiaProbeGuards(unittest.TestCase):
    def test_non_root_refuses_before_any_command(self):
        with patch.object(probe.platform, 'system', return_value='Linux'), \
                patch.object(probe.os, 'geteuid', return_value=1000), \
                patch.object(probe.subprocess, 'run') as command:
            with self.assertRaisesRegex(RuntimeError, 'locally as root'):
                probe.preflight()
            command.assert_not_called()

    def test_missing_uvm_refuses_before_any_module_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            modules = Path(directory)
            (modules / 'nvidia').mkdir()
            (modules / 'nvidia/initstate').write_text('live\n')
            with patch.object(probe, 'MODULES', modules), \
                    patch.object(probe.platform, 'system', return_value='Linux'), \
                    patch.object(probe.os, 'geteuid', return_value=0), \
                    patch.object(probe.subprocess, 'run') as command:
                with self.assertRaisesRegex(RuntimeError, 'nvidia_uvm must already be loaded'):
                    probe.preflight()
                command.assert_not_called()

    def test_parent_namespace_refuses_before_mounting(self):
        with patch.object(probe.os, 'stat', return_value=SimpleNamespace(st_ino=123)), \
                patch.object(probe.subprocess, 'run') as command:
            with self.assertRaisesRegex(RuntimeError, 'parent namespace'):
                probe.fixture(123)
            command.assert_not_called()

    def test_timeout_kills_the_entire_private_process_group(self):
        with patch.object(probe.subprocess, 'Popen') as launch, \
                patch.object(probe.os, 'killpg') as kill:
            child = launch.return_value
            child.pid = 456
            child.communicate.side_effect = probe.subprocess.TimeoutExpired('fixture', 90)
            with self.assertRaises(probe.subprocess.TimeoutExpired):
                probe.run_fixture(123)
            kill.assert_called_once_with(456, probe.signal.SIGKILL)
            child.wait.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
