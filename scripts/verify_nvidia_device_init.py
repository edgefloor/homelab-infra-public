#!/usr/bin/env python3
"""Verify NVIDIA node creation in a disposable mount namespace on the GPU host."""

import inspect
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys


MODULES = Path('/sys/module')
DEVICES = ('/dev/nvidia0', '/dev/nvidiactl', '/dev/nvidia-uvm', '/dev/nvidia-uvm-tools')


def preflight():
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise RuntimeError('run locally as root on the Linux GPU host')
    # Kernel module state is shared between mount namespaces. Refuse to test
    # until both drivers are already loaded; the probe must not load them.
    for name in ('nvidia', 'nvidia_uvm'):
        state = MODULES / name / 'initstate'
        if not state.is_file() or state.read_text().strip() != 'live':
            raise RuntimeError(f'{name} must already be loaded and live')
    for name in ('unshare', 'mount', 'setpriv', 'nvidia-modprobe'):
        path = Path('/usr/bin') / name
        metadata = path.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022 or not os.access(path, os.X_OK):
            raise RuntimeError(f'{path} must be root-owned, executable and not group/world-writable')


def device_identity():
    identity = {}
    for name in DEVICES:
        info = os.stat(name)
        if not stat.S_ISCHR(info.st_mode):
            raise RuntimeError(f'{name} must already be a host character device')
        identity[name] = (info.st_dev, info.st_ino, info.st_rdev, info.st_mode,
                          info.st_uid, info.st_gid)
    return identity


def fixture(parent_namespace):
    # This function is copied into the child interpreter, never called by the
    # normal parent process. Keep it self-contained and check isolation first.
    import json
    import os
    from pathlib import Path
    import stat
    import subprocess

    if os.stat('/proc/self/ns/mnt').st_ino == parent_namespace:
        raise RuntimeError('refusing to mount over /dev in the parent namespace')
    subprocess.run(['/usr/bin/mount', '--make-rprivate', '/'], check=True, timeout=10)
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        optional = line.split(' - ', 1)[0].split()[6:]
        if any(field.startswith(('shared:', 'master:')) for field in optional):
            raise RuntimeError('mount propagation is not private')
    # nodev prevents opening these fixture nodes as host devices. Node creation
    # and stat still work. All writes occur on this namespace's temporary /dev.
    subprocess.run(['/usr/bin/mount', '-t', 'tmpfs', '-o',
                    'mode=0755,nosuid,noexec,nodev', 'tmpfs', '/dev'], check=True, timeout=10)
    names = ('/dev/nvidia0', '/dev/nvidiactl', '/dev/nvidia-uvm', '/dev/nvidia-uvm-tools')
    if any(Path(name).exists() for name in names):
        raise RuntimeError('fixture /dev is not empty')
    Path('/dev/char').mkdir()  # NVIDIA 580 also creates /dev/char symlinks.

    def invoke(*args):
        # A missing module cannot be loaded even if its state changes after
        # preflight. The fixture still needs CAP_MKNOD to create temporary nodes.
        subprocess.run(['/usr/bin/setpriv', '--bounding-set=-sys_module', '--no-new-privs',
                        '/usr/bin/nvidia-modprobe', *args], check=True, timeout=15)

    invoke('-u')
    if Path('/dev/nvidia-uvm').exists():
        raise RuntimeError('unexpected utility behavior: -u created a device without -c')
    invoke('-c', '0')
    if not Path('/dev/nvidia0').exists() or Path('/dev/nvidiactl').exists():
        raise RuntimeError('unexpected core minor behavior')
    invoke('-c', '0', '-c', '255')
    invoke('-u', '-c', '0')
    if not all(stat.S_ISCHR(os.stat(name).st_mode) for name in names):
        raise RuntimeError('corrected commands did not create all four character devices')
    return {'private_empty_dev': True, 'device_access_disabled': True,
            'uvm_without_minor_creates_nothing': True,
            'core_minor_zero_does_not_create_control': True,
            'explicit_core_and_uvm_minors_create_all_four': True}


def run_fixture(parent_namespace):
    source = inspect.getsource(fixture)
    source += f'\nimport json\nprint(json.dumps(fixture({parent_namespace!r})))\n'
    child = subprocess.Popen(['/usr/bin/unshare', '--mount', '--fork', sys.executable, '-'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        output, errors = child.communicate(source, timeout=90)
    except BaseException:
        # Kill the whole private process group so a timeout/interruption cannot
        # leave a child retaining the temporary mount namespace.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        raise
    if child.returncode:
        raise RuntimeError('isolated fixture failed: ' + errors.strip())
    return json.loads(output)


def main():
    preflight()
    before = device_identity()
    parent_namespace = os.stat('/proc/self/ns/mnt').st_ino
    proof = run_fixture(parent_namespace)
    if device_identity() != before:
        raise RuntimeError('host device identity or permissions changed during the probe')
    version = subprocess.check_output(['/usr/bin/nvidia-modprobe', '--version'], text=True).strip()
    print(json.dumps({'status': 'passed', 'proof': proof,
                      'host_devices_unchanged': True, 'modprobe_version': version}, indent=2))


if __name__ == '__main__':
    main()
