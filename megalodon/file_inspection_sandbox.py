"""Linux-only, closed executable-inspection process boundary.

The target is data on a sealed non-executable memfd. No arbitrary command or
mount is selected by an HTTP request. Resource limits alone are not isolation.
"""
from __future__ import annotations

import ctypes
import errno
import fcntl
import os
from pathlib import Path
import resource
import selectors
import signal
import stat
import subprocess
import sys
import sysconfig
import time
import secrets

MAX_OUTPUT = 65536
MEMORY = 512 * 1024 * 1024
BWRAP = '/usr/bin/bwrap'
SYSTEM_LIBS = Path('/usr/lib/x86_64-linux-gnu')


class SandboxUnavailable(ValueError):
    pass


def sealed_input():
    # MFD_NOEXEC_SEAL / F_SEAL_EXEC require Linux 6.3+. Never downgrade this
    # admission on an older kernel. No raw bytes intentionally go to disk.
    fd = os.memfd_create('megalodon-inspection', 0x0001 | 0x0002 | 0x0008)
    try:
        os.fchmod(fd, 0o400)
    except BaseException:
        os.close(fd)
        raise
    return fd


def seal(fd):
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0020)
    os.lseek(fd, 0, os.SEEK_SET)


def _filter(*, threads=False):
    """libseccomp compiles native-architecture rules, not request-supplied BPF."""
    api = ctypes.CDLL(str(SYSTEM_LIBS / 'libseccomp.so.2'), use_errno=True)
    api.seccomp_init.argtypes = [ctypes.c_uint32]
    api.seccomp_init.restype = ctypes.c_void_p
    api.seccomp_release.argtypes = [ctypes.c_void_p]
    api.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    api.seccomp_syscall_resolve_name.restype = ctypes.c_int
    api.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    api.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]

    class Comparison(ctypes.Structure):
        _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_uint),
                    ('datum_a', ctypes.c_uint64), ('datum_b', ctypes.c_uint64)]
    api.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                         ctypes.c_uint, ctypes.POINTER(Comparison)]
    context = api.seccomp_init(0x7fff0000)
    if not context:
        raise SandboxUnavailable('Inspection filter unavailable.')
    fd = None
    denied = ('socket', 'socketpair', 'connect', 'bind', 'listen', 'accept', 'accept4',
              'fork', 'vfork', 'execveat', 'setsid', 'setpgid', 'mount', 'umount2',
              'pivot_root', 'chroot', 'unshare', 'setns', 'ptrace', 'process_vm_readv',
              'process_vm_writev', 'bpf', 'perf_event_open', 'keyctl', 'add_key', 'request_key',
              'open_by_handle_at', 'userfaultfd', 'io_uring_setup', 'memfd_create',
              'mknod', 'mknodat', 'chmod', 'fchmod', 'fchmodat')
    try:
        fd = os.memfd_create('megalodon-inspection-filter', os.MFD_CLOEXEC)
        for name in denied:
            number = api.seccomp_syscall_resolve_name(name.encode())
            if number < 0 or api.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0):
                raise SandboxUnavailable('Inspection filter unavailable.')
        # Only DIE needs Qt threads, and its scope independently caps tasks.
        # LIEF cannot create threads or processes. clone3 has an indirect
        # argument structure; ENOSYS permits libc's bounded Qt clone fallback.
        clone3 = api.seccomp_syscall_resolve_name(b'clone3')
        clone = api.seccomp_syscall_resolve_name(b'clone')
        cmp = Comparison(0, 7, 0x00010000, 0)  # MASKED_EQ: CLONE_THREAD absent
        if (clone3 < 0 or clone < 0
                or api.seccomp_rule_add(context, 0x00050000 | errno.ENOSYS, clone3, 0)):
            raise SandboxUnavailable('Inspection filter unavailable.')
        added = (api.seccomp_rule_add_array(context, 0x00050000 | errno.EPERM, clone, 1, ctypes.byref(cmp))
                 if threads else api.seccomp_rule_add(context, 0x00050000 | errno.EPERM, clone, 0))
        if added or api.seccomp_export_bpf(context, fd):
            raise SandboxUnavailable('Inspection filter unavailable.')
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise
    finally:
        api.seccomp_release(context)


def supported():
    if (sys.platform != 'linux' or os.uname().machine != 'x86_64'
            or os.getuid() == 0 or os.geteuid() == 0 or sys.version_info[:2] not in ((3, 11), (3, 12))):
        return False
    try:
        family, version = os.confstr('CS_GNU_LIBC_VERSION').split()
        return family == 'glibc' and tuple(int(part) for part in version.split('.')[:2]) >= (2, 38)
    except (AttributeError, OSError, ValueError, TypeError):
        return False


def command(runtime, input_fd, filter_fd, tool, *, probe=None):
    """Only compiled workers, fixed libraries, and the selected FD are mounted."""
    if not supported():
        raise SandboxUnavailable('File inspection requires a supported non-root Linux runtime.')
    python = Path(sys.executable).resolve()
    stdlib = Path(sysconfig.get_path('stdlib')).resolve()
    for path in (Path(BWRAP), python, stdlib, SYSTEM_LIBS):
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise SandboxUnavailable('Inspection system prerequisite is unsafe.')
    package = Path(__file__).parent
    argv = [BWRAP, '--unshare-all', '--unshare-user', '--disable-userns', '--assert-userns-disabled',
            '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
            '--ro-bind', str(SYSTEM_LIBS), str(SYSTEM_LIBS), '--symlink', 'usr/lib', '/lib',
            '--dir', '/lib64', '--symlink', str(SYSTEM_LIBS / 'ld-linux-x86-64.so.2'), '/lib64/ld-linux-x86-64.so.2',
            '--ro-bind', str(python), str(python), '--ro-bind', str(stdlib), str(stdlib),
            '--ro-bind', str(runtime), '/runtime',
            '--ro-bind', str(package / 'file_inspection_worker.py'), '/worker/file_inspection_worker.py',
            '--ro-bind', str(package / 'file_inspection_contract.py'), '/worker/file_inspection_contract.py',
            '--perms', '0400', '--ro-bind-data', str(input_fd), '/input/program',
            '--proc', '/proc', '--dev', '/dev', '--size', '1048576', '--tmpfs', '/tmp',
            '--dir', '/empty', '--clearenv', '--setenv', 'HOME', '/tmp',
            '--setenv', 'LC_ALL', 'C', '--setenv', 'LD_LIBRARY_PATH', '/runtime/lib',
            '--setenv', 'PYTHONDONTWRITEBYTECODE', '1', '--chdir', '/empty',
            '--seccomp', str(filter_fd), '--']
    if probe is not None:
        # This is a compiled self-test; no caller-controlled Python is accepted.
        if probe != 'confinement':
            raise ValueError('Unsupported confinement check.')
        argv += [str(python), '-I', '-c', PROBE]
    elif tool == 'lief':
        argv += [str(python), '-I', '/worker/file_inspection_worker.py']
    elif tool == 'die':
        argv += ['/runtime/die/diec', '--json', '--database', '/runtime/die/db',
                 '--extradatabase', '/empty', '--customdatabase', '/empty', '/input/program']
    else:
        raise ValueError('Unsupported inspection adapter.')
    return argv


PROBE = r'''
import os, socket, json
checks={}
for name,action in [('network',lambda:socket.socket()),('fork',os.fork),
                    ('host_read',lambda:open('/etc/passwd','rb')),
                    ('host_write',lambda:open('/runtime/inspection-write-test','wb')),
                    ('execute_input',lambda:os.execv('/input/program',['/input/program']))]:
    try: action(); checks[name]=False
    except OSError: checks[name]=True
print(json.dumps(checks))
'''


def run(runtime, fd, tool, *, deadline, cancelled, probe=None):
    filter_fd = None
    process = None
    try:
        # Filter admission can fail before a child exists. Return this adapter's
        # unavailable state so an earlier completed adapter keeps its evidence.
        filter_fd = _filter(threads=tool == 'die' and probe is None)
        argv = command(runtime, fd, filter_fd, tool, probe=probe)
        # Limits and parent-death supervision live in a fresh single-threaded
        # helper, never preexec_fn in the multithreaded HUD.
        launch = [sys.executable, '-I', str(Path(__file__).resolve()), str(os.getpid()), *argv]
        if tool == 'die' and probe is None:
            launch = ['/usr/bin/systemd-run', '--user', '--scope', '--quiet', '--collect',
                      '--unit=megalodon-inspection-' + secrets.token_hex(8),
                      '--property=MemoryMax=512M', '--property=MemorySwapMax=0',
                      '--property=TasksMax=32', *launch]
        os.lseek(fd, 0, os.SEEK_SET)
        process = subprocess.Popen(launch,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   pass_fds=(fd, filter_fd), start_new_session=True,
                                   env={'PATH': '/usr/bin', 'LC_ALL': 'C',
                                        'XDG_RUNTIME_DIR': f'/run/user/{os.geteuid()}',
                                        'DBUS_SESSION_BUS_ADDRESS': f'unix:path=/run/user/{os.geteuid()}/bus'})
        raw = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                if cancelled.is_set():
                    return 'cancelled', b''
                if time.monotonic() >= deadline:
                    return 'timed_out', b''
                for key, _ in selector.select(.05):
                    chunk = os.read(key.fd, 8192)
                    if chunk:
                        raw.extend(chunk)
                        if len(raw) > MAX_OUTPUT:
                            return 'failed', b''
                    else:
                        selector.unregister(key.fileobj)
        return ('completed', bytes(raw)) if process.wait() == 0 else ('failed', b'')
    except (OSError, ValueError, ctypes.ArgumentError):
        return 'unavailable', b''
    finally:
        if filter_fd is not None:
            os.close(filter_fd)
        if process is not None:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
            process.stdout.close()


def _launch():
    parent = int(sys.argv[1])
    api = ctypes.CDLL(None, use_errno=True)
    # Keep this supervisor outside credential/namespace transitions, which can
    # reset PDEATHSIG. On controller death kill our dedicated process group,
    # including the outer bwrap helper and its PID-namespace reaper.
    if os.getpgrp() != os.getpid():
        raise SystemExit(2)
    def terminate(_number, _frame):
        os.killpg(os.getpgrp(), signal.SIGKILL)
    signal.signal(signal.SIGTERM, terminate)
    if api.prctl(1, signal.SIGTERM, 0, 0, 0) or os.getppid() != parent or api.prctl(38, 1, 0, 0, 0):
        raise SystemExit(2)
    memory = MEMORY
    if '/runtime/die/diec' in sys.argv[2:]:
        # QtScript reserves 2 GiB of virtual space. The operator explicitly
        # approved 2.5 GiB AS only with this independently verified cgroup cap.
        group = Path('/proc/self/cgroup').read_text().strip().removeprefix('0::')
        if not group.startswith('/') or '..' in Path(group).parts or '\n' in group:
            raise SystemExit(2)
        base = Path('/sys/fs/cgroup') / group.lstrip('/')
        if (int((base / 'memory.max').read_text()) != MEMORY
                or int((base / 'memory.swap.max').read_text()) != 0
                or not 1 <= int((base / 'pids.max').read_text()) <= 32):
            raise SystemExit(2)
        memory = 2560 * 1024 * 1024
    for name, limit in ((resource.RLIMIT_AS, memory), (resource.RLIMIT_CPU, 15),
                        (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 64 * 1024 * 1024), (resource.RLIMIT_NOFILE, 64)):
        resource.setrlimit(name, (limit, limit))
    argv = sys.argv[2:]
    if not argv or argv[0] != BWRAP:
        raise SystemExit(2)
    input_fd = int(argv[argv.index('--ro-bind-data') + 1])
    filter_fd = int(argv[argv.index('--seccomp') + 1])
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                               pass_fds=(input_fd, filter_fd),
                               env={'PATH': '/usr/bin', 'LC_ALL': 'C'})
    raise SystemExit(process.wait())


if __name__ == '__main__':
    _launch()
