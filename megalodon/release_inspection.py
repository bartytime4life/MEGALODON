"""Fixed read-only Linux helpers for an explicitly requested release-retention check."""
import os
from pathlib import Path
import re
import subprocess

from .local_install import InstallError


def authorize():
    # sudo reads the password from the operator's terminal. The installer never sees it.
    try:
        subprocess.run(['/usr/bin/sudo', '-v'], check=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError('Read-only process inspection was not authorized.') from exc


def _inspect(argv):
    # Never launch a shell, project code or an installer with elevated privileges.
    try:
        return subprocess.run(['/usr/bin/sudo', '-n', '--', *argv], stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=10, cwd='/', env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError('Protected process inspection did not complete. Old release preserved.') from exc


def _contains(path, literal):
    # grep -c emits an explicit zero on a completed negative search. A sudo denial,
    # missing file or unreadable map must never be treated as a negative result.
    result = _inspect(['/usr/bin/grep','-aFc','--',str(literal),str(path)])
    if result.returncode == 1 and result.stdout == b'0\n' and not result.stderr:
        return False
    if result.returncode == 0 and re.fullmatch(rb'[1-9][0-9]*\n', result.stdout) and not result.stderr:
        return True
    raise InstallError('Could not verify a protected process. Old release preserved.')


def _glob_literal(path):
    return re.sub(r'([][?*\\])', r'\\\1', str(path))


def protected_process_holds(process, paths, release):
    """True if an otherwise inaccessible same-user process may use the candidate."""
    if (process.parent != Path('/proc') or not re.fullmatch(r'[1-9][0-9]*',process.name)
            or os.getuid()==0 or os.geteuid()!=os.getuid()):
        raise InstallError('Protected inspection requires an ordinary user and a native process ID.')
    descriptor = os.open(process, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_RDONLY)
    try:
        if os.fstat(descriptor).st_uid != os.getuid():
            return True
        # Pin this specific proc directory across sudo calls (PID exit/reuse cannot
        # redirect it to a new process). Emit only match flags, never fd paths or maps.
        base = Path('/proc') / str(os.getpid()) / 'fd' / str(descriptor)
        return _references_at(base, paths, release)
    finally:
        os.close(descriptor)


def _references_at(base, paths, release):
    normalized = Path(os.path.normpath(release))
    held = _glob_literal(normalized)
    marker = _glob_literal(normalized.parent)+'/*/megalodon'
    # Check cwd/exe too. A missing or unreadable expected link cannot certify absence.
    result = _inspect(['/usr/bin/find','-P',str(base/'cwd'),str(base/'exe'),str(base/'fd'),
                       '-maxdepth','1','!','-type','d','(',
                       '!','-lname','?*','-printf','U','-o',
                       '(','-lname',held,'-o','-lname',held+'/*',')','-printf','H','-o',
                       '-path',_glob_literal(base/'fd')+'/*','-lname',marker,'-printf','M',')'])
    if (result.returncode != 0 or result.stderr or not re.fullmatch(b'[HM]*',result.stdout)):
        raise InstallError('Could not verify protected file references. Old release preserved.')
    if b'H' in result.stdout or _contains(base/'cmdline', release):
        return True
    if normalized != release and _contains(base/'cmdline', normalized):
        return True
    if b'M' not in result.stdout:
        for alias in {paths.current, Path(os.path.normpath(paths.current))}:
            if _contains(base/'cmdline', alias):
                return True
    return _contains(base/'maps', normalized)
