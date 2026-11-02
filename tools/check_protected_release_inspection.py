"""Ubuntu acceptance: a real same-user, non-dumpable process holds, then releases a file."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from megalodon.release_inspection import protected_process_holds


def main():
    if sys.platform != 'linux' or os.getuid() != os.geteuid() or not os.getuid():
        raise RuntimeError('Run as an ordinary Linux user')
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        release = root/'releases'/'old'
        release.mkdir(parents=True)
        item = release/'module'
        item.touch()
        # The path is passed by pipe: the process no longer references the tree
        # after closing the file. No root file creation, settings or service actions.
        child = subprocess.Popen([sys.executable,'-I','-B','-c',"""
import ctypes,sys
with open(sys.stdin.readline().strip(),'rb') as held:
    if ctypes.CDLL(None).prctl(4,0,0,0,0)!=0:raise SystemExit(2)
    print('held',flush=True)
    sys.stdin.readline()
print('closed',flush=True)
sys.stdin.readline()
"""],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            child.stdin.write(str(item)+'\n');child.stdin.flush()
            if child.stdout.readline() != 'held\n':raise RuntimeError('Could not stage protected process')
            proc = Path('/proc')/str(child.pid)
            try:list((proc/'fd').iterdir())
            except PermissionError:pass
            else:raise RuntimeError('The unprivileged probe must be denied')
            paths = SimpleNamespace(current=root/'current')
            if not protected_process_holds(proc,paths,release):raise RuntimeError('Missed a live holder')
            child.stdin.write('\n');child.stdin.flush()
            if child.stdout.readline() != 'closed\n':raise RuntimeError('Child did not release file')
            if protected_process_holds(proc,paths,release):raise RuntimeError('Unused release could not be verified')
        finally:
            child.stdin.close()
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:child.kill();child.wait()
            child.stdout.close()
    print('Protected process inspection passed: ordinary access denied; live reference retained; closed reference cleared.')


if __name__ == '__main__':
    main()
