"""Exercise native binding cancellation through the real PTY bridge, offline."""
import os
import pty
import signal
import subprocess
import sys
import time
from pathlib import Path

master, slave = pty.openpty()
child = subprocess.Popen(sys.argv[1:], stdin=slave, stdout=slave, stderr=slave)
os.close(slave)
ssh_pid = None
ssh_gone = False
try:
    capture = Path(os.environ["TEST_BINDING_SSH_ARGS"])
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if capture.exists() and capture.read_text().strip():
            ssh_pid = int(capture.read_text().strip())
            break
        if child.poll() is not None:
            raise AssertionError("CLI exited before native SSH started")
        time.sleep(0.01)
    assert ssh_pid is not None, "native SSH did not start"
    os.kill(child.pid, signal.SIGTERM)
    assert child.wait(timeout=5) != 0, "canceled CLI reported success"
    deadline = time.monotonic() + 3
    while True:
        try:
            os.kill(ssh_pid, 0)
        except ProcessLookupError:
            ssh_gone = True
            break
        assert time.monotonic() < deadline, "PTY SSH child survived cancellation"
        time.sleep(0.01)
finally:
    if child.poll() is None:
        child.kill()
        child.wait(timeout=5)
    if ssh_pid is not None and not ssh_gone:
        try:
            os.kill(ssh_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    os.close(master)
