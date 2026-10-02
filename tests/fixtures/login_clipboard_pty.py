"""Exercise the packaged SSH proxy through a real PTY; never touch a real clipboard."""
import base64
import errno
import fcntl
import os
import pathlib
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time


def auth_url(state):
    return (
        "https://claude.com/cai/oauth/authorize?client_id=fixture&response_type=code"
        "&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback"
        "&code_challenge=" + "a" * 43 + "&code_challenge_method=S256&state=" + state
    )


# This replaces only the SSH executable; its stdin must remain the real terminal.
FAKE_SSH = r'''#!/usr/bin/env python3
import base64, os, sys, time, tty
assert os.isatty(0)
assert os.get_terminal_size(0).columns == 80
tty.setraw(0)
def paint(state):
    url = os.environ['FIXTURE_URL_' + state]
    width = os.get_terminal_size(0).columns
    frame = "\x1b[2J\x1b[HBrowser didn't open? Use the url below to sign in\r\n\r\n"
    frame += "\x1b[4m" + "\r\n".join(url[i:i+width] for i in range(0, len(url), width))
    frame += "\x1b[0m\r\n\r\nPaste code here if prompted > "
    for i in range(0, len(frame), 11):
        sys.stdout.write(frame[i:i+11]); sys.stdout.flush()
paint('ONE')
assert os.read(0, 1) == b'a'
paint('ONE')
time.sleep(.4)
sys.stdout.write('\r\nREDRAW_DONE\r\n'); sys.stdout.flush()
assert os.read(0, 1) == b'b'
assert os.get_terminal_size(0).columns == 100
paint('TWO')
assert os.read(0, 1) == b'c'
sys.stdout.write('\x1b]52;c;?\x07'); sys.stdout.flush()
copy = '\x1b]52;c;' + base64.b64encode('选中的 Claude 回复\n  code\n'.encode()).decode() + '\x1b\\'
for byte in copy:
    sys.stdout.write(byte); sys.stdout.flush()
assert os.read(0, 1) == b'd'
sys.stdout.write('\r\nINPUT_OK\r\n'); sys.stdout.flush()
sys.exit(23)
'''


def main(binary):
    with tempfile.TemporaryDirectory(prefix="agent-remote-clipboard-") as directory:
        root = pathlib.Path(directory)
        fake = root / "ssh-fixture"
        fake.write_text(FAKE_SSH)
        fake.chmod(0o700)
        env = dict(os.environ, AGENT_REMOTE_HOME=str(root / "home"),
                   AGENT_REMOTE_SYSTEM_SSH=str(fake), TERM="xterm-256color",
                   SSH_CONNECTION="fixture remote", FIXTURE_URL_ONE=auth_url("one"),
                   FIXTURE_URL_TWO=auth_url("two"))
        for name in ("TMUX", "AGENT_REMOTE_LOGIN_CLIPBOARD_ACTIVE", "AGENT_REMOTE_LOGIN_CLIPBOARD", "AGENT_REMOTE_CLIPBOARD"):
            env.pop(name, None)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 48, 80, 0, 0))
        child = subprocess.Popen([binary, "-tt", "fixture@host", "agent-remote-attach",
                                  "--binding", "account-fixture"],
                                 stdin=slave, stdout=slave, stderr=slave, env=env)
        os.close(slave)
        output = bytearray()

        def until(marker):
            deadline = time.monotonic() + 10
            while marker not in output:
                assert time.monotonic() < deadline, "PTY output deadline exceeded"
                if not select.select([master], [], [], .1)[0]:
                    continue
                try:
                    chunk = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        raise AssertionError("proxy ended before expected output") from exc
                    raise
                assert chunk, "proxy closed output early"
                output.extend(chunk)

        try:
            first = b"\x1b]52;c;" + base64.b64encode(auth_url("one").encode()) + b"\x07"
            second = b"\x1b]52;c;" + base64.b64encode(auth_url("two").encode()) + b"\x07"
            until(first)
            os.write(master, b'a')
            until(b'REDRAW_DONE')
            assert output.count(first) == 1, "redraw copied the same URL again"
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 48, 100, 0, 0))
            os.write(master, b'b')
            until(second)
            os.write(master, b'c')
            selected = b"\x1b]52;c;" + base64.b64encode('选中的 Claude 回复\n  code\n'.encode()) + b"\x07"
            until(selected)
            assert b"\x1b]52;c;?\x07" not in output, "clipboard read request reached terminal"
            assert output.count(selected) == 1, "selection copied more than once"
            os.write(master, b'd')
            until(b'INPUT_OK')
            assert child.wait(timeout=5) == 23, "SSH exit status was changed"
            assert output.count(first) == output.count(second) == 1
            assert b"Claude login links copy automatically" in output
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
            os.close(master)
        assert not any(b"oauth/authorize" in path.read_bytes()
                       for path in (root / "home").rglob("*") if path.is_file())


if __name__ == "__main__":
    main(sys.argv[1])
