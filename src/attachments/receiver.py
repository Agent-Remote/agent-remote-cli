"""Owned attachment channel inside the existing user SSH sandbox."""
import hashlib
import errno
import json
import os
import re
import shutil
import signal
import stat
import sys
import tempfile
import zipfile

LIMIT = 256 * 1024 * 1024
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
TRAVERSE = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW


def interrupted(signum, frame):
    raise InterruptedError("attachment connection closed")


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGHUP, interrupted)


def open_account(path):
    if not path.startswith("/") or any(p in ("", ".", "..") for p in path[1:].split("/")):
        raise ValueError("invalid account directory")
    fd = os.open("/", TRAVERSE)
    try:
        for part in path[1:].split("/"):
            child = os.open(part, TRAVERSE, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def directory(parent, name, create=True):
    if create:
        try:
            os.mkdir(name, 0o770, dir_fd=parent)
        except FileExistsError:
            pass
    return os.open(name, DIRECTORY, dir_fd=parent)


def remove(parent, name):
    # fd-relative traversal also supports the Python 3.10 shipped by older Nodes.
    try:
        mode = os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(mode):
        os.unlink(name, dir_fd=parent)
        return
    fd = os.open(name, DIRECTORY, dir_fd=parent)
    try:
        for child in os.listdir(fd):
            remove(fd, child)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent)


def extract(archive, parent):
    total = 0
    seen = set()
    with zipfile.ZipFile(archive) as package:
        entries = package.infolist()
        if len(entries) > 10000:
            raise ValueError("too many attachment entries")
        for entry in entries:
            name = entry.filename.rstrip("/")
            parts = name.split("/")
            if not name or len(parts) > 65 or name in seen or any(p in ("", ".", "..") for p in parts):
                raise ValueError("invalid attachment path")
            if any(ord(c) < 32 for c in name) or "\\" in name or len(name.encode()) > 4096:
                raise ValueError("invalid attachment name")
            if entry.compress_type != zipfile.ZIP_STORED:
                raise ValueError("unsupported archive compression")
            kind = (entry.external_attr >> 16) & 0o170000
            if kind not in (0, 0o100000, 0o040000):
                raise ValueError("attachment links and special files are forbidden")
            seen.add(name)
            total += entry.file_size
            if total > LIMIT:
                raise ValueError("attachment size limit exceeded")
            current = os.dup(parent)
            try:
                for part in parts[:-1]:
                    child = directory(current, part)
                    os.close(current)
                    current = child
                if entry.is_dir():
                    os.close(directory(current, parts[-1]))
                else:
                    mode = 0o660 | ((entry.external_attr >> 16) & 0o110)
                    fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=current)
                    with os.fdopen(fd, "wb") as target, package.open(entry) as source:
                        shutil.copyfileobj(source, target, 64 * 1024)
            finally:
                os.close(current)


def operation(request):
    if request.get("version") != 1 or request.get("operation") not in ("upload", "cleanup"):
        raise ValueError("unsupported attachment operation")
    for key in ("session", "lease"):
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", request[key]):
            raise ValueError("invalid attachment identity")
    account = open_account(request["account"])
    namespace = session = lease = None
    try:
        cleanup = request["operation"] == "cleanup"
        try:
            namespace = directory(account, ".agent-remote-attachments", not cleanup)
            session = directory(namespace, request["session"], not cleanup)
        except FileNotFoundError:
            if not cleanup:
                raise
            return
        if request["operation"] == "cleanup":
            remove(session, request["lease"])
            for parent, name in ((namespace, request["session"]), (account, ".agent-remote-attachments")):
                try:
                    os.rmdir(name, dir_fd=parent)
                except OSError as error:
                    if error.errno not in (errno.ENOTEMPTY, errno.ENOENT):
                        raise
        else:
            size = request["size"]
            if not isinstance(size, int) or not 0 < size <= LIMIT + 8 * 1024 * 1024:
                raise ValueError("invalid attachment archive size")
            batch = request["batch"]
            if not re.fullmatch(r"[a-f0-9]{32}", batch):
                raise ValueError("invalid attachment batch")
            lease = directory(session, request["lease"])
            staging = ".partial-" + batch
            os.mkdir(staging, 0o770, dir_fd=lease)
            staging_fd = os.open(staging, DIRECTORY, dir_fd=lease)
            try:
                # The anonymous archive cannot outlive this SSH process.
                with tempfile.TemporaryFile() as archive:
                    digest = hashlib.sha256()
                    remaining = size
                    while remaining:
                        chunk = sys.stdin.buffer.read(min(65536, remaining))
                        if not chunk:
                            raise EOFError("attachment upload interrupted")
                        archive.write(chunk)
                        digest.update(chunk)
                        remaining -= len(chunk)
                    if digest.hexdigest() != request["sha256"]:
                        raise ValueError("attachment checksum mismatch")
                    archive.seek(0)
                    extract(archive, staging_fd)
                os.rename(staging, batch, src_dir_fd=lease, dst_dir_fd=lease)
            finally:
                os.close(staging_fd)
                remove(lease, staging)
    finally:
        for fd in (lease, session, namespace, account):
            if fd is not None:
                os.close(fd)


def main():
    identity = None
    try:
        while True:
            line = sys.stdin.buffer.readline(16385)
            if not line:
                break
            if len(line) > 16384:
                raise ValueError("attachment header too large")
            request = json.loads(line)
            current = tuple(request.get(key) for key in ("account", "session", "lease"))
            if identity is not None and current != identity:
                raise ValueError("attachment channel identity changed")
            identity = current
            operation(request)
            print(json.dumps({"version": 1, "ok": True}), flush=True)
            if request["operation"] == "cleanup":
                identity = None
                break
    finally:
        # EOF, broken SSH, and termination clean this channel's files, including
        # successfully acknowledged batches. A local receipt covers hard crashes.
        if identity is not None:
            account, session, lease = identity
            operation(dict(version=1, operation="cleanup", account=account, session=session, lease=lease))


try:
    main()
except Exception as error:
    # Never echo attachment names, contents, or remote filesystem state.
    print(json.dumps({"version": 1, "ok": False, "error": type(error).__name__, "errno": getattr(error, "errno", None)}), flush=True)
    sys.exit(1)
