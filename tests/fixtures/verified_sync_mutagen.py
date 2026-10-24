#!/usr/bin/env python3
"""Isolated fake daemon and bounded public Mutagen models for verified flush tests."""
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

if sys.argv[1] == "--fixture-daemon":
    root = Path(sys.argv[2])
    lock = (root / "daemon/daemon.lock").open("w")
    fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    endpoint = socket.socket(socket.AF_UNIX)
    endpoint.bind(str(root / "daemon/daemon.sock"))
    (root / "ready").touch()
    while True:
        time.sleep(1)

root = Path(os.environ["MUTAGEN_DATA_DIRECTORY"])
assert os.environ["MUTAGEN_DISABLE_AUTOSTART"] == "1"
args = sys.argv[1:]
with (root / "calls").open("a") as log:
    log.write(json.dumps(args) + "\n")
model = json.loads((root / "model.json").read_text())
if args[:2] == ["sync", "list"]:
    if "json" in args[3]:
        print(json.dumps(model))
    else:
        print(model["identifier"] + " false")
elif args[:2] == ["forward", "list"]:
    pass
elif args[:2] == ["sync", "flush"]:
    assert args == ["sync", "flush", "--", model["identifier"]]
    case = (root / "case").read_text()
    (root / "flushed").touch()
    if case in ("cancel", "timeout"):
        child = subprocess.Popen(["sleep", "120"])
        (root / "child-pid").write_text(str(child.pid))
        time.sleep(120)
    elif case == "replace":
        model["identifier"] = "sync_" + "b" * 43
    elif case == "post-conflict":
        model["conflicts"] = [{"alphaChanges": []}]
    elif case == "post-git-lock":
        git = Path(model["alpha"]["path"]) / ".git"
        git.mkdir(exist_ok=True)
        (git / "index.lock").touch()
    elif case == "config-change":
        (root / "config-path").read_text()
        Path((root / "config-path").read_text()).write_text('server_url = "https://changed.invalid"\nactive_device_id = "changed"\n')
    elif case == "directory-change":
        project = Path(model["alpha"]["path"])
        project.rename(str(project) + "-previous")
        project.mkdir()
    elif case == "flush-fail":
        sys.exit(7)
    (root / "model.json").write_text(json.dumps(model))
else:
    raise AssertionError("unexpected mutation: " + repr(args))
