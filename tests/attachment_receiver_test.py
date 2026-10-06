"""Exercise actual receiver subprocesses, including interrupted transfers."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import signal
import select
import subprocess
import sys
import tempfile
import unittest
import zipfile

RECEIVER = Path(__file__).resolve().parents[1] / "src/attachments/receiver.py"


def archive(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as package:
        for name, data in entries:
            package.writestr(name, data)
    return stream.getvalue()


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.account = Path(self.temporary.name).resolve()
        self.root = self.account / ".agent-remote-attachments/session/lease"
        self.channels = {}
        self.addCleanup(self.close_channels)

    def close_channels(self):
        for child in self.channels.values():
            if child.poll() is None:
                child.stdin.close()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            if not child.stdin.closed:
                child.stdin.close()
            child.stdout.close()
            child.stderr.close()
        self.channels.clear()

    def run_request(self, payload=b"", **changes):
        header = dict(version=1, operation="upload", account=str(self.account), session="session", lease="lease", batch="a" * 32, size=len(payload), sha256=hashlib.sha256(payload).hexdigest())
        header.update(changes)
        lease = header["lease"]
        child = self.channels.get(lease)
        if child is None or child.poll() is not None:
            if child is not None:
                child.stdout.close()
                child.stderr.close()
                if not child.stdin.closed:
                    child.stdin.close()
            child = subprocess.Popen([sys.executable, str(RECEIVER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.channels[lease] = child
        child.stdin.write(json.dumps(header).encode() + b"\n" + payload)
        child.stdin.flush()
        if header.get("size", 0) > len(payload):
            child.stdin.close()
        self.assertTrue(select.select([child.stdout], [], [], 5)[0], "receiver did not acknowledge")
        response = child.stdout.readline(4097)
        self.assertLess(len(response), 256)
        reply = json.loads(response)
        if not reply["ok"] or header["operation"] == "cleanup":
            child.wait(timeout=5)
            self.assertEqual(child.stderr.read(), b"")
        return reply["ok"]

    def assert_no_partial_files(self):
        self.assertFalse(self.root.exists())

    def test_eof_and_termination_clean_successful_uploads(self):
        for terminate in (False, True):
            self.assertTrue(self.run_request(archive([("file", b"test")])))
            child = self.channels["lease"]
            if terminate:
                child.send_signal(signal.SIGTERM)
            else:
                child.stdin.close()
            child.wait(timeout=5)
            self.assertFalse((self.account / ".agent-remote-attachments").exists())

    def test_multiple_batches_share_one_connection(self):
        self.assertTrue(self.run_request(archive([("file", b"first")])))
        pid = self.channels["lease"].pid
        self.assertTrue(self.run_request(archive([("image.png", b"second")]), batch="b" * 32))
        self.assertEqual(self.channels["lease"].pid, pid)
        self.assertEqual((self.root / ("a" * 32) / "file").read_bytes(), b"first")
        self.assertEqual((self.root / ("b" * 32) / "image.png").read_bytes(), b"second")

    def test_file_directory_image_and_cleanup_of_last_file(self):
        content = archive([("中文 space/file.txt", b"example"), ("image.png", b"\x89PNG\r\n\x00image"), ("empty/", b"")])
        self.assertTrue(self.run_request(content))
        self.assertEqual((self.root / ("a" * 32) / "中文 space/file.txt").read_bytes(), b"example")
        self.assertTrue((self.root / ("a" * 32) / "empty").is_dir())
        self.assertTrue(self.run_request(operation="cleanup"))
        self.assertFalse((self.account / ".agent-remote-attachments").exists())
        self.assertTrue(self.run_request(operation="cleanup"))
        self.assertFalse((self.account / ".agent-remote-attachments").exists())

    def test_cleanup_cannot_remove_another_live_connections_files(self):
        content = archive([("image.png", b"test")])
        self.assertTrue(self.run_request(content))
        self.assertTrue(self.run_request(content, lease="another-connection"))
        self.assertTrue(self.run_request(operation="cleanup"))
        self.assertTrue((self.root.parent / "another-connection" / ("a" * 32) / "image.png").exists())

    def test_checksum_mismatch_and_eof_remove_partial_upload(self):
        content = archive([("file.txt", b"test")])
        self.assertFalse(self.run_request(content, sha256="0" * 64))
        self.assert_no_partial_files()
        self.assertFalse(self.run_request(content[:-5], size=len(content)))
        self.assert_no_partial_files()

    def test_untrusted_archives_cannot_escape(self):
        for name in ("../outside", "/outside", "a/../../outside", "a\\outside", "a\nfile"):
            self.assertFalse(self.run_request(archive([(name, b"unsafe")])))
            self.assert_no_partial_files()
        link = zipfile.ZipInfo("link")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.assertFalse(self.run_request(archive([(link, b"/etc/passwd")])))

    @unittest.skipUnless(hasattr(os, "O_PATH"), "Linux execute-only ancestor semantics")
    def test_account_ancestors_need_only_traverse_access(self):
        parent = self.account / "traverse-only"
        parent.mkdir()
        nested = parent / "account"
        nested.mkdir()
        parent.chmod(0o111)
        try:
            self.assertTrue(self.run_request(archive([("file", b"test")]), account=str(nested)))
            self.assertTrue(self.run_request(operation="cleanup", account=str(nested)))
        finally:
            parent.chmod(0o700)

    def test_remote_namespace_symlink_is_rejected(self):
        outside = self.account / "outside"
        outside.mkdir()
        (outside / "keep").write_text("preserve")
        (self.account / ".agent-remote-attachments").symlink_to(outside, target_is_directory=True)
        self.assertFalse(self.run_request(archive([("file", b"test")])))
        self.assertFalse(self.run_request(operation="cleanup"))
        self.assertEqual((outside / "keep").read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
