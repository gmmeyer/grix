"""The Python bindings, against the real grix (GRIX_BIN, or target/release/grix)."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))
os.environ.setdefault("GRIX_BIN", str(ROOT / "target/release/grix"))

import grix  # noqa: E402

FIXTURES = ROOT / "fixtures/build"
BUSYBOX = FIXTURES / "alpine/bin/busybox.static"


class SandboxTest(unittest.TestCase):
    def test_run_with_files_stdin_and_events(self):
        sb = grix.Sandbox(
            imports={BUSYBOX: "/bin/busybox"},
            files={"/data/names.txt": "carol\nalice\nbob\n"},
            env={"GREETING": "hi"},
            capabilities=["process"],
        )
        r = sb.run(["/bin/busybox", "sh", "-c", 'echo "$GREETING"; /bin/busybox sort /data/names.txt; /bin/busybox cat'], stdin="from stdin\n")
        self.assertTrue(r.ok, r)
        self.assertEqual(r.stdout, "hi\nalice\nbob\ncarol\nfrom stdin\n")
        self.assertEqual(r.events, [])

    def test_denials_and_missing_capabilities(self):
        r = grix.Sandbox(imports={BUSYBOX: "/bin/busybox"}).run(["/bin/busybox", "wget", "-q", "-O-", "http://example.com"])
        self.assertFalse(r.ok)
        self.assertEqual(r.missing_capabilities, ["net"])
        self.assertTrue(any("needs capability `net`" in e for e in r.events), r.events)

    def test_exports_and_timeouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            sb = grix.Sandbox(imports={BUSYBOX: "/bin/busybox"}, capabilities=["fs_write"], exports={"/out": dest})
            r = sb.run(["/bin/busybox", "cp", "/bin/busybox", "/out/copy"])
            self.assertTrue(r.ok, r)
            self.assertEqual((dest / "copy").read_bytes(), BUSYBOX.read_bytes())
        r = grix.Sandbox(imports={BUSYBOX: "/bin/busybox"}, timeout=1, grace=0).run(["/bin/busybox", "sh", "-c", "while :; do :; done"])
        self.assertEqual((r.status["kind"], r.exit_code), ("timeout", 124))

    def test_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "hello.grix"
            grix.build(image, copy={FIXTURES / "hello": "/bin/hello"}, command=["/bin/hello", "py"], env={"GREETING": "yo"})
            r = grix.Sandbox(image=image).run()
            self.assertEqual(r.exit_code, 7)
            self.assertIn("argv[1]=py\nGREETING=yo\n", r.stdout)

    def test_errors(self):
        with self.assertRaises(grix.GrixError):
            grix.Sandbox(imports={"/no/such/file": "/x"}).run(["/x"])


if __name__ == "__main__":
    unittest.main()
