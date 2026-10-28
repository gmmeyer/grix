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


class Common:
    """Tests for both ways of running: natively and through the grix command."""

    mode = ""

    def setUp(self):
        self.saved = os.environ.get("GRIX_PYTHON")
        os.environ["GRIX_PYTHON"] = self.mode
        self.assertEqual(grix.native(), self.mode == "native")

    def tearDown(self):
        if self.saved is None:
            os.environ.pop("GRIX_PYTHON", None)
        else:
            os.environ["GRIX_PYTHON"] = self.saved

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

    def test_snapshots(self):
        if sys.platform != "darwin" and not os.path.exists("/dev/kvm"):
            self.skipTest("snapshots need grix-vmm (macOS, or Linux with KVM)")
        with tempfile.TemporaryDirectory() as tmp:
            sb = grix.Sandbox(imports={BUSYBOX: "/bin/busybox"}, capabilities=["process"])
            snap = sb.snapshot(Path(tmp) / "sh.snap", ["/bin/busybox", "sh", "-c", 'read x; echo "got $x"'])
            for word in ["a", "b"]:
                r = snap.run(stdin=f"{word}\n")
                self.assertTrue(r.ok, r)
                self.assertEqual(r.stdout, f"got {word}\n")
            with self.assertRaises(grix.GrixError):
                sb.snapshot(Path(tmp) / "none.snap", ["/bin/busybox", "true"])

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

    def test_exports_where_mounts_could_lead_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            (work / "res").mkdir(parents=True)
            sb = grix.Sandbox(imports={BUSYBOX: "/bin/busybox"}, mounts=[(work, "/work", "ro")], exports={"/out": work / "res" / "out"})
            with self.assertRaisesRegex(grix.GrixError, "inside mounted"):
                sb.run(["/bin/busybox", "true"])
            sb = grix.Sandbox(imports={BUSYBOX: "/bin/busybox"}, exports={"/out": Path(tmp) / "out", "/o2": Path(tmp) / "out"})
            with self.assertRaisesRegex(grix.GrixError, "two exports"):
                sb.run(["/bin/busybox", "true"])

    def test_output_as_it_comes(self):
        seen = []
        sb = grix.Sandbox(imports={BUSYBOX: "/bin/busybox"}, capabilities=["process"])
        r = sb.run(["/bin/busybox", "sh", "-c", "echo out; echo err >&2"], on_output=lambda s, d: seen.append((s, d)))
        self.assertTrue(r.ok, r)
        self.assertEqual(b"".join(d for s, d in seen if s == "stdout"), b"out\n")
        self.assertEqual(b"".join(d for s, d in seen if s == "stderr"), b"err\n")


class CliTest(Common, unittest.TestCase):
    mode = "cli"


class NativeTest(Common, unittest.TestCase):
    """The native module (make python builds it; it's never skipped)."""

    mode = "native"

    def test_control_from_another_thread(self):
        import threading
        import time

        control = grix.Control()
        sb = grix.Sandbox(imports={BUSYBOX: "/bin/busybox"}, capabilities=["process"])
        seen = threading.Event()

        def on_output(stream, data):
            if b"ready" in data:
                seen.set()

        t = threading.Thread(target=lambda: (seen.wait(30), time.sleep(0.2), control.signal(15)))
        t.start()
        script = "trap 'echo got TERM; exit 3' TERM; echo ready; while :; do /bin/busybox sleep 1; done"
        r = sb.run(["/bin/busybox", "sh", "-c", script], on_output=on_output, control=control)
        t.join()
        self.assertEqual(r.exit_code, 3, r)
        self.assertIn("got TERM", r.stdout)
        # Cancelled: what starts after that stops at once.
        control.cancel()
        r = sb.run(["/bin/busybox", "sleep", "30"], control=control)
        self.assertEqual(r.status["kind"], "stopped", r)

    def test_exports_that_fail_say_so(self):
        # The destination is taken during the run: 125, and why.
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"

            def on_output(stream, data):
                dest.mkdir(exist_ok=True)
                (dest / "taken").write_text("x")

            sb = grix.Sandbox(imports={BUSYBOX: "/bin/busybox"}, capabilities=["fs_write"], exports={"/out": dest})
            r = sb.run(["/bin/busybox", "sh", "-c", "echo hi > /out/f; echo go"], on_output=on_output)
            self.assertEqual(r.exit_code, 125, r)
            self.assertFalse(r.ok)
            self.assertIn("exporting /out", r.messages)

    def test_runs_in_parallel_threads(self):
        import threading
        import time

        sb = grix.Sandbox(imports={BUSYBOX: "/bin/busybox"})
        results = []
        started = time.monotonic()
        threads = [threading.Thread(target=lambda: results.append(sb.run(["/bin/busybox", "sleep", "2"]))) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual([r.exit_code for r in results], [0, 0, 0])
        # The GIL is released while they run: not one after another.
        self.assertLess(time.monotonic() - started, 5.5)

    def test_callback_errors_stop_the_run(self):
        def boom(stream, data):
            raise ValueError("no thanks")

        sb = grix.Sandbox(imports={BUSYBOX: "/bin/busybox"}, capabilities=["process"])
        with self.assertRaises(ValueError):
            sb.run(["/bin/busybox", "sh", "-c", "echo hi; /bin/busybox sleep 30"], on_output=boom)


if __name__ == "__main__":
    unittest.main()
