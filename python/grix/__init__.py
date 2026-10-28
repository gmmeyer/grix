"""Run Linux programs in grix sandboxes from Python.

grix boots a fresh microVM for every run. The program sees only the files
you give it and has only the capabilities you grant; whatever it tries
beyond that is denied and reported in the result's ``events``.

    from grix import Sandbox

    sb = Sandbox(imports={"./busybox": "/bin/busybox"}, capabilities=["process"])
    result = sb.run(["/bin/busybox", "echo", "hi"])
    print(result.exit_code, result.stdout, result.events)

This drives the ``grix`` command (``grix run --json``): set ``grix=`` or
the ``GRIX_BIN`` environment variable to say where it is, or have it on the
PATH.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence, Union

__all__ = ["Sandbox", "Snapshot", "Result", "GrixError", "build", "find_grix"]

PathLike = Union[str, os.PathLike]


class GrixError(Exception):
    """grix couldn't run the sandbox (not the program failing)."""


def find_grix(grix: Optional[PathLike] = None) -> str:
    """The grix command: ``grix``, ``$GRIX_BIN``, or ``grix`` on the PATH."""
    path = grix or os.environ.get("GRIX_BIN") or shutil.which("grix")
    if not path:
        raise GrixError("can't find grix: set GRIX_BIN or put it on the PATH")
    return os.fspath(path)


@dataclass
class Result:
    """What a run did."""

    #: ``{"kind": "exited"|"signaled"|"timeout"|"stopped"|..., "value": ...}``
    status: dict
    #: Shell-style: the exit status, 128+signal, 124 on timeout, 125 if the sandbox failed.
    exit_code: int
    stdout: str
    stderr: str
    #: What the program was denied, couldn't find, crashed on, ... (readable lines).
    events: list
    #: Capabilities the program asked for and didn't have.
    missing_capabilities: list
    duration_ms: int
    #: Exported directories: path, kind and size of what came back.
    exports: list = field(default_factory=list)
    #: What each mount's changes did on the host.
    mount_changes: list = field(default_factory=list)
    #: grix's own notes and warnings (its stderr), not the program's.
    messages: str = ""
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def ok(self) -> bool:
        """The program exited with 0 and everything it changed reached the host."""
        return self.exit_code == 0 and self.status.get("kind") == "exited" and self.status.get("value") == 0


@dataclass
class Sandbox:
    """A sandbox configuration; each :meth:`run` boots a fresh one.

    ``imports`` maps host paths to sandbox paths (copied in); ``files`` maps
    sandbox paths to contents (str or bytes). ``mounts`` lists
    ``(host, guest)`` or ``(host, guest, mode)`` with mode ``"rw"`` (live,
    the default), ``"ro"`` or ``"on-exit"``. ``exports`` maps sandbox
    directories to host directories (which must not exist yet, or be empty)
    to write them to when the program ends.
    """

    image: Optional[PathLike] = None
    imports: Mapping[PathLike, str] = field(default_factory=dict)
    files: Mapping[str, Union[str, bytes]] = field(default_factory=dict)
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: Optional[str] = None
    capabilities: Sequence[str] = ()
    memory_mb: Optional[int] = None
    timeout: Optional[float] = None
    grace: Optional[float] = None
    allow_hosts: Sequence[str] = ()
    publish: Sequence[str] = ()
    mounts: Sequence[tuple] = ()
    exports: Mapping[str, PathLike] = field(default_factory=dict)
    max_output_mb: Optional[int] = None
    grix: Optional[PathLike] = None

    def _args(self, tmp: Path) -> list:
        a = []
        if self.image is not None:
            a += ["--image", os.fspath(self.image)]
        for host, guest in self.imports.items():
            a += ["-i", f"{os.fspath(host)}:{guest}"]
        for i, (guest, content) in enumerate(self.files.items()):
            data = content.encode() if isinstance(content, str) else bytes(content)
            path = tmp / f"file{i}"
            path.write_bytes(data)
            a += ["-i", f"{path}:{guest}"]
        for k, v in self.env.items():
            a += ["-e", f"{k}={v}"]
        if self.cwd:
            a += ["--cwd", self.cwd]
        for c in self.capabilities:
            a += ["-a", c]
        if self.memory_mb:
            a += ["--mem", str(int(self.memory_mb))]
        if self.timeout is not None:
            a += ["--timeout", str(max(1, int(round(self.timeout))))]
        if self.grace is not None:
            a += ["--grace", str(int(self.grace))]
        for rule in self.allow_hosts:
            a += ["--allow-host", rule]
        for spec in self.publish:
            a += ["-p", spec]
        for m in self.mounts:
            host, guest, *mode = m
            a += ["--mount", f"{os.fspath(host)}:{guest}" + (f":{mode[0]}" if mode else "")]
        for guest, host in self.exports.items():
            a += ["-x", f"{guest}:{os.fspath(host)}"]
        if self.max_output_mb:
            a += ["--max-output", str(int(self.max_output_mb))]
        return a

    def run(self, command: Optional[Sequence[str]] = None, stdin: Union[str, bytes, None] = None) -> Result:
        """Run ``command`` (or the image's) and wait for it."""
        with tempfile.TemporaryDirectory(prefix="grix-py-") as tmp:
            argv = [find_grix(self.grix), "run", "--json", "--quiet"] + self._args(Path(tmp))
            if stdin is None:
                argv.append("--no-stdin")
            if command:
                argv += ["--", *command]
            return _run(argv, stdin)

    def snapshot(self, path: PathLike, command: Optional[Sequence[str]] = None) -> "Snapshot":
        """Start ``command`` (or the image's) and save the whole machine to
        ``path`` when it first waits for input; each :meth:`Snapshot.run`
        then starts from there, in milliseconds. Needs grix's own VMM
        (macOS 15+); the sandbox can't have mounts."""
        with tempfile.TemporaryDirectory(prefix="grix-py-") as tmp:
            argv = [find_grix(self.grix), "snapshot", "--quiet", "-o", os.fspath(path)] + self._args(Path(tmp))
            if command:
                argv += ["--", *command]
            proc = subprocess.run(argv, capture_output=True)
        if proc.returncode != 0:
            raise GrixError(proc.stderr.decode(errors="replace").strip())
        return Snapshot(path, grix=self.grix)


@dataclass
class Snapshot:
    """A machine :meth:`Sandbox.snapshot` saved: each :meth:`run` goes on
    from where the program waited for input, with its own stdin."""

    path: PathLike
    timeout: Optional[float] = None
    grix: Optional[PathLike] = None

    def run(self, stdin: Union[str, bytes, None] = None) -> Result:
        argv = [find_grix(self.grix), "run", "--json", "--quiet", "--snapshot", os.fspath(self.path)]
        if self.timeout is not None:
            argv += ["--timeout", str(max(1, int(round(self.timeout))))]
        if stdin is None:
            argv.append("--no-stdin")
        return _run(argv, stdin)


def _run(argv: list, stdin: Union[str, bytes, None]) -> Result:
    data = stdin.encode() if isinstance(stdin, str) else stdin
    proc = subprocess.run(argv, input=data, capture_output=True)
    try:
        out = json.loads(proc.stdout)
    except ValueError:
        raise GrixError(proc.stderr.decode(errors="replace").strip() or f"grix exited with {proc.returncode}")
    return Result(
        status=out["status"],
        exit_code=proc.returncode,
        stdout=out["stdout"],
        stderr=out["stderr"],
        events=out["events"],
        missing_capabilities=out.get("missing_capabilities", []),
        duration_ms=out["duration"],
        exports=out.get("exports", []),
        mount_changes=out.get("mount_changes", []),
        messages=proc.stderr.decode(errors="replace"),
        raw=out,
    )


def build(
    output: PathLike,
    grixfile: Optional[PathLike] = None,
    *,
    from_: Optional[str] = None,
    copy: Mapping[PathLike, str] = {},
    command: Optional[Sequence[str]] = None,
    env: Mapping[str, str] = {},
    capabilities: Iterable[str] = (),
    run: Iterable[str] = (),
    grix: Optional[PathLike] = None,
) -> None:
    """Build a grix image at ``output`` (``grix build``): from a Grixfile,
    these settings, or both. ``run`` steps are shell commands."""
    argv = [find_grix(grix), "build", "--quiet", "-o", os.fspath(output)]
    if grixfile is not None:
        argv += ["-f", os.fspath(grixfile)]
    if from_:
        argv += ["--from", from_]
    for host, guest in copy.items():
        argv += ["--copy", f"{os.fspath(host)}:{guest}"]
    for k, v in env.items():
        argv += ["-e", f"{k}={v}"]
    for c in capabilities:
        argv += ["-a", c]
    for step in run:
        argv += ["--run", step]
    if command:
        argv += ["--", *command]
    proc = subprocess.run(argv, capture_output=True)
    if proc.returncode != 0:
        raise GrixError(proc.stderr.decode(errors="replace").strip())
