"""Run Linux programs in grix sandboxes from Python.

grix boots a fresh microVM for every run. The program sees only the files
you give it and has only the capabilities you grant; whatever it tries
beyond that is denied and reported in the result's ``events``.

    from grix import Sandbox

    sb = Sandbox(imports={"./busybox": "/bin/busybox"}, capabilities=["process"])
    result = sb.run(["/bin/busybox", "echo", "hi"])
    print(result.exit_code, result.stdout, result.events)

With grix's native module (``grix._native``, built by ``make python``),
runs happen in this process: they release the GIL, output can come back as
it's written (``on_output``), a :class:`Control` signals or stops a run
from another thread, and Ctrl-C stops the run. Without it (or with
``grix=`` or ``GRIX_PYTHON=cli``), this drives the ``grix`` command
(``grix run --json``): set ``grix=`` or ``GRIX_BIN`` to say where it is, or
have it on the PATH. Either way, a release's kernel and grix-vmm are found
beside the ``grix`` command.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping, Optional, Sequence, Union

try:
    from . import _native
except ImportError:  # not built: the grix command does the work
    _native = None

__all__ = ["Sandbox", "Snapshot", "Result", "GrixError", "Control", "build", "find_grix", "native"]

PathLike = Union[str, os.PathLike]
#: ``on_output(stream, data)``: ``"stdout"`` or ``"stderr"``, and the bytes.
OnOutput = Callable[[str, bytes], None]


class GrixError(Exception):
    """grix couldn't run the sandbox (not the program failing)."""


def native(grix: Optional[PathLike] = None) -> bool:
    """Whether runs happen in this process (grix's native module), rather
    than through the ``grix`` command."""
    return _native is not None and grix is None and os.environ.get("GRIX_PYTHON") != "cli"


def _install_dir() -> str:
    """Where grix's kernel and grix-vmm are: beside this package in a
    release (``python/grix`` in it), or beside the ``grix`` command
    (``GRIX_BIN``, or on the PATH). Never the Python interpreter's
    directory."""
    release = Path(__file__).resolve().parents[2]
    if (release / "grix-kernel").is_file():
        return os.fspath(release)
    command = os.environ.get("GRIX_BIN")
    if command and os.sep not in command:
        command = shutil.which(command)
    command = command or shutil.which("grix")
    return os.fspath(Path(command).resolve().parent if command else release)


class Control:
    """Signals or stops a run from another thread: pass it to ``run``. Needs
    grix's native module."""

    def __init__(self) -> None:
        if _native is None:
            raise GrixError("Control needs grix's native module (make python)")
        self._inner = _native.Control()

    def signal(self, sig: int) -> bool:
        """Send signal ``sig`` (2 SIGINT, 15 SIGTERM, 9 SIGKILL, ...) to the
        program's process group. False if nothing is running."""
        return self._inner.signal(sig)

    def stop(self) -> bool:
        """End the run in progress now. False if nothing is running."""
        return self._inner.stop()

    def cancel(self) -> None:
        """Stop the run in progress, and any started later with this control."""
        self._inner.cancel()


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
    #: What the guest kernel reported of its resources as the program
    #: ended: ``cpu_ms``, ``syscalls``, ``usage`` (``{resource: {"now",
    #: "peak", "limit"}}``) and ``limits_hit`` (``{limit: count}``). None
    #: if the VM was stopped.
    guest_stats: Optional[dict] = None
    #: What the VM's process cost the host: ``cpu_user_ms``,
    #: ``cpu_system_ms``, ``peak_memory_bytes``.
    host_usage: Optional[dict] = None
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
    the default), ``"ro"``, ``"on-exit"`` or ``"lazy"`` (imported without
    copying it in; changes stay in the sandbox). ``exports`` maps sandbox
    directories to host directories (which must not exist yet, or be empty)
    to write them to when the program ends.
    """

    image: Optional[PathLike] = None
    imports: Mapping[PathLike, str] = field(default_factory=dict)
    files: Mapping[str, Union[str, bytes]] = field(default_factory=dict)
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: Optional[str] = None
    #: The sandbox's host name (``grix`` by default).
    hostname: Optional[str] = None
    #: Give the program HOME, PATH, LANG and TMPDIR, unless ``env`` sets them.
    default_env: bool = False
    host_timezone: bool = False
    #: The network stack: ``"none"``, ``"native"`` (sockets on the host's own
    #: stack, what the ``net`` capability gives) or ``"vm"`` (TCP/IP in the
    #: sandbox). The last two grant ``net``, and the same rules hold on both.
    network: Optional[str] = None
    capabilities: Sequence[str] = ()
    memory_mb: Optional[int] = None
    #: CPUs for the program's threads (1 by default).
    cpus: Optional[int] = None
    #: An x86_64 translator (arm64 qemu-x86_64; box64 untested) to run x86_64 programs with.
    x86_64: Optional[PathLike] = None
    timeout: Optional[float] = None
    grace: Optional[float] = None
    allow_hosts: Sequence[str] = ()
    #: Forwarded ports as ``grix run -p`` takes them: ``"8080:80"``, ``"5353:53/udp"``.
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
        if self.hostname is not None:
            a += ["--hostname", self.hostname]
        if self.host_timezone:
            a += ["--host-timezone"]
        if self.default_env:
            a += ["--default-env"]
        if self.network is not None:
            a += ["--network", self.network]
        for c in self.capabilities:
            a += ["-a", c]
        if self.memory_mb:
            a += ["--mem", str(int(self.memory_mb))]
        if self.cpus:
            a += ["--cpus", str(int(self.cpus))]
        if self.x86_64 is not None:
            a += ["--x86-64", os.fspath(self.x86_64)]
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

    def _config(self) -> dict:
        """What the native module takes."""
        files = [(g, c.encode() if isinstance(c, str) else bytes(c), 0o644) for g, c in self.files.items()]
        num = lambda v, t: None if v is None else t(v)  # noqa: E731
        return {
            "image": num(self.image, os.fspath),
            "imports": [(os.fspath(h), g) for h, g in self.imports.items()],
            "files": files,
            "env": list(self.env.items()),
            "cwd": self.cwd,
            "hostname": self.hostname,
            "default_env": bool(self.default_env),
            "host_timezone": bool(self.host_timezone),
            "network": self.network,
            "capabilities": list(self.capabilities),
            "memory_mb": num(self.memory_mb or None, int),
            "cpus": num(self.cpus or None, int),
            "x86_64": num(self.x86_64, os.fspath),
            "timeout": num(self.timeout, float),
            "grace": num(self.grace, float),
            "allow_hosts": list(self.allow_hosts),
            "publish": list(self.publish),
            "mounts": [(os.fspath(m[0]), m[1], m[2] if len(m) > 2 else "rw") for m in self.mounts],
            "exports": [(g, os.fspath(h)) for g, h in self.exports.items()],
            "max_output_mb": num(self.max_output_mb or None, int),
            "install_dir": _install_dir(),
        }

    def run(
        self,
        command: Optional[Sequence[str]] = None,
        stdin: Union[str, bytes, None] = None,
        *,
        on_output: Optional[OnOutput] = None,
        control: Optional[Control] = None,
    ) -> Result:
        """Run ``command`` (or the image's) and wait for it. ``on_output``
        gets the program's output as it comes (natively; through the
        ``grix`` command, once it's done)."""
        if native(self.grix):
            data = stdin.encode() if isinstance(stdin, str) else stdin
            inner = control._inner if control is not None else None
            return _native_result(_native.run, self._config(), list(command or []), data, on_output, inner)
        if control is not None:
            raise GrixError("Control needs grix's native module (make python)")
        with tempfile.TemporaryDirectory(prefix="grix-py-") as tmp:
            argv = [find_grix(self.grix), "run", "--json", "--quiet"] + self._args(Path(tmp))
            if stdin is None:
                argv.append("--no-stdin")
            if command:
                argv += ["--", *command]
            return _run(argv, stdin, on_output)

    def snapshot(self, path: PathLike, command: Optional[Sequence[str]] = None) -> "Snapshot":
        """Start ``command`` (or the image's) and save the whole machine to
        ``path`` when it first waits for input; each :meth:`Snapshot.run`
        then starts from there, in milliseconds. Needs grix's own VMM
        (macOS 15+); the sandbox can't have on-exit mounts, and its live
        mounts need their host directories again (``Snapshot.mounts``)."""
        if native(self.grix):
            try:
                _native.snapshot(self._config(), os.fspath(path), list(command or []))
            except _native.Error as e:
                raise GrixError(str(e)) from None
            return Snapshot(path, grix=self.grix)
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
    from where the program waited for input, with its own stdin. Its live
    mounts need their host directories again: ``mounts`` lists ``(host,
    guest)`` or ``(host, guest, "ro")``. Whoever wrote the file, runs get
    the network only with ``allow_net`` (and only to ``allow_hosts``, if
    any), never the file's own rules."""

    path: PathLike
    timeout: Optional[float] = None
    grix: Optional[PathLike] = None
    mounts: Sequence[tuple] = ()
    allow_net: bool = False
    allow_hosts: Sequence[str] = ()

    def run(
        self,
        stdin: Union[str, bytes, None] = None,
        *,
        on_output: Optional[OnOutput] = None,
        control: Optional[Control] = None,
    ) -> Result:
        if native(self.grix):
            data = stdin.encode() if isinstance(stdin, str) else stdin
            inner = control._inner if control is not None else None
            mounts = [(os.fspath(m[0]), m[1], m[2] if len(m) > 2 else "rw") for m in self.mounts]
            return _native_result(
                _native.snapshot_run,
                os.fspath(self.path),
                _install_dir(),
                data,
                self.timeout,
                on_output,
                inner,
                mounts,
                self.allow_net,
                list(self.allow_hosts),
            )
        if control is not None:
            raise GrixError("Control needs grix's native module (make python)")
        argv = [find_grix(self.grix), "run", "--json", "--quiet", "--snapshot", os.fspath(self.path)]
        for m in self.mounts:
            host, guest, *mode = m
            argv += ["--mount", f"{os.fspath(host)}:{guest}" + (f":{mode[0]}" if mode else "")]
        if self.timeout is not None:
            argv += ["--timeout", str(max(1, int(round(self.timeout))))]
        if self.allow_net:
            argv += ["-a", "net"]
            for rule in self.allow_hosts:
                argv += ["--allow-host", rule]
        if stdin is None:
            argv.append("--no-stdin")
        return _run(argv, stdin, on_output)


def _native_result(fn, *args) -> Result:
    try:
        out = json.loads(fn(*args))
    except _native.Error as e:
        raise GrixError(str(e)) from None
    return _result(out, out["exit_code"], out["messages"])


def _run(argv: list, stdin: Union[str, bytes, None], on_output: Optional[OnOutput] = None) -> Result:
    data = stdin.encode() if isinstance(stdin, str) else stdin
    proc = subprocess.run(argv, input=data, capture_output=True)
    try:
        out = json.loads(proc.stdout)
    except ValueError:
        raise GrixError(proc.stderr.decode(errors="replace").strip() or f"grix exited with {proc.returncode}")
    if on_output is not None:
        for stream in ("stdout", "stderr"):
            if out[stream]:
                on_output(stream, out[stream].encode())
    return _result(out, proc.returncode, proc.stderr.decode(errors="replace"))


def _result(out: dict, exit_code: int, messages: str) -> Result:
    return Result(
        status=out["status"],
        exit_code=exit_code,
        stdout=out["stdout"],
        stderr=out["stderr"],
        events=out["events"],
        missing_capabilities=out.get("missing_capabilities", []),
        duration_ms=out["duration"],
        exports=out.get("exports", []),
        mount_changes=out.get("mount_changes", []),
        messages=messages,
        guest_stats=out.get("guest_stats"),
        host_usage=out.get("host_usage"),
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
    cache: bool = True,
    arch: Optional[str] = None,
    grix: Optional[PathLike] = None,
) -> None:
    """Build a grix image at ``output`` (``grix build``): from a Grixfile,
    these settings, or both. ``run`` steps are shell commands. With
    ``cache=False``, every step runs even if its inputs haven't changed.
    ``arch`` (``"aarch64"`` or ``"x86_64"``) is the architecture to build
    for, the host's by default: an image runs on its own."""
    argv = [find_grix(grix), "build", "--quiet", "-o", os.fspath(output)]
    if not cache:
        argv.append("--no-cache")
    if arch is not None:
        argv += ["--arch", arch]
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
