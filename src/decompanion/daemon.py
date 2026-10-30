"""`dcp serve`: one resident process per project that runs the dcp commands, so a command pays neither the
interpreter start and imports nor the first read of the image, the sources, the store and the objects.

    dcp serve            run the daemon of the project above the cwd in the foreground (Ctrl-C stops it)
    dcp serve --status   is it running: pid, uptime, requests served, memory
    dcp serve --stop     stop it

The `dcp` command (client.py) sends every other command line to the project's daemon when one runs and runs it in
its own process otherwise: the same code either way, and the output, the exit code and the files written are the
same. The daemon only keeps what the process memos keep anyway (fsmemo, the source scan, the plans, the parsed
objects, the compares, the decoded facts); every memo is keyed by the content it was computed from, every
request opens the project afresh (the configuration is read again) and starts a new file epoch, so a request
sees every change made since the last one, by dcp or by anyone else.

- One daemon per project root: a named pipe (AF_PIPE; a Unix socket elsewhere) whose name hashes the root, with
  a random key per start. build/daemon.json holds the address, the key and the pid; only a client that can read
  it can connect.
- Requests run one at a time, in the order they connect (the store has one writer; a command changes the cwd and
  the environment of the process): two agents' commands are serialised, not interleaved. A request carries the
  argv, the cwd and the environment of the client; stdout and stderr are streamed back as they are written.
- `dcp serve` is a small supervisor around the daemon process. When the code of decompanion changed (any .py of
  the package), the daemon answers the next request with `restart` (the client runs that command itself) and
  exits; the supervisor starts a new one.
- A worktree is a project root of its own: it gets its own daemon (`dcp serve` there), or runs in-process.
- The store stays open in the daemon: stop it before deleting build/ (Windows refuses to delete an open file).
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import sys
import time
import traceback
from contextlib import redirect_stderr, redirect_stdout
from multiprocessing.connection import Listener
from pathlib import Path

RESTART = 75              # the daemon's exit code when the code changed: the supervisor starts it again
PKG = Path(__file__).resolve().parent


def address(root: Path) -> tuple[str, str]:
    """(family, address) of the project's daemon."""
    if os.name == "nt":
        h = hashlib.sha256(str(Path(root).resolve()).lower().encode()).hexdigest()[:16]
        return "AF_PIPE", rf"\\.\pipe\dcp-{h}"
    return "AF_UNIX", str(Path(root) / "build" / "daemon.sock")


def info_path(root: Path) -> Path:
    return Path(root) / "build" / "daemon.json"


def code_stamp() -> str:
    """The stamps (path, size, modification time) of every .py of the package: changed code changes it."""
    h = hashlib.sha256()

    def rec(d):
        with os.scandir(d) as it:
            for e in sorted(it, key=lambda e: e.name):
                if e.is_dir() and e.name != "__pycache__":
                    rec(e.path)
                elif e.name.endswith(".py"):
                    st = e.stat()
                    h.update(f"{e.path}\0{st.st_size}\0{st.st_mtime_ns}\n".encode())
    rec(PKG)
    return h.hexdigest()


class _Stream(io.TextIOBase):
    """A text stream that sends what is written to the client: ("out" | "err", text), one message per line
    batch."""

    def __init__(self, conn, kind: str):
        self.conn, self.kind, self.buf = conn, kind, []

    def writable(self):
        return True

    def write(self, s: str) -> int:
        self.buf.append(s)
        if "\n" in s:
            self.flush()
        return len(s)

    def flush(self):
        if self.buf:
            text, self.buf = "".join(self.buf), []
            try:
                self.conn.send((self.kind, text))
            except OSError:
                pass                      # the client went away: the command still finishes

    @property
    def encoding(self):
        return "utf-8"

    def isatty(self):
        return False


class Daemon:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.code = code_stamp()
        self.started = time.time()
        self.requests = 0

    def run(self) -> int:
        family, addr = address(self.root)
        key = secrets.token_bytes(32)
        if family == "AF_UNIX" and os.path.exists(addr):
            os.unlink(addr)
        listener = Listener(addr, family=family, authkey=key)
        info = info_path(self.root)
        info.parent.mkdir(parents=True, exist_ok=True)
        tmp = info.with_name(f"daemon.{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"pid": os.getpid(), "family": family, "address": addr, "authkey": key.hex(),
                                   "root": str(self.root), "started": self.started}), newline="\n")
        os.replace(tmp, info)
        from . import cli  # noqa: F401  (the imports and the rule registry are what a request should not pay)
        from .ledger import store
        store.KEEP_OPEN = True
        print(f"dcp serve: {self.root} (pid {os.getpid()}, {addr})", file=sys.stderr, flush=True)
        rc = 0
        try:
            while True:
                try:
                    conn = listener.accept()
                except (OSError, EOFError) as ex:         # a client that failed the key, or vanished
                    print(f"dcp serve: refused a connection: {ex}", file=sys.stderr, flush=True)
                    continue
                try:
                    req = conn.recv()
                    op = req.get("op", "run")
                    if op == "stop":
                        conn.send(("exit", 0))
                        break
                    if op == "status":
                        conn.send(("status", self.status()))
                        continue
                    if code_stamp() != self.code:
                        conn.send(("restart", "the decompanion code changed"))
                        print("dcp serve: the decompanion code changed: restarting", file=sys.stderr, flush=True)
                        rc = RESTART
                        break
                    self.handle(conn, req)
                except (OSError, EOFError):
                    pass
                finally:
                    conn.close()
        except KeyboardInterrupt:
            pass
        finally:
            listener.close()
            try:
                if json.loads(info.read_text()).get("pid") == os.getpid():
                    info.unlink()
            except (OSError, ValueError):
                pass
        return rc

    def status(self) -> dict:
        mem = None
        try:
            import ctypes
            from ctypes import wintypes

            class PMC(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
            c = PMC()
            c.cb = ctypes.sizeof(PMC)
            k32, psapi = ctypes.WinDLL("kernel32"), ctypes.WinDLL("psapi")
            k32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
            if psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(c), c.cb):
                mem = c.WorkingSetSize
        except (AttributeError, OSError, ImportError):
            pass
        return {"pid": os.getpid(), "root": str(self.root), "uptime": int(time.time() - self.started),
                "requests": self.requests, "memory_mb": round(mem / 2**20) if mem else None}

    def handle(self, conn, req: dict):
        from . import cli, timing
        self.requests += 1
        t0 = time.perf_counter()
        env, cwd = dict(os.environ), os.getcwd()
        out, err = _Stream(conn, "out"), _Stream(conn, "err")
        code = 1
        try:
            os.environ.clear()
            os.environ.update(req.get("env") or env)
            os.chdir(req.get("cwd") or cwd)
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    code = cli.main(list(req.get("argv") or []))
                except SystemExit as ex:
                    if ex.code is None or isinstance(ex.code, int):
                        code = ex.code or 0
                    else:
                        print(ex.code, file=sys.stderr)
                        code = 1
                except Exception:
                    traceback.print_exc()
                    code = 1
                if timing.level():
                    print(f"timing: daemon request={(time.perf_counter() - t0) * 1000:.0f}", file=sys.stderr)
            out.flush()
            err.flush()
        finally:
            os.environ.clear()
            os.environ.update(env)
            try:
                os.chdir(cwd)
            except OSError:
                pass
        conn.send(("exit", code if isinstance(code, int) else 1))


def supervise(root: Path) -> int:
    """Run the daemon in a child process and start it again whenever it exits because the code changed."""
    import subprocess
    while True:
        try:
            rc = subprocess.call([sys.executable, "-m", "decompanion.daemon", str(root)])
        except KeyboardInterrupt:
            return 0
        if rc != RESTART:
            return rc


if __name__ == "__main__":
    sys.exit(Daemon(Path(sys.argv[1])).run())
