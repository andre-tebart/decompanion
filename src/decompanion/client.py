"""The `dcp` command: send the command line to the project's daemon (`dcp serve`, daemon.py) when one runs, else
run it in this process (cli.main). It imports nothing of decompanion until it knows which: a command the daemon
runs costs the interpreter start and one round trip.

DCP_NO_DAEMON=1 always runs in-process. A daemon that does not answer (gone, or started for another root) and a
daemon restarting after a code change leave the command to this process too.
"""
from __future__ import annotations

import json
import os
import sys

CONFIG_NAME = "decompanion.toml"


def project_root(argv: list[str]) -> str | None:
    """The --root of the command line, else the first directory from the cwd up holding decompanion.toml."""
    for i, a in enumerate(argv):
        if a == "--root" and i + 1 < len(argv):
            return os.path.abspath(argv[i + 1])
        if a.startswith("--root="):
            return os.path.abspath(a[7:])
    d = os.getcwd()
    while True:
        if os.path.isfile(os.path.join(d, CONFIG_NAME)):
            return d
        up = os.path.dirname(d)
        if up == d:
            return None
        d = up


def connect(root: str):
    """A connection to the daemon of root, or None."""
    try:
        with open(os.path.join(root, "build", "daemon.json"), encoding="utf-8") as fh:
            info = json.load(fh)
        from multiprocessing.connection import Client
        return Client(info["address"], family=info["family"], authkey=bytes.fromhex(info["authkey"]))
    except (OSError, ValueError, KeyError, EOFError):
        return None


def via_daemon(root: str, argv: list[str]) -> int | None:
    """Run the command in the daemon: its exit code, None when it did not run there."""
    conn = connect(root)
    if conn is None:
        return None
    try:
        conn.send({"op": "run", "argv": argv, "cwd": os.getcwd(), "env": dict(os.environ)})
        while True:
            msg = conn.recv()
            kind = msg[0]
            if kind == "out":
                sys.stdout.write(msg[1])
                sys.stdout.flush()
            elif kind == "err":
                sys.stderr.write(msg[1])
                sys.stderr.flush()
            elif kind == "exit":
                return msg[1]
            elif kind == "restart":
                print(f"dcp: the daemon restarts ({msg[1]}); this command runs in-process", file=sys.stderr)
                return None
    except (OSError, EOFError) as ex:
        print(f"dcp: lost the daemon ({ex})", file=sys.stderr)
        return 1
    finally:
        conn.close()


def control(root: str, op: str) -> int:
    import time
    conn = connect(root)
    for _ in range(10):                  # a daemon restarting after a code change opens its pipe within a second
        if conn is not None or not os.path.exists(os.path.join(root, "build", "daemon.json")):
            break
        time.sleep(0.3)
        conn = connect(root)
    if conn is None:
        print(f"dcp serve: no daemon runs for {root}")
        return 1
    try:
        conn.send({"op": op})
        kind, value = conn.recv()
        if op == "status":
            print("  ".join(f"{k}={v}" for k, v in value.items()))
        else:
            print(f"dcp serve: stopped ({root})")
        return 0
    except (OSError, EOFError) as ex:
        print(f"dcp serve: {ex}")
        return 1
    finally:
        conn.close()


def serve(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="dcp serve", description="run the project's daemon (daemon.py)")
    ap.add_argument("--root", help="the project (default: the decompanion.toml above the cwd)")
    ap.add_argument("--stop", action="store_true", help="stop the running daemon")
    ap.add_argument("--status", action="store_true", help="print the running daemon's state")
    a = ap.parse_args(argv)
    root = os.path.abspath(a.root) if a.root else project_root([])
    if root is None:
        print(f"dcp serve: no {CONFIG_NAME} in {os.getcwd()} or above", file=sys.stderr)
        return 2
    if a.stop or a.status:
        return control(root, "stop" if a.stop else "status")
    conn = connect(root)
    if conn is not None:
        conn.close()
        print(f"dcp serve: a daemon runs already for {root} (dcp serve --status)", file=sys.stderr)
        return 1
    from .daemon import supervise
    return supervise(root)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["serve"]:
        return serve(argv[1:])
    if not os.environ.get("DCP_NO_DAEMON"):
        root = project_root(argv)
        if root is not None:
            code = via_daemon(root, argv)
            if code is not None:
                return code
    from .cli import main as cli_main
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())
