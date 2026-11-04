#!/usr/bin/env python3
"""Linux shared-sandbox regression test; builds must already exist.

Run with: python3 tests/sandy_identity.py --sandy /path/to/sandy --devsm /path/to/devsm
Requires working sandy user/mount namespaces. Uses disposable repos and state.
"""

import argparse
import ctypes
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


CONFIG = """[action.probe]
sh = 'pwd; readlink /proc/self/ns/mnt; cat label'

[action.setup]
sh = 'echo setup >> /tmp/identity-setup-count'
cache.persistent = true

[action.use]
sh = 'test "$(wc -l < /tmp/identity-setup-count)" -eq 1'
require = ['setup']

[action.complete]
cmd = ['true', { var = 'args' }]
cli.forward-arguments = true
cli.autocomplete = { command = ['sh', 'schema.sh'] }
"""


def run(command, **kwargs):
    # Keep stdin open until exit: devsm treats EOF as the caller detaching.
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, **kwargs) as child:
        try:
            child.wait(timeout=20)
        except BaseException:
            child.kill()
            raise
        stdout, stderr = child.stdout.read(), child.stderr.read()
        assert child.returncode == 0, (command, stdout, stderr)
        return stdout


def owner(path):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect(path)
        return struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0]


def inside():
    private = Path(f"/tmp/devsm-{os.geteuid()}")
    assert os.environ["DEVSM_SOCKET"] == str(private / "devsm.socket")
    assert os.environ["DEVSM_DB"] == str(private / "devsm.db")
    assert private.stat().st_mode & 0o777 == 0o700
    binary = "/test-bin/devsm"
    namespace = os.readlink("/proc/self/ns/mnt")
    if "--connect-only" not in sys.argv:
        probe = run([binary, "run", "probe"]).splitlines()
        assert probe == [str(Path.cwd()), namespace, Path("label").read_text().strip()], probe
        run([binary, "run", "use"])
        assert Path("/tmp/identity-setup-count").read_text() == "setup\n"
    records = json.loads(run([binary, "get", "workspaces", "--json"]))["workspaces"]
    if "--connect-only" not in sys.argv:
        assert len(records) == 1 and records[0]["currently_loaded"], records
        assert records[0]["config_path"] == str(Path.cwd() / "devsm.toml"), records
    if "--complete" in sys.argv:
        result = run([binary, "self", "complete", "task-args", "--task=complete", "--", ""])
        assert result.strip() == "items\n--local", result
        assert Path("/tmp/identity-schema-count").read_text() == "schema\n"
        assert len(list((private / "devsm.db.cache/autocomplete").iterdir())) == 1
    pid = owner(os.environ["DEVSM_SOCKET"])
    assert os.readlink(f"/proc/{pid}/ns/mnt") == namespace
    metadata = private.stat()
    print(json.dumps({"namespace": namespace, "pid": pid, "cwd": str(Path.cwd()),
                      "state": [metadata.st_dev, metadata.st_ino]}), flush=True)
    if "--hold" in sys.argv:
        assert sys.stdin.readline().strip() == "done"


class Client:
    def __init__(self, command, **kwargs):
        self.error = tempfile.TemporaryFile(mode="w+")
        self.child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=self.error, text=True, **kwargs)

    def ready(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.child.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=30), "sandbox timed out"
        line = self.child.stdout.readline()
        self.error.seek(0)
        assert line, self.error.read()
        return json.loads(line)

    def finish(self):
        self.child.communicate("done\n", timeout=10)
        self.error.seek(0)
        assert self.child.returncode == 0, self.error.read()

    def close(self):
        if self.child.poll() is None:
            self.child.kill()
        self.child.wait()
        self.child.stdin.close()
        self.child.stdout.close()
        self.error.close()


def kill_daemon(pid):
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sandy", required=True, type=Path)
    parser.add_argument("--devsm", required=True, type=Path)
    args = parser.parse_args()
    sandy, binary = args.sandy.resolve(), args.devsm.resolve()
    # Adopt automatic daemons so failures cannot leave our sandboxes running.
    assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
    with tempfile.TemporaryDirectory(prefix="sandy-shared-") as fixture:
        fixture = Path(fixture)
        repos = [fixture / name for name in ["a", "b", "custom", "keep", "original"]]
        for repo in repos:
            repo.mkdir()
            (repo / "devsm.toml").write_text(CONFIG)
            (repo / "label").write_text(repo.name + "\n")
            (repo / "schema.sh").write_text("echo schema >> /tmp/identity-schema-count\nprintf '%s\\n' '{\"version\":1,\"options\":[{\"name\":\"local\"}]}'\n")
        env = os.environ.copy()
        env.pop("DEVSM_NO_AUTO_SPAWN", None)
        env.update(DEVSM_SOCKET=str(fixture / "host.socket"), DEVSM_DB=str(fixture / "host.db"))
        clients = []
        host = None

        def command(flags=()):
            return [str(sandy), *flags, "-r", f"{binary.parent}:/test-bin",
                    "-r", f"{Path(__file__).resolve().parent}:/test-tools", "--"]

        def start(repo, flags=(), hold=False, complete=False, shell=None, connect_only=False):
            cmd = command(flags)
            worker = ["/usr/bin/python3", "/test-tools/sandy_identity.py", "--inside"]
            if hold:
                worker.append("--hold")
            if complete:
                worker.append("--complete")
            if connect_only:
                worker.append("--connect-only")
            cmd += ["/bin/sh", "-c", shell, "--", *worker] if shell else worker
            client = Client(cmd, cwd=repo, env=env)
            clients.append(client)
            return client

        def probe(repo, **kwargs):
            client = start(repo, **kwargs)
            record = client.ready()
            client.finish()
            return record

        try:
            with tempfile.TemporaryFile() as log:
                host = subprocess.Popen([str(binary), "self", "server"], cwd=repos[0], env=env,
                                        stdout=log, stderr=log)
                deadline = time.monotonic() + 10
                while not Path(env["DEVSM_SOCKET"]).exists():
                    assert host.poll() is None and time.monotonic() < deadline
                    time.sleep(0.01)

            # Concurrent first launches must converge on one namespace and daemon.
            boxes = [start(repos[0], hold=True, connect_only=True) for _ in range(12)]
            records = [box.ready() for box in boxes]
            first = records[0]
            assert all(record == first for record in records), records
            assert first["namespace"] != os.readlink("/proc/self/ns/mnt")
            for box in boxes:
                box.finish()
            assert probe(repos[0], complete=True) == first
            assert probe(repos[0], complete=True) == first
            link = fixture / "alias"
            link.symlink_to(repos[0], target_is_directory=True)
            assert probe(link) == first
            assert probe(repos[0], shell='exec /test-bin/sandy "$@"') == first
            print("PASS concurrent and later same-directory launches share namespaces, daemon, and caches")

            other = probe(repos[1])
            assert other["namespace"] != first["namespace"]
            assert other["pid"] != first["pid"] and other["state"] != first["state"]
            host_probe = run([str(binary), "run", "probe"], cwd=repos[0], env=env).splitlines()
            assert host_probe == [str(repos[0]), os.readlink("/proc/self/ns/mnt"), "a"]
            assert owner(env["DEVSM_SOCKET"]) == host.pid
            print("PASS different directories and the host remain isolated")

            # A live shell keeps /tmp and its caches when the daemon crashes.
            holder = start(repos[0], hold=True)
            assert holder.ready() == first
            kill_daemon(first["pid"])
            recovered = probe(repos[0], complete=True)
            assert recovered["namespace"] == first["namespace"]
            assert recovered["pid"] != first["pid"]
            holder.finish()
            kill_daemon(recovered["pid"])
            fresh = probe(repos[0])
            assert fresh["namespace"] != first["namespace"]
            print("PASS daemon crash recovery reuses a live sandbox; final exit allows a fresh sandbox")

            custom = probe(repos[2], flags=["--at", "/workspace"], complete=True)
            assert custom["cwd"] == "/workspace"
            assert probe(repos[2], complete=True) == custom
            keep = probe(repos[3], flags=["--keep-path"], complete=True)
            assert probe(repos[3], complete=True, shell=f'cd "{repos[3]}"; exec "$@"') == keep
            original = probe(repos[4], flags=["--at", str(repos[4])], complete=True)
            assert original["cwd"] == str(repos[4])
            assert probe(repos[4], complete=True) == original
            print("PASS first-launch mounts and keep-path symlinks reuse workspace and completion caches")
        finally:
            for client in clients:
                client.close()
            if host is not None:
                host.terminate()
                host.wait(timeout=10)
            children = Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()
            for pid in children:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            while True:
                try:
                    os.waitpid(-1, 0)
                except ChildProcessError:
                    break


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--inside":
        inside()
    else:
        main()
