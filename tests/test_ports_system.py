"""Ports collector against real processes, the real ss, and a stand-in docker."""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"
sys.path.insert(0, str(BIN))

import ports  # noqa: E402

PORTS = str(BIN / "ports.py")
REDIS_ID = "496909168eb86ef27f24d6c813d55e02bf3b6c3dcc742a671fadf93452f8365b"

TCP_LISTENER = (
    "import socket, time\n"
    "s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen()\n"
    "print(s.getsockname()[1], flush=True)\n"
    "time.sleep(60)\n"
)

UDP_LISTENER = (
    "import socket, time\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 0))\n"
    "print(s.getsockname()[1], flush=True)\n"
    "time.sleep(60)\n"
)


def exited_within(child, seconds):
    try:
        child.wait(timeout=seconds)
        return True
    except subprocess.TimeoutExpired:
        return False


def exited_pid():
    child = subprocess.Popen(["true"])
    child.wait()
    return child.pid


class ChildProcessCase(unittest.TestCase):
    """Spawns processes this user owns and always reaps them."""

    def spawn(self, code="import time; time.sleep(60)", cwd=None):
        child = subprocess.Popen([sys.executable, "-c", code], cwd=cwd,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.addCleanup(self.reap, child)
        return child

    @staticmethod
    def reap(child):
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()


class DescribeProcessTests(ChildProcessCase):
    def test_own_child_is_described(self):
        with tempfile.TemporaryDirectory() as workdir:
            child = self.spawn(cwd=workdir)
            details = ports.describe_process(child.pid)
            self.assertIsNotNone(details)
            self.assertTrue(details["owned"])
            self.assertGreater(details["start"], 0)
            self.assertIn("time.sleep(60)", details["command"])
            self.assertEqual(details["cwd"], os.path.realpath(workdir))

    def test_process_of_another_user_is_not_owned(self):
        details = ports.describe_process(1)
        self.assertIsNotNone(details)
        self.assertFalse(details["owned"])

    def test_exited_process_is_not_described(self):
        self.assertIsNone(ports.describe_process(exited_pid()))


class SignalProcessTests(ChildProcessCase):
    def start_of(self, child):
        details = ports.describe_process(child.pid)
        self.assertIsNotNone(details, "child could not be described")
        return details["start"]

    def test_matching_identity_is_terminated(self):
        child = self.spawn()
        ports.signal_process(child.pid, self.start_of(child), "term")
        self.assertTrue(exited_within(child, 5))
        self.assertEqual(child.returncode, -signal.SIGTERM)

    def test_kill_sends_sigkill(self):
        child = self.spawn()
        ports.signal_process(child.pid, self.start_of(child), "kill")
        self.assertTrue(exited_within(child, 5))
        self.assertEqual(child.returncode, -signal.SIGKILL)

    def test_stale_start_time_is_refused_and_process_survives(self):
        child = self.spawn()
        with self.assertRaises(ports.ActionError):
            ports.signal_process(child.pid, self.start_of(child) + 1, "term")
        self.assertFalse(exited_within(child, 0.3))

    def test_unknown_signal_is_refused_and_process_survives(self):
        child = self.spawn()
        with self.assertRaises(ports.ActionError):
            ports.signal_process(child.pid, self.start_of(child), "hup")
        self.assertFalse(exited_within(child, 0.3))

    @unittest.skipIf(os.geteuid() == 0, "as root this would really signal init")
    def test_process_of_another_user_is_refused(self):
        with self.assertRaises(ports.ActionError):
            ports.signal_process(1, ports.describe_process(1)["start"], "term")

    def test_exited_process_is_refused(self):
        with self.assertRaises(ports.ActionError):
            ports.signal_process(exited_pid(), 1, "term")


class FakeDocker:
    """Stands in for subprocess.run: answers each docker subcommand from a
    script and records every argv it was handed."""

    def __init__(self, replies):
        self.replies = replies
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        code, out, err = self.replies.get(argv[1], (1, "", "unexpected docker call"))
        return subprocess.CompletedProcess(argv, code, out, err)


INSPECT_RUNNING = ["docker", "inspect", "--format", "{{.State.Running}}", REDIS_ID]


class StopContainerTests(unittest.TestCase):
    def test_malformed_ids_never_reach_docker(self):
        for bad in ("", "abc", "postgres; rm -rf /", "g" * 64, REDIS_ID[:11]):
            docker = FakeDocker({"inspect": (0, "true\n", ""), "stop": (0, "", "")})
            with self.assertRaises(ports.ActionError, msg=bad):
                ports.stop_container(bad, run=docker)
            self.assertEqual(docker.calls, [], bad)

    def test_container_that_is_not_running_is_not_stopped(self):
        docker = FakeDocker({"inspect": (0, "false\n", "")})
        with self.assertRaises(ports.ActionError):
            ports.stop_container(REDIS_ID, run=docker)
        self.assertEqual(docker.calls, [INSPECT_RUNNING])

    def test_running_container_is_stopped(self):
        docker = FakeDocker({"inspect": (0, "true\n", ""), "stop": (0, REDIS_ID + "\n", "")})
        ports.stop_container(REDIS_ID, run=docker)
        self.assertEqual(docker.calls, [INSPECT_RUNNING, ["docker", "stop", REDIS_ID]])

    def test_docker_refusing_to_stop_is_an_action_error(self):
        docker = FakeDocker({"inspect": (0, "true\n", ""),
                             "stop": (1, "", "Error response from daemon: permission denied")})
        with self.assertRaises(ports.ActionError):
            ports.stop_container(REDIS_ID, run=docker)


class CliTests(ChildProcessCase):
    def run_cli(self, *args, env=None):
        result = subprocess.run([sys.executable, PORTS, *map(str, args)],
                                capture_output=True, text=True, timeout=20, env=env)
        self.assertTrue(result.stdout.strip(), f"no JSON on stdout; stderr: {result.stderr!r}")
        return result.returncode, json.loads(result.stdout)

    def listening(self, code=TCP_LISTENER):
        child = self.spawn(code)
        return child, int(child.stdout.readline())

    def test_scan_reports_a_listening_child(self):
        child, port = self.listening()
        code, payload = self.run_cli("scan", "--no-docker")
        self.assertEqual(code, 0)
        matches = [l for l in payload["listeners"] if l["port"] == port]
        self.assertEqual(len(matches), 1, payload)
        listener = matches[0]
        self.assertEqual(listener["owner"]["kind"], "process")
        self.assertEqual(listener["owner"]["pid"], child.pid)
        self.assertTrue(listener["owner"]["owned"])
        self.assertEqual(listener["scope"], "local")
        self.assertEqual(listener["url"], f"http://localhost:{port}")
        self.assertIn("terminate", listener["actions"])

    def test_ignored_port_is_left_out(self):
        _, port = self.listening()
        _, payload = self.run_cli("scan", "--no-docker", "--ignore", f"1-2,{port}")
        self.assertNotIn(port, [l["port"] for l in payload["listeners"]])

    def test_udp_is_only_scanned_when_asked(self):
        _, port = self.listening(UDP_LISTENER)
        _, without = self.run_cli("scan", "--no-docker")
        _, with_udp = self.run_cli("scan", "--no-docker", "--udp")
        self.assertNotIn(port, [l["port"] for l in without["listeners"]])
        self.assertIn((port, "udp"), [(l["port"], l["proto"]) for l in with_udp["listeners"]])

    def test_signal_command_terminates_a_scanned_listener(self):
        child, port = self.listening()
        _, payload = self.run_cli("scan", "--no-docker")
        [listener] = [l for l in payload["listeners"] if l["port"] == port]
        code, result = self.run_cli("signal", "--pid", child.pid,
                                    "--start", listener["owner"]["start"], "--signal", "term")
        self.assertEqual((code, result), (0, {"ok": True}))
        self.assertTrue(exited_within(child, 5))

    def test_signal_command_reports_a_refusal_as_json(self):
        child, _ = self.listening()
        code, result = self.run_cli("signal", "--pid", child.pid, "--start", 1, "--signal", "term")
        self.assertEqual(code, 1)
        self.assertIsInstance(result.get("error"), str)
        self.assertTrue(result["error"])
        self.assertFalse(exited_within(child, 0.3))

    def fake_path(self, docker_script=None):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        os.symlink(shutil.which("ss"), os.path.join(directory, "ss"))
        if docker_script is not None:
            docker = Path(directory, "docker")
            docker.write_text(docker_script)
            docker.chmod(0o755)
        return dict(os.environ, PATH=directory)

    def test_unreachable_docker_is_a_warning_and_sockets_still_list(self):
        _, port = self.listening()
        env = self.fake_path("#!/bin/sh\necho 'Cannot connect to the Docker daemon' >&2\nexit 1\n")
        code, payload = self.run_cli("scan", env=env)
        self.assertEqual(code, 0)
        self.assertTrue(any("Cannot connect to the Docker daemon" in w for w in payload["warnings"]), payload)
        self.assertIn(port, [l["port"] for l in payload["listeners"]])

    def test_machine_without_docker_scans_quietly(self):
        _, port = self.listening()
        code, payload = self.run_cli("scan", env=self.fake_path())
        self.assertEqual(code, 0)
        self.assertEqual(payload["warnings"], [])
        self.assertIn(port, [l["port"] for l in payload["listeners"]])


    def test_runaway_docker_output_is_a_warning_and_sockets_still_list(self):
        _, port = self.listening()
        env = self.fake_path("#!/usr/bin/python3\nimport sys\nsys.stdout.write('x' * 6_000_000)\n")
        code, payload = self.run_cli("scan", env=env)
        self.assertEqual(code, 0)
        self.assertTrue(any("too much output" in w for w in payload["warnings"]), payload["warnings"])
        self.assertIn(port, [l["port"] for l in payload["listeners"]])


    def test_docker_ps_noise_never_reaches_inspect(self):
        _, port = self.listening()
        real_id = "c" * 64
        script = (
            "#!/usr/bin/python3\n"
            "import sys\n"
            "if sys.argv[1] == 'ps':\n"
            "    print('WARNING: not a container id')\n"
            f"    print('{real_id}')\n"
            "    sys.exit(0)\n"
            "if sys.argv[1] == 'inspect':\n"
            "    if sys.argv[2:] != ['" + real_id + "']:\n"
            "        sys.stderr.write('inspect was handed ' + ' '.join(sys.argv[2:]) + '\\n')\n"
            "        sys.exit(1)\n"
            "    print('[]')\n"
            "    sys.exit(0)\n"
            "sys.exit(1)\n"
        )
        code, payload = self.run_cli("scan", env=self.fake_path(script))
        self.assertEqual(code, 0)
        self.assertEqual(payload["warnings"], [])
        self.assertIn(port, [l["port"] for l in payload["listeners"]])

class RunBoundedTests(unittest.TestCase):
    """ss and docker are read through run_bounded: a child that talks too much
    or runs too long is killed rather than buffered or waited on."""

    def test_small_output_comes_back_like_subprocess_run(self):
        result = ports.run_bounded(
            [sys.executable, "-c", "import sys; print('hi'); sys.stderr.write('err'); sys.exit(3)"],
            timeout=5, limit=1024)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (3, "hi\n", "err"))

    def test_output_over_the_limit_kills_the_child_early(self):
        started = time.monotonic()
        with self.assertRaises(ports.OutputTooLarge):
            ports.run_bounded(
                [sys.executable, "-c", "import sys, time; sys.stdout.write('x' * 1_000_000); sys.stdout.flush(); time.sleep(4)"],
                timeout=3, limit=100_000)
        self.assertLess(time.monotonic() - started, 2.5)

    def test_silent_child_past_its_deadline_is_killed(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            ports.run_bounded([sys.executable, "-c", "import time; time.sleep(4)"], timeout=0.5, limit=1024)
        self.assertLess(time.monotonic() - started, 2.5)

if __name__ == "__main__":
    unittest.main()
