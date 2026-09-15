#!/usr/bin/env python3
"""Listening sockets on this machine, for the Ports bar widget.

The panel runs `ports.py scan` on a timer and reads one JSON document: every
listener, grouped by the process or container that owns it. `signal` and
`stop` are the only two things it can do to a listener, and both re-check
their target immediately before acting.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

WILDCARDS = {"0.0.0.0", "::", "*"}

# Tailscale and NetBird both hand out addresses from the CGNAT block, and
# Tailscale's IPv6 sits under its own ULA prefix. A socket bound only there is
# reachable from the tailnet, not from whatever network the laptop is on.
OVERLAY_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),
)

# What usually sits on a port, for sockets ss cannot name — anything owned by
# root or another user, which as a normal user is most of them. The panel
# presents these as a guess, never as the owner.
WELL_KNOWN = {
    # Core network services
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "rpcbind",
    123: "NTP",
    137: "NetBIOS",
    139: "SMB (NetBIOS)",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    554: "RTSP",
    587: "SMTP submission",
    631: "CUPS",
    636: "LDAPS",
    853: "DNS over TLS",
    873: "rsync",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS proxy",
    1194: "OpenVPN",
    1900: "SSDP",
    2049: "NFS",
    3128: "Squid",
    3389: "RDP",
    3478: "STUN",
    5353: "mDNS",
    5355: "LLMNR",
    5900: "VNC",
    6000: "X11",
    9050: "Tor",
    9051: "Tor control",
    41641: "Tailscale",
    51820: "WireGuard",
    # Desktop
    1716: "KDE Connect",
    4713: "PulseAudio",
    5037: "ADB",
    24800: "Barrier",
    27036: "Steam",
    47990: "Sunshine",
    57621: "Spotify Connect",
    # Media and self-hosted
    1935: "RTMP",
    6881: "BitTorrent",
    7359: "Jellyfin discovery",
    7878: "Radarr",
    8096: "Jellyfin",
    8123: "Home Assistant",
    8384: "Syncthing",
    8686: "Lidarr",
    8920: "Jellyfin HTTPS",
    8989: "Sonarr",
    9091: "Transmission",
    9443: "Portainer",
    9696: "Prowlarr",
    10000: "Webmin",
    19999: "Netdata",
    21027: "Syncthing discovery",
    22000: "Syncthing",
    25565: "Minecraft",
    32400: "Plex",
    # Databases, queues and infrastructure
    1433: "SQL Server",
    1521: "Oracle DB",
    1883: "MQTT",
    2181: "ZooKeeper",
    2375: "Docker API",
    2376: "Docker API (TLS)",
    2379: "etcd",
    3306: "MySQL",
    4222: "NATS",
    4317: "OpenTelemetry",
    4318: "OpenTelemetry",
    5222: "XMPP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "RabbitMQ",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes API",
    6667: "IRC",
    7233: "Temporal",
    8086: "InfluxDB",
    8200: "Vault",
    8233: "Temporal UI",
    8500: "Consul",
    8883: "MQTT (TLS)",
    9042: "Cassandra",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    9418: "Git daemon",
    10250: "kubelet",
    11211: "Memcached",
    11434: "Ollama",
    15672: "RabbitMQ UI",
    27017: "MongoDB",
}

SCOPE_RANK = {"local": 0, "overlay": 1, "network": 2}

# Bounds on everything the panel reads. Command lines, paths and image names
# come from other programs, and so does the output of ss and docker, so none
# of them may grow what the helper holds or prints without limit.
MAX_TEXT = 512
MAX_LISTENERS = 512
MAX_CHILD_OUTPUT = 4 * 1024 * 1024

# One `("name",pid=N,fd=N)` entry from ss's users:(...) column. Names can hold
# spaces and escaped quotes, so this is matched against the whole line rather
# than a whitespace-split field.
USERS_ENTRY = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=(\d+),fd=\d+\)')


class ActionError(Exception):
    """A refusal or failure the panel shows to the user as-is."""


# ------------------------------------------------------------ parsing input

def truncate(text, limit: int = MAX_TEXT) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def parse_ignored(spec: str) -> set[int]:
    """"53, 631, 8000-8010" -> ports. Junk is skipped rather than fatal: this
    comes straight from a settings text field."""
    ignored: set[int] = set()
    for token in str(spec or "").split(","):
        token = token.strip()
        low, dash, high = token.partition("-")
        if not dash:
            if token.isdigit() and 1 <= int(token) <= 65535:
                ignored.add(int(token))
            continue
        if not (low.isdigit() and high.isdigit()):
            continue
        first, last = sorted((int(low), int(high)))
        ignored.update(range(max(first, 1), min(last, 65535) + 1))
    return ignored


def classify(address: str) -> str:
    """How far a bind address reaches: local, overlay (VPN only), or network.
    Anything that cannot be proven local is assumed to reach the network."""
    if address in WILDCARDS:
        return "network"
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "network"
    if ip.is_loopback:
        return "local"
    if any(ip in network for network in OVERLAY_NETWORKS):
        return "overlay"
    return "network"


def split_endpoint(text: str) -> tuple[str, int] | None:
    host, colon, port = text.rpartition(":")
    if not colon or not port.isdigit():
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    # ss appends the interface to link-scoped binds (127.0.0.53%lo).
    return host.split("%", 1)[0], int(port)


def parse_sockets(text: str, proto: str) -> list[dict]:
    """Rows of `ss -H -l -n -p` for one protocol. The local endpoint is always
    the fourth column; everything after the peer column is process info."""
    sockets = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        endpoint = split_endpoint(fields[3])
        if endpoint is None:
            continue
        address, port = endpoint
        processes = [{"name": name, "pid": int(pid)} for name, pid in USERS_ENTRY.findall(line)]
        sockets.append({"proto": proto, "address": address, "port": port, "processes": processes})
    return sockets


def container_ports(inspected: list[dict]) -> list[dict]:
    """Host bindings published by running containers, from `docker inspect`.
    Exposed-but-unpublished ports come through as null and are skipped."""
    published = []
    for container in inspected:
        if not (container.get("State") or {}).get("Running"):
            continue
        config = container.get("Config") or {}
        labels = config.get("Labels") or {}
        identity = {
            "id": str(container.get("Id", "")),
            "name": truncate(str(container.get("Name", "")).lstrip("/")),
            "image": truncate(config.get("Image", "")),
            "project": truncate(labels.get("com.docker.compose.project", "")),
            "service": truncate(labels.get("com.docker.compose.service", "")),
        }
        bindings_by_port = (container.get("NetworkSettings") or {}).get("Ports") or {}
        for spec, bindings in bindings_by_port.items():
            target, _, proto = spec.partition("/")
            for binding in bindings or []:
                host_port = str(binding.get("HostPort", ""))
                if not (target.isdigit() and host_port.isdigit()):
                    continue
                published.append({
                    "proto": proto or "tcp",
                    "port": int(host_port),
                    # An empty HostIp is docker's way of saying every address.
                    "address": binding.get("HostIp") or "0.0.0.0",
                    "containerPort": int(target),
                    "container": identity,
                })
    return published


# ----------------------------------------------------------------- grouping

def process_owner(name: str, pid: int, details: dict | None) -> dict:
    # A process that exits between ss and /proc has no details; it is shown,
    # but as read-only, since there is nothing left to verify a signal against.
    details = details or {}
    return {
        "kind": "process",
        "name": truncate(name),
        "pid": pid,
        "owned": bool(details.get("owned")),
        "start": int(details.get("start") or 0),
        "command": truncate(details.get("command", "")),
        "cwd": truncate(details.get("cwd", "")),
    }


def listener_url(proto: str, port: int, addresses: list[str]) -> str | None:
    if proto != "tcp":
        return None
    # Reachable on loopback means localhost works, whatever else it binds.
    if any(address in WILDCARDS or classify(address) == "local" for address in addresses):
        host = "localhost"
    else:
        host = addresses[0]
        if ":" in host:
            host = f"[{host}]"
    return f"http://{host}:{port}"


def build_listeners(sockets: list[dict], containers: list[dict], describe, ignored: set[int]) -> list[dict]:
    """Sockets and container bindings -> one listener per owner per port.

    Grouping by owner rather than by address is what folds the IPv4 and IPv6
    halves of a dual-stack bind into one row, while two different processes
    that happen to share a port number stay apart.
    """
    groups: dict[tuple, dict] = {}

    def group(key: tuple, proto: str, port: int) -> dict:
        if key not in groups:
            groups[key] = {"proto": proto, "port": port, "addresses": [], "owner": None}
        return groups[key]

    def add_address(entry: dict, address: str) -> None:
        if address not in entry["addresses"]:
            entry["addresses"].append(address)

    for sock in sockets:
        if sock["port"] in ignored:
            continue
        # Forked servers share one socket across every worker; the lowest pid
        # is the one that opened it, and the one worth signalling.
        pids = sorted(process["pid"] for process in sock["processes"])
        owner_pid = pids[0] if pids else None
        entry = group((sock["proto"], sock["port"], "pid", owner_pid), sock["proto"], sock["port"])
        add_address(entry, sock["address"])
        if owner_pid is not None and entry["owner"] is None:
            name = next(p["name"] for p in sock["processes"] if p["pid"] == owner_pid)
            entry["owner"] = process_owner(name, owner_pid, describe(owner_pid))

    for binding in containers:
        proto, port = binding["proto"], binding["port"]
        if port in ignored:
            continue
        # docker-proxy runs as root, so its host socket reaches us unnamed.
        # The container that published the port is its real owner.
        anonymous = groups.pop((proto, port, "pid", None), None)
        container = binding["container"]
        key = (proto, port, "container", container["id"])
        entry = groups.get(key)
        if entry is None:
            entry = group(key, proto, port)
            entry["owner"] = {"kind": "container", **container, "containerPort": binding["containerPort"]}
        for address in (anonymous or {}).get("addresses", []):
            add_address(entry, address)
        add_address(entry, binding["address"])

    listeners = []
    for key, entry in groups.items():
        owner = entry["owner"] or {"kind": "unknown", "guess": WELL_KNOWN.get(entry["port"])}
        url = listener_url(entry["proto"], entry["port"], entry["addresses"])
        actions = ["open", "copy"] if url else []
        if owner["kind"] == "container":
            actions.append("stop")
        if owner["kind"] == "process" and owner["owned"] and owner["start"] > 0:
            actions += ["terminate", "kill"]
        listeners.append({
            "key": ":".join(str(part) for part in key),
            "proto": entry["proto"],
            "port": entry["port"],
            "addresses": entry["addresses"],
            "scope": max((classify(a) for a in entry["addresses"]), key=SCOPE_RANK.__getitem__),
            "url": url,
            "owner": owner,
            "actions": actions,
        })
    listeners.sort(key=lambda listener: (listener["port"], listener["proto"]))
    return listeners


# ------------------------------------------------------------------ actions

SIGNALS = {"term": signal.SIGTERM, "kill": signal.SIGKILL}
CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}")


class OutputTooLarge(subprocess.SubprocessError):
    """A child printed more than run_bounded agreed to read."""

    def __init__(self, argv: list[str], limit: int):
        super().__init__(f"{argv[0]} printed more than {limit} bytes")
        self.argv = argv
        self.limit = limit


def run_bounded(argv, *, timeout: float, limit: int = MAX_CHILD_OUTPUT, **_ignored) -> subprocess.CompletedProcess:
    """subprocess.run for children whose output size is not ours to trust.

    stdout and stderr are read together, up to `limit` bytes and within
    `timeout` seconds; the child is killed the moment either is exceeded
    rather than buffered or waited on. Extra keyword arguments are accepted so
    this stands in for subprocess.run(capture_output=True, text=True, ...).
    """
    argv = list(argv)
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    received = {process.stdout: bytearray(), process.stderr: bytearray()}
    total = 0
    try:
        with selectors.DefaultSelector() as selector:
            for stream in received:
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > limit:
                        raise OutputTooLarge(argv, limit)
                    received[key.fileobj] += chunk
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
        process.stderr.close()
    return subprocess.CompletedProcess(argv, returncode,
                                       received[process.stdout].decode(errors="replace"),
                                       received[process.stderr].decode(errors="replace"))


def limit_listeners(listeners: list[dict], warnings: list[str], limit: int = MAX_LISTENERS) -> list[dict]:
    """Keeps the first `limit` listeners of the port-sorted list and says how
    many were left out."""
    if len(listeners) <= limit:
        return listeners
    warnings.append(f"Showing the first {limit} of {len(listeners)} listeners")
    return listeners[:limit]


def last_line(text: str) -> str:
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    return lines[-1][:240] if lines else ""


def read_start_time(proc_dir: Path) -> int:
    raw = (proc_dir / "stat").read_text()
    # The command name (field 2) is parenthesised and may itself contain
    # spaces or ')', so fields are counted from the last closing paren.
    # starttime is field 22: the 20th after it.
    return int(raw[raw.rindex(")") + 2:].split()[19])


def blank_on_error(read) -> str:
    try:
        return read()
    except OSError:
        return ""


def describe_process(pid: int, proc_root: str = "/proc") -> dict | None:
    """Owner, start time, command line and working directory of a pid, or
    None once it has exited. Another user's cwd is unreadable and comes back
    blank; the rest of /proc/<pid> stays world-readable."""
    proc_dir = Path(proc_root) / str(pid)
    try:
        uid = proc_dir.stat().st_uid
        start = read_start_time(proc_dir)
    except (OSError, ValueError, IndexError):
        return None
    return {
        "owned": uid == os.geteuid(),
        "start": start,
        "command": blank_on_error(lambda: " ".join(
            part.decode(errors="replace")
            for part in (proc_dir / "cmdline").read_bytes().split(b"\0") if part)),
        "cwd": blank_on_error(lambda: os.readlink(proc_dir / "cwd")),
    }


def signal_process(pid: int, start: int, signal_name: str) -> None:
    """SIGTERM or SIGKILL a pid, but only while it is still the process the
    panel listed: owned by this user and started at the same instant."""
    sig = SIGNALS.get(signal_name)
    if sig is None:
        raise ActionError(f"Unknown signal {signal_name!r}")
    if pid <= 1:
        raise ActionError("Refusing to signal init")
    # Open the pidfd before verifying, not after. The kernel pins the fd to
    # whichever process held the pid when it was opened, so once the checks
    # below pass, the signal cannot land on something that reused the pid in
    # the meantime. Checking and then signalling by pid leaves that window.
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        raise ActionError(f"PID {pid} has already exited") from None
    except OSError as error:
        raise ActionError(f"Could not open PID {pid}: {error.strerror}") from None
    try:
        details = describe_process(pid)
        if details is None:
            raise ActionError(f"PID {pid} has already exited")
        if not details["owned"]:
            raise ActionError(f"PID {pid} belongs to another user")
        if details["start"] != start:
            raise ActionError(f"PID {pid} is a different process now. Refresh and try again.")
        try:
            signal.pidfd_send_signal(pidfd, sig)
        except ProcessLookupError:
            raise ActionError(f"PID {pid} has already exited") from None
        except PermissionError:
            raise ActionError(f"Not allowed to signal PID {pid}") from None
    finally:
        os.close(pidfd)


def docker(run, args: list[str], timeout: float = 10) -> str:
    try:
        result = run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise ActionError("Docker is not installed") from None
    except OSError as error:
        raise ActionError(f"Could not run docker: {error.strerror or error}") from None
    except OutputTooLarge:
        raise ActionError(f"docker {args[0]} printed too much output") from None
    except subprocess.TimeoutExpired:
        raise ActionError(f"docker {args[0]} timed out") from None
    if result.returncode != 0:
        raise ActionError(last_line(result.stderr) or f"docker {args[0]} failed")
    return result.stdout


def stop_container(container_id: str, run=run_bounded) -> None:
    # The id reaches docker as one argv entry, never through a shell, but it
    # is still checked: the panel should only ever pass back what inspect gave.
    if not CONTAINER_ID.fullmatch(str(container_id or "")):
        raise ActionError("Not a Docker container id")
    if docker(run, ["inspect", "--format", "{{.State.Running}}", container_id]).strip() != "true":
        raise ActionError("That container is no longer running")
    docker(run, ["stop", container_id], timeout=30)


def running_containers(run=run_bounded) -> list[dict]:
    # Only tokens shaped like container ids go back to docker: anything else
    # on stdout (a warning, a misbehaving plugin) must not become arguments.
    ids = [token for token in docker(run, ["ps", "--quiet", "--no-trunc"]).split()
           if CONTAINER_ID.fullmatch(token)]
    if not ids:
        return []
    try:
        return json.loads(docker(run, ["inspect", *ids]))
    except json.JSONDecodeError:
        raise ActionError("docker inspect printed something unreadable") from None


# --------------------------------------------------------------------- scan

def listening_sockets(include_udp: bool, warnings: list[str]) -> list[dict]:
    sockets: list[dict] = []
    for proto in ("tcp", "udp") if include_udp else ("tcp",):
        try:
            result = run_bounded(["ss", "-H", "-l", "-n", "-p", f"--{proto}"], timeout=5)
        except OutputTooLarge:
            warnings.append(f"ss printed too much output for {proto.upper()}")
            continue
        except (OSError, subprocess.TimeoutExpired) as error:
            warnings.append(f"Could not run ss: {error}")
            continue
        if result.returncode != 0:
            warnings.append(last_line(result.stderr) or f"ss exited with status {result.returncode}")
            continue
        sockets += parse_sockets(result.stdout, proto)
    return sockets


def scan(include_udp: bool, include_docker: bool, ignored: set[int]) -> dict:
    warnings: list[str] = []
    sockets = listening_sockets(include_udp, warnings)
    containers: list[dict] = []
    # No docker binary means a machine without docker, which says nothing. A
    # docker that is installed but unreachable is worth a line in the panel.
    if include_docker and shutil.which("docker"):
        try:
            containers = container_ports(running_containers())
        except ActionError as error:
            warnings.append(f"Docker: {error}")
    return {
        "scannedAt": int(time.time()),
        "listeners": limit_listeners(build_listeners(sockets, containers, describe_process, ignored), warnings),
        "warnings": warnings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ports.py", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    scan_command = commands.add_parser("scan", help="print every listener as JSON")
    scan_command.add_argument("--udp", action="store_true", help="include UDP sockets")
    scan_command.add_argument("--no-docker", action="store_true", help="skip published container ports")
    scan_command.add_argument("--ignore", default="", help='ports to leave out, e.g. "53,631,8000-8010"')

    signal_command = commands.add_parser("signal", help="terminate or kill a verified process")
    signal_command.add_argument("--pid", type=int, required=True)
    signal_command.add_argument("--start", type=int, required=True,
                                help="start time from scan; proves it is still the same process")
    signal_command.add_argument("--signal", choices=sorted(SIGNALS), default="term")

    stop_command = commands.add_parser("stop", help="stop a running container")
    stop_command.add_argument("--container", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            payload = scan(args.udp, not args.no_docker, parse_ignored(args.ignore))
        elif args.command == "signal":
            signal_process(args.pid, args.start, args.signal)
            payload = {"ok": True}
        else:
            stop_container(args.container)
            payload = {"ok": True}
    except ActionError as error:
        print(json.dumps({"error": str(error)}))
        return 1
    print(json.dumps(payload, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
