"""Behaviour of the Ports collector: turning ss and docker output into listeners."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bin"))

import ports  # noqa: E402


# Captured from `ss -H -ltnp` as a normal user. Sockets owned by root or by
# another user carry no users:() field; the user's own sockets do. Process
# names can contain spaces, and a socket inherited by forked workers lists
# every process holding it.
SS_TCP = """\
LISTEN 0      4096                       0.0.0.0:6379  0.0.0.0:*
LISTEN 0      4096                 127.0.0.53%lo:53    0.0.0.0:*
LISTEN 0      4096   [fd7a:115c:a1e0::6c01:74c1]:65009    [::]:*
LISTEN 0      128                          [::1]:51725    [::]:* users:(("python3",pid=112443,fd=6))
LISTEN 0      511                        0.0.0.0:8080  0.0.0.0:* users:(("nginx",pid=911,fd=6),("nginx",pid=907,fd=6))
LISTEN 0      128                      127.0.0.1:3000  0.0.0.0:* users:(("Web Content",pid=5150,fd=41))

not a socket line
"""

SS_UDP = """\
UNCONN 0      0                             127.0.0.1:57983 0.0.0.0:* users:(("python3",pid=112443,fd=7))
UNCONN 0      0                                     *:5353        *:*
"""

POSTGRES_ID = "cf700d1b5f1e09c6859c55e74ad917fccb629810d60b67264fae300bb22e4a5b"
REDIS_ID = "496909168eb86ef27f24d6c813d55e02bf3b6c3dcc742a671fadf93452f8365b"
WEB_ID = "7d3c9a" + "0" * 58

# The fields `docker inspect` returns that the collector reads, shaped as
# docker 29 prints them: bindings per "port/proto", null for exposed-only
# ports, an empty HostIp meaning every address.
DOCKER_INSPECT = [
    {
        "Id": POSTGRES_ID,
        "Name": "/postgres",
        "Config": {
            "Image": "postgres:18",
            "Labels": {
                "com.docker.compose.project": "shop",
                "com.docker.compose.service": "postgres",
                "com.docker.compose.project.working_dir": "/home/alice/src/shop",
            },
        },
        "State": {"Running": True, "Status": "running"},
        "NetworkSettings": {
            "Ports": {
                "5432/tcp": [
                    {"HostIp": "0.0.0.0", "HostPort": "5432"},
                    {"HostIp": "::", "HostPort": "5432"},
                ]
            }
        },
    },
    {
        "Id": WEB_ID,
        "Name": "/scratch-web",
        "Config": {"Image": "nginx:alpine", "Labels": None},
        "State": {"Running": True, "Status": "running"},
        "NetworkSettings": {
            "Ports": {
                "80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8088"}],
                "443/tcp": None,
                "5353/udp": [{"HostIp": "", "HostPort": "5354"}],
            }
        },
    },
    {
        "Id": "0e" + "1" * 62,
        "Name": "/stopped",
        "Config": {"Image": "busybox", "Labels": {}},
        "State": {"Running": False, "Status": "exited"},
        "NetworkSettings": {"Ports": {"9000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "9000"}]}},
    },
]


class IgnoredPortsTests(unittest.TestCase):
    def test_single_ports_and_ranges(self):
        self.assertEqual(ports.parse_ignored("53, 631, 8000-8002"), {53, 631, 8000, 8001, 8002})

    def test_reversed_range_is_read_low_to_high(self):
        self.assertEqual(ports.parse_ignored("9002-9000"), {9000, 9001, 9002})

    def test_ranges_are_clamped_to_real_ports(self):
        self.assertEqual(ports.parse_ignored("65534-70000"), {65534, 65535})
        self.assertEqual(ports.parse_ignored("0-2"), {1, 2})

    def test_junk_is_skipped(self):
        self.assertEqual(ports.parse_ignored("abc, 0, 70000, -5, 7-, ,"), set())
        self.assertEqual(ports.parse_ignored(""), set())


class ClassifyTests(unittest.TestCase):
    def test_loopback_is_local(self):
        for address in ("127.0.0.1", "127.0.0.53", "::1"):
            self.assertEqual(ports.classify(address), "local", address)

    def test_tailscale_and_netbird_ranges_are_overlay(self):
        for address in ("100.64.0.1", "100.90.0.14", "100.127.255.255", "fd7a:115c:a1e0::6c01:74c1"):
            self.assertEqual(ports.classify(address), "overlay", address)

    def test_wildcards_and_everything_else_are_network(self):
        for address in ("0.0.0.0", "::", "*", "192.168.1.8", "172.17.0.1",
                        "100.63.255.255", "100.128.0.0", "fd00::1", "example.local"):
            self.assertEqual(ports.classify(address), "network", address)


class WireGuardTests(unittest.TestCase):
    def test_vpn_addresses_are_overlay(self):
        vpn = frozenset({"10.0.0.7", "fd00::7"})
        self.assertEqual(ports.classify("10.0.0.7", vpn), "overlay")
        self.assertEqual(ports.classify("fd00::7", vpn), "overlay")
        # Other private addresses still reach the network.
        self.assertEqual(ports.classify("10.0.0.8", vpn), "network")
        self.assertEqual(ports.classify("0.0.0.0", vpn), "network")
        self.assertEqual(ports.classify("127.0.0.1", vpn), "local")

    def test_parse_interface_addresses(self):
        text = ('[{"ifname":"wg0","addr_info":[{"family":"inet","local":"10.0.0.7","prefixlen":32},'
                '{"family":"inet6","local":"fd00::7","prefixlen":128},{"local":"junk"}]}]')
        self.assertEqual(ports.parse_interface_addresses(text), {"10.0.0.7", "fd00::7"})
        for junk in ("", "not json", "{}", '[{"addr_info": "x"}]', "[1]"):
            self.assertEqual(ports.parse_interface_addresses(junk), set(), junk)

    def test_wireguard_interfaces_from_uevent(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            for name, uevent in (("wg0", "DEVTYPE=wireguard\nINTERFACE=wg0\n"),
                                 ("wlan0", "DEVTYPE=wlan\nINTERFACE=wlan0\n"),
                                 ("eth0", "INTERFACE=eth0\n")):
                Path(root, name).mkdir()
                Path(root, name, "uevent").write_text(uevent)
            Path(root, "broken").mkdir()  # no uevent
            self.assertEqual(ports.wireguard_interfaces(root), ["wg0"])

            calls = []

            def run(argv, timeout):
                calls.append(argv)
                return ports.subprocess.CompletedProcess(
                    argv, 0, '[{"addr_info":[{"local":"10.0.0.7"}]}]', "")

            self.assertEqual(ports.wireguard_addresses(root, run), frozenset({"10.0.0.7"}))
            self.assertEqual(calls, [["ip", "-j", "addr", "show", "dev", "wg0"]])

    def test_build_listeners_scope_uses_vpn_addresses(self):
        def describe(pid):
            return None
        socks = [sock(a, 22) for a in ("10.0.0.7", "127.0.0.1", "::1")]
        [listener] = ports.build_listeners(socks, [], describe, set(), frozenset({"10.0.0.7"}))
        self.assertEqual(listener["scope"], "overlay")
        [listener] = ports.build_listeners(socks, [], describe, set())
        self.assertEqual(listener["scope"], "network")


class ParseSocketsTests(unittest.TestCase):
    def test_tcp_rows(self):
        self.assertEqual(ports.parse_sockets(SS_TCP, "tcp"), [
            {"proto": "tcp", "address": "0.0.0.0", "port": 6379, "processes": []},
            {"proto": "tcp", "address": "127.0.0.53", "port": 53, "processes": []},
            {"proto": "tcp", "address": "fd7a:115c:a1e0::6c01:74c1", "port": 65009, "processes": []},
            {"proto": "tcp", "address": "::1", "port": 51725,
             "processes": [{"name": "python3", "pid": 112443}]},
            {"proto": "tcp", "address": "0.0.0.0", "port": 8080,
             "processes": [{"name": "nginx", "pid": 911}, {"name": "nginx", "pid": 907}]},
            {"proto": "tcp", "address": "127.0.0.1", "port": 3000,
             "processes": [{"name": "Web Content", "pid": 5150}]},
        ])

    def test_udp_rows_including_star_address(self):
        self.assertEqual(ports.parse_sockets(SS_UDP, "udp"), [
            {"proto": "udp", "address": "127.0.0.1", "port": 57983,
             "processes": [{"name": "python3", "pid": 112443}]},
            {"proto": "udp", "address": "*", "port": 5353, "processes": []},
        ])


class ContainerPortsTests(unittest.TestCase):
    def test_published_bindings_of_running_containers(self):
        postgres = {"id": POSTGRES_ID, "name": "postgres", "image": "postgres:18",
                    "project": "shop", "service": "postgres"}
        web = {"id": WEB_ID, "name": "scratch-web", "image": "nginx:alpine",
               "project": "", "service": ""}
        self.assertEqual(ports.container_ports(DOCKER_INSPECT), [
            {"proto": "tcp", "port": 5432, "address": "0.0.0.0", "containerPort": 5432, "container": postgres},
            {"proto": "tcp", "port": 5432, "address": "::", "containerPort": 5432, "container": postgres},
            {"proto": "tcp", "port": 8088, "address": "127.0.0.1", "containerPort": 80, "container": web},
            {"proto": "udp", "port": 5354, "address": "0.0.0.0", "containerPort": 5353, "container": web},
        ])


# ------------------------------------------------------------------ grouping

SELF = {"owned": True, "start": 227621, "command": "python3 -m http.server 42635", "cwd": "/home/alice/code/site"}
PROCESSES = {
    112443: SELF,
    4242: {"owned": False, "start": 900, "command": "/usr/bin/prometheus", "cwd": "/"},
    5150: {"owned": True, "start": 0, "command": "", "cwd": ""},
    907: {"owned": True, "start": 50, "command": "nginx: master process", "cwd": "/"},
    911: {"owned": True, "start": 51, "command": "nginx: worker process", "cwd": "/"},
}


def describe(pid):
    return PROCESSES.get(pid)


def sock(address, port, proto="tcp", *procs):
    return {"proto": proto, "address": address, "port": port,
            "processes": [{"name": name, "pid": pid} for name, pid in procs]}


def published(address, port, *, name="redis", cid=REDIS_ID, image="redis:7", container_port=None,
              project="shop", service="redis", proto="tcp"):
    return {"proto": proto, "port": port, "address": address,
            "containerPort": port if container_port is None else container_port,
            "container": {"id": cid, "name": name, "image": image, "project": project, "service": service}}


def build(sockets, containers=(), ignored=frozenset()):
    return ports.build_listeners(list(sockets), list(containers), describe, set(ignored))


def without_key(listener):
    return {k: v for k, v in listener.items() if k != "key"}


class BuildListenersTests(unittest.TestCase):
    def test_dual_stack_sockets_of_one_process_become_one_listener(self):
        listeners = build([sock("0.0.0.0", 42635, "tcp", ("python3", 112443)),
                           sock("::", 42635, "tcp", ("python3", 112443))])
        self.assertEqual([without_key(l) for l in listeners], [{
            "proto": "tcp", "port": 42635, "addresses": ["0.0.0.0", "::"],
            "scope": "network", "url": "http://localhost:42635",
            "owner": {"kind": "process", "name": "python3", "pid": 112443, "owned": True,
                      "start": 227621, "command": "python3 -m http.server 42635",
                      "cwd": "/home/alice/code/site"},
            "actions": ["open", "copy", "terminate", "kill"],
        }])

    def test_different_processes_on_one_port_stay_separate(self):
        listeners = build([sock("127.0.0.1", 8000, "tcp", ("python3", 112443)),
                           sock("::1", 8000, "tcp", ("prometheus", 4242))])
        self.assertEqual(sorted(l["owner"]["pid"] for l in listeners), [4242, 112443])
        self.assertEqual(len({l["key"] for l in listeners}), 2)

    def test_socket_shared_by_forked_workers_belongs_to_lowest_pid(self):
        [listener] = build([sock("0.0.0.0", 8080, "tcp", ("nginx", 911), ("nginx", 907))])
        self.assertEqual(listener["owner"]["pid"], 907)
        self.assertEqual(listener["owner"]["command"], "nginx: master process")

    def test_published_container_claims_the_anonymous_host_sockets(self):
        listeners = build([sock("0.0.0.0", 6379), sock("::", 6379)],
                          [published("0.0.0.0", 6379), published("::", 6379)])
        self.assertEqual([without_key(l) for l in listeners], [{
            "proto": "tcp", "port": 6379, "addresses": ["0.0.0.0", "::"],
            "scope": "network", "url": "http://localhost:6379",
            "owner": {"kind": "container", "name": "redis", "id": REDIS_ID, "image": "redis:7",
                      "project": "shop", "service": "redis", "containerPort": 6379},
            "actions": ["open", "copy", "stop"],
        }])

    def test_container_without_a_visible_host_socket_is_still_listed(self):
        listeners = build([], [published("127.0.0.1", 8088, name="scratch-web", cid=WEB_ID,
                                         image="nginx:alpine", container_port=80,
                                         project="", service="")])
        self.assertEqual([without_key(l) for l in listeners], [{
            "proto": "tcp", "port": 8088, "addresses": ["127.0.0.1"],
            "scope": "local", "url": "http://localhost:8088",
            "owner": {"kind": "container", "name": "scratch-web", "id": WEB_ID, "image": "nginx:alpine",
                      "project": "", "service": "", "containerPort": 80},
            "actions": ["open", "copy", "stop"],
        }])

    def test_unknown_owner_on_a_well_known_port_gets_a_guess(self):
        [listener] = build([sock("0.0.0.0", 8096)])
        self.assertEqual(listener["owner"], {"kind": "unknown", "guess": "Jellyfin"})
        self.assertEqual(listener["actions"], ["open", "copy"])

    def test_hidden_sockets_on_popular_service_ports_get_guesses(self):
        # One from each kind of service the table covers: file sharing,
        # desktop, name resolution, queues, sync, search, media, VPN.
        cases = {
            445: "SMB",
            1716: "KDE Connect",
            2049: "NFS",
            3389: "RDP",
            5355: "LLMNR",
            5672: "RabbitMQ",
            8384: "Syncthing",
            9200: "Elasticsearch",
            32400: "Plex",
            51820: "WireGuard",
            57621: "Spotify Connect",
        }
        for port, guess in cases.items():
            [listener] = build([sock("0.0.0.0", port)])
            self.assertEqual(listener["owner"], {"kind": "unknown", "guess": guess}, port)

    def test_unknown_owner_on_an_unlisted_port_has_no_guess(self):
        [listener] = build([sock("127.0.0.1", 39033)])
        self.assertEqual(listener["owner"], {"kind": "unknown", "guess": None})
        self.assertEqual(listener["scope"], "local")

    def test_real_process_name_beats_the_port_guess(self):
        [listener] = build([sock("0.0.0.0", 8096, "tcp", ("python3", 112443))])
        self.assertEqual(listener["owner"]["kind"], "process")
        self.assertEqual(listener["owner"]["name"], "python3")

    def test_vpn_only_listener_links_to_its_vpn_address(self):
        [listener] = build([sock("100.90.0.14", 57203)])
        self.assertEqual(listener["scope"], "overlay")
        self.assertEqual(listener["url"], "http://100.90.0.14:57203")

    def test_ipv6_address_is_bracketed_in_url(self):
        [listener] = build([sock("fd7a:115c:a1e0::6c01:74c1", 65009)])
        self.assertEqual(listener["url"], "http://[fd7a:115c:a1e0::6c01:74c1]:65009")

    def test_widest_reach_sets_scope_but_loopback_keeps_localhost_url(self):
        [listener] = build([sock("127.0.0.1", 4000, "tcp", ("python3", 112443)),
                            sock("100.90.0.14", 4000, "tcp", ("python3", 112443))])
        self.assertEqual(listener["addresses"], ["127.0.0.1", "100.90.0.14"])
        self.assertEqual(listener["scope"], "overlay")
        self.assertEqual(listener["url"], "http://localhost:4000")

    def test_udp_has_no_url_or_browser_actions(self):
        [listener] = build([sock("127.0.0.1", 57983, "udp", ("python3", 112443))])
        self.assertIsNone(listener["url"])
        self.assertEqual(listener["actions"], ["terminate", "kill"])

    def test_process_of_another_user_is_read_only(self):
        [listener] = build([sock("0.0.0.0", 9090, "tcp", ("prometheus", 4242))])
        self.assertFalse(listener["owner"]["owned"])
        self.assertEqual(listener["actions"], ["open", "copy"])

    def test_process_without_a_verifiable_start_time_cannot_be_signalled(self):
        [listener] = build([sock("127.0.0.1", 3000, "tcp", ("Web Content", 5150))])
        self.assertEqual(listener["actions"], ["open", "copy"])

    def test_process_that_exited_before_it_was_described_is_read_only(self):
        [listener] = build([sock("127.0.0.1", 5001, "tcp", ("ghost", 777))])
        self.assertEqual(listener["owner"], {"kind": "process", "name": "ghost", "pid": 777, "owned": False,
                                             "start": 0, "command": "", "cwd": ""})
        self.assertEqual(listener["actions"], ["open", "copy"])

    def test_ignored_ports_are_dropped(self):
        listeners = build([sock("127.0.0.53", 53), sock("127.0.0.1", 631), sock("0.0.0.0", 3001)],
                          ignored={53, 631})
        self.assertEqual([l["port"] for l in listeners], [3001])

    def test_sorted_by_port_then_protocol(self):
        listeners = build([sock("*", 5353, "udp"), sock("0.0.0.0", 5353), sock("0.0.0.0", 22)])
        self.assertEqual([(l["port"], l["proto"]) for l in listeners], [(22, "tcp"), (5353, "tcp"), (5353, "udp")])


class OutputBoundsTests(unittest.TestCase):
    """The panel reads the helper's whole JSON document, so every field that
    comes from outside (command lines, working directories, image names) and
    the number of rows are bounded before they are printed."""

    def test_long_process_details_are_truncated_and_marked(self):
        details = {4001: {"owned": True, "start": 9,
                          "command": "python3 " + "x" * 5000, "cwd": "/home/alice/" + "d" * 1000}}
        [listener] = ports.build_listeners([sock("127.0.0.1", 7000, "tcp", ("python3", 4001))], [],
                                           details.get, set())
        owner = listener["owner"]
        for field in ("command", "cwd"):
            self.assertLessEqual(len(owner[field]), 512, field)
            self.assertTrue(owner[field].endswith("…"), field)
        self.assertTrue(owner["command"].startswith("python3 xxx"))

    def test_long_container_fields_are_truncated(self):
        inspected = [{
            "Id": "ab" * 32,
            "Name": "/" + "n" * 900,
            "Config": {"Image": "registry.example/" + "i" * 2000, "Labels": {}},
            "State": {"Running": True},
            "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8081"}]}},
        }]
        [binding] = ports.container_ports(inspected)
        self.assertLessEqual(len(binding["container"]["name"]), 512)
        self.assertLessEqual(len(binding["container"]["image"]), 512)
        self.assertEqual(binding["container"]["id"], "ab" * 32)

    def test_listener_list_is_capped_with_a_warning(self):
        many = [{"key": f"tcp:{port}", "port": port, "proto": "tcp"} for port in range(1, 601)]
        warnings = []
        kept = ports.limit_listeners(many, warnings)
        self.assertEqual([listener["port"] for listener in kept], list(range(1, 513)))
        self.assertEqual(len(warnings), 1)
        self.assertIn("600", warnings[0])

    def test_short_listener_list_is_untouched(self):
        few = [{"key": "tcp:22", "port": 22, "proto": "tcp"}, {"key": "tcp:80", "port": 80, "proto": "tcp"}]
        warnings = []
        self.assertEqual(ports.limit_listeners(few, warnings), few)
        self.assertEqual(warnings, [])

if __name__ == "__main__":
    unittest.main()
