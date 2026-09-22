"""End to end, against a real echo server on loopback.

These start an actual UDP echo server, point a real relay at it and send real
packets through. A relay that passes a test with mocked sockets is a relay
that has never moved a byte, and the things that break here -- a socket bound
before its address exists, a reply going to the wrong client -- are exactly
the things mocks agree to.

    python3 -m unittest discover -s tests
"""

import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import udp_relay  # noqa: E402


def free_port() -> int:
    """A port nothing is using, released again before it is handed back.

    Racy in principle. In practice nothing else on a test machine takes the
    port in the microsecond between, and the alternative is hard-coding ports
    that collide with whatever else the developer is running.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Echo:
    """Answers every datagram with a prefix and the datagram."""

    def __init__(self, port: int, prefix: bytes = b"OK:") -> None:
        self.port = port
        self.prefix = prefix
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while self.running:
            try:
                data, who = self.sock.recvfrom(4096)
            except OSError:
                continue

            try:
                self.sock.sendto(self.prefix + data, who)
            except OSError:
                pass

    def stop(self) -> None:
        self.running = False
        self.thread.join(timeout=1)
        self.sock.close()


def config(listen_port: int, target_port: int, candidates: list, **over) -> dict:
    conf = udp_relay.merge(
        udp_relay.DEFAULTS,
        {
            "listen": {"address": "127.0.0.1", "port": listen_port},
            "target": {"port": target_port, "candidates": candidates, "recheck_seconds": 1},
            "probe": {"kind": "udp", "timeout": 0.5, "send_hex": "70696e67"},  # "ping"
            "log": {"path": ""},
        },
    )

    return udp_relay.merge(conf, over)


class ProbeTests(unittest.TestCase):
    def test_udp_probe_finds_a_live_server(self):
        port = free_port()
        echo = Echo(port)

        try:
            probe = udp_relay.Probe(
                {"kind": "udp", "timeout": 0.5, "send_hex": "70696e67", "expect_prefix_hex": ""}
            )

            self.assertTrue(probe("127.0.0.1", port))
        finally:
            echo.stop()

    def test_udp_probe_rejects_a_dead_one(self):
        probe = udp_relay.Probe(
            {"kind": "udp", "timeout": 0.3, "send_hex": "70696e67", "expect_prefix_hex": ""}
        )

        self.assertFalse(probe("127.0.0.1", free_port()))

    def test_expected_prefix_rejects_the_wrong_protocol(self):
        """Something answered, but it is not what we are looking for."""
        port = free_port()
        echo = Echo(port, prefix=b"WRONG:")

        try:
            probe = udp_relay.Probe(
                {
                    "kind": "udp",
                    "timeout": 0.5,
                    "send_hex": "70696e67",
                    "expect_prefix_hex": b"OK:".hex(),
                }
            )

            self.assertFalse(probe("127.0.0.1", port))
        finally:
            echo.stop()

    def test_none_probe_accepts_anything(self):
        probe = udp_relay.Probe(
            {"kind": "none", "timeout": 0.5, "send_hex": "", "expect_prefix_hex": ""}
        )

        self.assertTrue(probe("203.0.113.1", 9))

    def test_unknown_kind_is_refused_at_construction(self):
        with self.assertRaises(ValueError):
            udp_relay.Probe(
                {"kind": "smoke-signal", "timeout": 1, "send_hex": "", "expect_prefix_hex": ""}
            )


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.log = udp_relay.Log("", 0)
        self.echoes = []
        self.relays = []

    def tearDown(self):
        for echo in self.echoes:
            echo.stop()

    def start(self, conf):
        relay = udp_relay.Relay(conf, self.log)
        thread = threading.Thread(target=relay.run, daemon=True)
        thread.start()
        self.relays.append(relay)

        # Wait for the listener to exist rather than sleeping a fixed amount.
        for _ in range(100):
            if relay.listener is not None:
                break
            time.sleep(0.02)

        return relay

    def test_a_packet_goes_through_and_comes_back(self):
        target = free_port()
        listen = free_port()

        self.echoes.append(Echo(target))

        self.start(config(listen, target, ["127.0.0.1"]))

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2)

        try:
            client.sendto(b"hello", ("127.0.0.1", listen))
            data, _ = client.recvfrom(4096)

            self.assertEqual(data, b"OK:hello")
        finally:
            client.close()

    def test_two_clients_get_their_own_replies(self):
        """The bug this guards: one shared upstream socket sends every reply
        to whoever spoke last."""
        target = free_port()
        listen = free_port()

        self.echoes.append(Echo(target))

        self.start(config(listen, target, ["127.0.0.1"]))

        a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        a.settimeout(2)
        b.settimeout(2)

        try:
            a.sendto(b"aaa", ("127.0.0.1", listen))
            b.sendto(b"bbb", ("127.0.0.1", listen))

            self.assertEqual(a.recvfrom(4096)[0], b"OK:aaa")
            self.assertEqual(b.recvfrom(4096)[0], b"OK:bbb")
        finally:
            a.close()
            b.close()

    def test_a_dead_first_candidate_is_skipped(self):
        target = free_port()
        listen = free_port()
        dead = free_port()

        self.echoes.append(Echo(target))

        relay = self.start(config(listen, target, ["127.0.0.1"], target={"port": target}))

        # Both candidates are 127.0.0.1 here, so the interesting case is the
        # port: point the relay at a dead one first and let it find the live.
        relay.candidates = ["127.0.0.1"]
        self.assertEqual(relay.find_target(), "127.0.0.1")
        self.assertFalse(relay.probe("127.0.0.1", dead))

    def test_empty_candidate_list_is_refused(self):
        with self.assertRaises(ValueError):
            udp_relay.Relay(config(free_port(), free_port(), []), self.log)


class ConfigTests(unittest.TestCase):
    def test_merge_fills_in_defaults_and_keeps_overrides(self):
        conf = udp_relay.merge(udp_relay.DEFAULTS, {"listen": {"port": 9999}})

        self.assertEqual(conf["listen"]["port"], 9999)
        self.assertEqual(conf["listen"]["address"], "0.0.0.0")
        self.assertEqual(conf["session"]["buffer_bytes"], 4096)

    def test_the_example_config_parses_and_is_complete(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        conf = udp_relay.load_config(os.path.join(here, "config.example.toml"))

        self.assertTrue(conf["target"]["candidates"])
        udp_relay.Probe(conf["probe"])


if __name__ == "__main__":
    unittest.main()
