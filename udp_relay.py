#!/usr/bin/env python3
"""A UDP relay that keeps working when the target's address changes.

Forwarding UDP is easy. The hard part, in the situation this was written for,
is that the machine on the other end does not have a stable address: it is a
VM on a home router, and every new router, new lease or new flat gives it a
different one. A relay pinned to a single address stops working and nobody
finds out until somebody complains.

So the target is a *list* of addresses, and the relay asks which one is really
there before it sends anybody's traffic to it -- at start-up, and again on a
timer. Moving house costs one line in a config file, and usually not even
that: if the old address is already in the list, it is found again by itself.

No dependencies beyond the standard library. Python 3.11 or newer (tomllib).
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
import tomllib
from datetime import datetime

# Windows only. Without this, an ICMP port-unreachable from an earlier send
# makes the *next* recvfrom raise ConnectionResetError, which reads as the
# socket dying when nothing is wrong.
SIO_UDP_CONNRESET = -1744830452

DEFAULTS = {
    "listen": {"address": "0.0.0.0", "port": 7777},
    "target": {"port": 7777, "candidates": [], "recheck_seconds": 60},
    "probe": {"kind": "udp", "timeout": 1.5, "send_hex": "", "expect_prefix_hex": ""},
    "log": {"path": "", "max_bytes": 1_000_000},
    "session": {"idle_seconds": 120, "buffer_bytes": 4096},
}


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
def merge(base: dict, over: dict) -> dict:
    """Two levels deep is all this config has, so two levels is all this does."""
    out = {section: dict(values) for section, values in base.items()}

    for section, values in over.items():
        if section not in out:
            out[section] = {}
        if isinstance(values, dict):
            out[section].update(values)
        else:
            out[section] = values

    return out


def load_config(path: str) -> dict:
    with open(path, "rb") as fh:
        return merge(DEFAULTS, tomllib.load(fh))


# ---------------------------------------------------------------------------
# logging
# ---------------------------------------------------------------------------
class Log:
    """Timestamped lines to stdout, and to a file if one is configured.

    The file is rolled over rather than rotated properly: this runs for months
    at a time and the alternative is a log nobody reads growing without bound.
    """

    def __init__(self, path: str, max_bytes: int) -> None:
        self.path = path
        self.max_bytes = max_bytes

    def __call__(self, message: str) -> None:
        line = "[%s] %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message)
        print(line, flush=True)

        if not self.path:
            return

        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.max_bytes:
                os.replace(self.path, self.path + ".old")

            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            # A log that cannot be written is not a reason to stop relaying.
            pass


# ---------------------------------------------------------------------------
# sockets
# ---------------------------------------------------------------------------
def harden(sock: socket.socket) -> None:
    try:
        sock.ioctl(SIO_UDP_CONNRESET, False)
    except (AttributeError, OSError, ValueError):
        pass


def bind_listener(address: str, port: int, log: Log) -> socket.socket:
    """Wait for the address to exist rather than dying because it does not yet.

    A relay that listens on a VPN adapter starts before the VPN does, every
    time the machine boots. Failing there would mean the relay is only ever up
    when somebody starts it by hand.
    """
    warned = False

    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        harden(sock)

        try:
            sock.bind((address, port))
            return sock
        except OSError as exc:
            sock.close()

            if not warned:
                log("waiting for %s to come up (%s)" % (address, exc))
                warned = True

            time.sleep(5)


# ---------------------------------------------------------------------------
# is the target actually there
# ---------------------------------------------------------------------------
def samp_query(ip: str, port: int) -> bytes:
    """The SA-MP 'information' query, kept as a worked example of a real probe.

    A protocol-aware probe is better than a blind one: it tells you the thing
    you are looking for is on that port, not merely that something is.
    """
    return b"SAMP" + bytes(int(x) for x in ip.split(".")) + port.to_bytes(2, "little") + b"i"


class Probe:
    """Whether a candidate address is worth sending traffic to.

    Four kinds, in order of how much they tell you:

      none  -- assume the first candidate is right; useful when the target
               cannot be probed at all
      tcp   -- a TCP connect on the same port number
      udp   -- send something, expect anything back
      samp  -- the SA-MP query above, and its reply magic
    """

    def __init__(self, conf: dict) -> None:
        self.kind = conf["kind"]
        self.timeout = float(conf["timeout"])
        self.send = bytes.fromhex(conf["send_hex"]) if conf["send_hex"] else b""
        self.expect = bytes.fromhex(conf["expect_prefix_hex"]) if conf["expect_prefix_hex"] else b""

        if self.kind not in ("none", "tcp", "udp", "samp"):
            raise ValueError("probe.kind must be none, tcp, udp or samp")

    def __call__(self, ip: str, port: int) -> bool:
        if self.kind == "none":
            return True

        if self.kind == "tcp":
            return self._tcp(ip, port)

        return self._udp(ip, port)

    def _tcp(self, ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except OSError:
            return False

    def _udp(self, ip: str, port: int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        harden(sock)
        sock.settimeout(self.timeout)

        try:
            payload = samp_query(ip, port) if self.kind == "samp" else self.send
            expect = b"SAMP" if self.kind == "samp" else self.expect

            sock.sendto(payload, (ip, port))
            data, _ = sock.recvfrom(2048)

            return data.startswith(expect) if expect else True
        except (OSError, ValueError):
            return False
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# the relay
# ---------------------------------------------------------------------------
class Relay:
    def __init__(self, conf: dict, log: Log) -> None:
        self.conf = conf
        self.log = log

        self.probe = Probe(conf["probe"])
        self.candidates = list(conf["target"]["candidates"])
        self.target_port = int(conf["target"]["port"])
        self.recheck = int(conf["target"]["recheck_seconds"])

        if not self.candidates:
            raise ValueError("target.candidates is empty: there is nowhere to relay to")

        self.target_ip = self.candidates[0]

        self.buffer = int(conf["session"]["buffer_bytes"])
        self.idle = int(conf["session"]["idle_seconds"])

        self.sessions: dict[tuple[str, int], socket.socket] = {}
        self.lock = threading.Lock()
        self.listener: socket.socket | None = None

    # -- finding the target -------------------------------------------------
    def find_target(self) -> str | None:
        for ip in self.candidates:
            if self.probe(ip, self.target_port):
                return ip

        return None

    def watch_target(self) -> None:
        """Look again on a timer, so a change of address heals itself."""
        while True:
            time.sleep(self.recheck)

            # Still answering where it is: nothing to do, and no reason to
            # probe every other candidate.
            if self.probe(self.target_ip, self.target_port):
                continue

            found = self.find_target()

            if found and found != self.target_ip:
                self.log("target moved: %s -> %s" % (self.target_ip, found))
                self.target_ip = found

    # -- moving the packets -------------------------------------------------
    def pump_replies(self, client: tuple[str, int], upstream: socket.socket) -> None:
        """Everything the target says back to one client, until it goes quiet."""
        while True:
            try:
                data, _ = upstream.recvfrom(self.buffer)
            except OSError:
                break

            try:
                assert self.listener is not None
                self.listener.sendto(data, client)
            except OSError:
                break

        # A client that stopped talking should not leave a socket behind for
        # good; the timeout above is what eventually brings us here.
        with self.lock:
            if self.sessions.get(client) is upstream:
                del self.sessions[client]

        upstream.close()

    def upstream_for(self, client: tuple[str, int]) -> socket.socket:
        with self.lock:
            sock = self.sessions.get(client)

            if sock is not None:
                return sock

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            harden(sock)
            sock.settimeout(self.idle)

            self.sessions[client] = sock

        threading.Thread(target=self.pump_replies, args=(client, sock), daemon=True).start()

        return sock

    def run(self) -> None:
        listen = self.conf["listen"]

        self.listener = bind_listener(listen["address"], int(listen["port"]), self.log)

        found = self.find_target()

        if found:
            self.target_ip = found
        else:
            self.log(
                "no candidate answered yet; starting with %s and looking again every %ds"
                % (self.target_ip, self.recheck)
            )

        threading.Thread(target=self.watch_target, daemon=True).start()

        self.log(
            "relay listening on %s:%s -> %s:%d"
            % (listen["address"], listen["port"], self.target_ip, self.target_port)
        )

        while True:
            try:
                data, client = self.listener.recvfrom(self.buffer)
            except OSError:
                continue

            try:
                self.upstream_for(client).sendto(data, (self.target_ip, self.target_port))
            except OSError:
                pass


# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-c", "--config", default="config.toml", help="path to the config file")
    parser.add_argument(
        "--check",
        action="store_true",
        help="probe every candidate, print what answered, and exit",
    )

    args = parser.parse_args(argv)

    try:
        conf = load_config(args.config)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print("cannot read %s: %s" % (args.config, exc), file=sys.stderr)
        return 2

    log = Log(conf["log"]["path"], int(conf["log"]["max_bytes"]))

    try:
        relay = Relay(conf, log)
    except ValueError as exc:
        print("config: %s" % exc, file=sys.stderr)
        return 2

    if args.check:
        for ip in relay.candidates:
            ok = relay.probe(ip, relay.target_port)
            print("%-16s %s" % (ip, "answered" if ok else "-"))

        return 0

    try:
        relay.run()
    except KeyboardInterrupt:
        log("stopped")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
