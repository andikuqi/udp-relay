# udp-relay

A UDP relay that keeps working when the target's address changes.

Forwarding UDP is easy — `socat` does it in one line. The hard part is that
the machine on the other end often does not have a stable address. It is a VM
on a home router, a box on DHCP, a server in a flat you moved out of. A relay
pinned to one address stops working, and nobody finds out until somebody
complains.

So here the target is a **list** of addresses, and the relay asks which one is
really there before it sends anyone's traffic to it — at start-up, and again
on a timer. A new router costs one line in a config file, and usually not even
that: if the address has been seen before, it is found again by itself.

No dependencies. Python 3.11 or newer.

## What it is for

- A game server on a LAN that friends reach through a VPN adapter.
- Anything behind NAT you cannot port-forward, reached through a host you can.
- A dev box whose address changes every time the lease renews.
- Two networks joined by one machine that sits on both.

It relays UDP only, IPv4 only, one port to one port. If you need TCP, or a
port range, or load balancing, this is the wrong tool and `socat`, `nginx
stream` or HAProxy are the right ones.

## Running it

```sh
cp config.example.toml config.toml
$EDITOR config.toml
python3 udp_relay.py --config config.toml
```

Check which of your candidate addresses is alive without relaying anything:

```sh
python3 udp_relay.py --config config.toml --check
```

```
192.168.0.42     answered
192.168.0.27     -
192.168.178.190  -
```

## How the failover works

At start-up the relay probes each candidate in order and uses the first that
answers. Every `recheck_seconds` it probes **only the address in use**; the
rest are tried just when that one goes quiet. So the steady-state cost is one
packet a minute, and a target that moves is picked up within a minute of the
move without restarting anything.

There are four kinds of probe, in order of how much they tell you:

| kind | what it proves |
|------|----------------|
| `none` | nothing. The first candidate is used and there is no failover. |
| `tcp` | a machine is listening on that port number over TCP. |
| `udp` | something answered a datagram on that port. |
| `samp` | the reply is a SA-MP server — a real protocol handshake. |

`udp` with `send_hex` and `expect_prefix_hex` set is the useful general case:
send whatever your protocol's cheapest request is, and check the reply starts
the way that protocol's replies start. That is the difference between "a
machine is there" and "*my* server is there" — which matters, because the
address that answers might now belong to somebody's printer.

The `samp` kind is built in as a worked example of what a protocol-aware probe
looks like. Copy its shape for your own.

## Config

See [`config.example.toml`](config.example.toml) — every option is commented
there rather than duplicated here.

## Running it as a service

**Linux (systemd).** Edit the paths and the user, then:

```sh
sudo cp systemd/udp-relay.service /etc/systemd/system/
sudo systemctl enable --now udp-relay
journalctl -u udp-relay -f
```

Leave `log.path` empty and let the journal have it.

**Windows (Task Scheduler).** Create a task that runs at logon with
`pythonw.exe` (not `python.exe` — `pythonw` has no console window):

```
Program:   C:\Path\To\Python\pythonw.exe
Arguments: "C:\Path\To\udp-relay\udp_relay.py" --config "C:\Path\To\udp-relay\config.toml"
Start in:  C:\Path\To\udp-relay
```

Set `log.path` to a file, because there is no console to read.

## Things worth knowing

**It waits for its own address.** A relay that listens on a VPN adapter starts
before the VPN does, every boot. Rather than failing there, it retries the
bind every five seconds until the address exists. This is the difference
between a service that survives a reboot and one you start by hand.

**Windows and `ConnectionResetError`.** On Windows, an ICMP port-unreachable
from an earlier send makes the *next* `recvfrom` raise, which reads as the
socket dying when nothing is wrong. The relay clears `SIO_UDP_CONNRESET` on
every socket it makes. Without that, one unreachable probe kills a session.

**One socket per client, closed when idle.** Each client address gets its own
upstream socket so replies go back to the right place. A client that says
nothing for `idle_seconds` has its socket closed and reopened the moment it
speaks again.

**The target does not know about this.** It sees all traffic coming from the
relay's address. If it does per-address bans, rate limits or auto-login by IP,
every client through the relay looks like one machine to it. That is a real
hole and it is worth designing around: it is exactly how one of these tripped
an IP-based auto-login on the server it was written for.

## Licence

MIT. See [LICENSE](LICENSE).
