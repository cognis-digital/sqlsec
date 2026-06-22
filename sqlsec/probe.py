"""ACTIVE, authorization-gated database-endpoint reachability probe.

================================  WARNING  ================================
This is the only module in sqlsec that touches the network. It is an
AUTHORIZED-USE-ONLY capability and is DISABLED BY DEFAULT.

It performs a *defensive* check: given a target ``host:port`` you are
authorized to inspect, it opens a TCP connection, reads any greeting banner
the service volunteers, and fingerprints the database engine. It NEVER sends
SQL, NEVER attempts a login, NEVER sends an exploit or injection payload, and
NEVER writes anything to the target. It is the network equivalent of "is the
DB port reachable, and what does it announce itself as" -- the kind of check
a defender runs against their own infrastructure.

To run, the operator MUST supply ALL of:
  * ``--authorized``            an explicit consent acknowledgement flag
  * a target allowlist (scope)  every probed host MUST be in scope or it is
                                refused and skipped
  * a rate limit                minimum delay enforced between connections

Targets not in the allowlist are refused. There is no override.
==========================================================================

Standard library only (``socket``). Original work by Cognis Digital.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

AUTHORIZED_USE_BANNER = (
    "================================================================\n"
    " sqlsec ACTIVE PROBE -- AUTHORIZED USE ONLY\n"
    " You assert you are authorized to inspect the listed targets.\n"
    " This probe only checks reachability and reads volunteered\n"
    " banners. It sends NO SQL, NO login, and NO exploit payloads.\n"
    " Unauthorized scanning may be illegal. You are responsible.\n"
    "================================================================"
)


class AuthorizationError(Exception):
    """Raised when an active probe is attempted without proper authorization."""


class ScopeError(Exception):
    """Raised when a target is outside the configured allowlist (scope)."""


# --------------------------------------------------------------------------
# Well-known database ports -> engine label (fingerprint hint only).
# --------------------------------------------------------------------------
_PORT_HINTS = {
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL / MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9042: "Cassandra",
    5984: "CouchDB",
    7687: "Neo4j (bolt)",
    50000: "IBM Db2",
}

# Tiny, non-intrusive banner signatures. We only *read*; we never craft a
# protocol handshake. Postgres/MySQL volunteer enough on connect to fingerprint.
_BANNER_SIGNS = (
    (b"mysql", "MySQL / MariaDB"),
    (b"mariadb", "MariaDB"),
    (b"postgres", "PostgreSQL"),
    (b"PGSQL", "PostgreSQL"),
    (b"Microsoft", "Microsoft SQL Server"),
    (b"redis", "Redis"),
    (b"-ERR", "Redis"),
    (b"MongoDB", "MongoDB"),
)


@dataclass(frozen=True)
class Target:
    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class ProbeResult:
    target: Target
    reachable: bool
    engine: Optional[str]      # best-guess engine label
    banner: str                # decoded, truncated, sanitized banner text
    error: Optional[str]       # connection error string if not reachable

    def as_dict(self) -> dict:
        return {
            "host": self.target.host,
            "port": self.target.port,
            "reachable": self.reachable,
            "engine": self.engine,
            "banner": self.banner,
            "error": self.error,
        }


@dataclass
class Scope:
    """Authorization scope for an active probe run.

    * ``authorized`` -- must be True or every probe is refused.
    * ``allowlist``  -- set of permitted hostnames / IPs. A target whose host is
      not present is refused (ScopeError).
    * ``rate_limit`` -- minimum seconds between successive connections.
    """

    authorized: bool = False
    allowlist: frozenset = field(default_factory=frozenset)
    rate_limit: float = 1.0

    def normalized_allowlist(self) -> frozenset:
        return frozenset(h.strip().lower() for h in self.allowlist if h.strip())

    def check_authorized(self) -> None:
        if not self.authorized:
            raise AuthorizationError(
                "active probe refused: --authorized was not supplied. "
                "This capability is authorized-use-only and off by default."
            )
        if not self.normalized_allowlist():
            raise AuthorizationError(
                "active probe refused: an empty target allowlist means no "
                "target is in scope. Supply --target-allowlist host[,host...]."
            )

    def in_scope(self, target: Target) -> bool:
        return target.host.strip().lower() in self.normalized_allowlist()


def parse_target(raw: str, default_port: int = 5432) -> Target:
    """Parse ``host``, ``host:port``. IPv6 must be bracketed: ``[::1]:5432``."""
    raw = raw.strip()
    if raw.startswith("["):  # bracketed IPv6
        host, _, rest = raw[1:].partition("]")
        port = int(rest.lstrip(":")) if rest.lstrip(":") else default_port
        return Target(host, port)
    if raw.count(":") == 1:
        host, _, p = raw.partition(":")
        return Target(host, int(p) if p else default_port)
    return Target(raw, default_port)


def _sanitize_banner(data: bytes) -> str:
    text = data.decode("latin-1", errors="replace")
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    return cleaned.strip()[:200]


def _fingerprint(port: int, banner_bytes: bytes) -> Optional[str]:
    low = banner_bytes.lower()
    for sign, label in _BANNER_SIGNS:
        if sign.lower() in low:
            return label
    return _PORT_HINTS.get(port)


def probe_target(
    target: Target,
    scope: Scope,
    timeout: float = 3.0,
    connector: Optional[Callable[[Target, float], bytes]] = None,
) -> ProbeResult:
    """Probe a single in-scope target. Caller must have checked authorization.

    ``connector`` is injectable for tests so the suite never touches a real
    external host: it takes (target, timeout) and returns the banner bytes, or
    raises OSError to simulate an unreachable port. The default uses a real
    socket and is only exercised against localhost/fixtures in tests.
    """
    if not scope.in_scope(target):
        raise ScopeError(
            f"target {target} is not in the allowlist (scope) -- refused"
        )

    conn = connector or _default_connector
    try:
        banner_bytes = conn(target, timeout)
    except OSError as exc:
        return ProbeResult(target, False, None, "", str(exc))
    engine = _fingerprint(target.port, banner_bytes)
    return ProbeResult(
        target=target,
        reachable=True,
        engine=engine,
        banner=_sanitize_banner(banner_bytes),
        error=None,
    )


def _default_connector(target: Target, timeout: float) -> bytes:
    """Open a TCP socket, read a short volunteered banner, close. Read-only."""
    with socket.create_connection((target.host, target.port), timeout=timeout) as s:
        s.settimeout(timeout)
        try:
            return s.recv(256)
        except (socket.timeout, OSError):
            # Reachable but silent (many DBs wait for a client handshake).
            return b""


def probe_targets(
    raw_targets: list[str],
    scope: Scope,
    timeout: float = 3.0,
    default_port: int = 5432,
    connector: Optional[Callable[[Target, float], bytes]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[ProbeResult]:
    """Probe a list of targets, enforcing authorization, scope, and rate limit.

    Authorization is checked once up front (raises AuthorizationError). Each
    target is then checked against the allowlist: out-of-scope targets are
    skipped (recorded with an error), never connected to. The rate limit is
    enforced as a minimum delay between *actual* connection attempts.
    """
    scope.check_authorized()
    results: list[ProbeResult] = []
    first = True
    for raw in raw_targets:
        target = parse_target(raw, default_port=default_port)
        if not scope.in_scope(target):
            results.append(
                ProbeResult(target, False, None, "",
                            "skipped: not in allowlist (out of scope)")
            )
            continue
        if not first and scope.rate_limit > 0:
            sleep(scope.rate_limit)
        first = False
        results.append(probe_target(target, scope, timeout=timeout,
                                    connector=connector))
    return results
