"""Tests for the ACTIVE, authorization-gated probe (sqlsec.probe).

CRITICAL: no test here touches a real external host. Every probe uses an
injected fake connector or a loopback fixture server bound to 127.0.0.1. The
suite's purpose is to prove the authorization gating, scope enforcement, and
rate limiting behave correctly.
"""

import socket
import threading

import pytest

from sqlsec import probe as P
from sqlsec.probe import (
    AuthorizationError,
    Scope,
    ScopeError,
    Target,
    parse_target,
    probe_target,
    probe_targets,
)


# --- target parsing -------------------------------------------------------

def test_parse_host_only_uses_default_port():
    t = parse_target("db.local", default_port=5432)
    assert t == Target("db.local", 5432)


def test_parse_host_port():
    assert parse_target("db.local:3306") == Target("db.local", 3306)


def test_parse_ipv6_bracketed():
    assert parse_target("[::1]:5432") == Target("::1", 5432)


def test_parse_ipv6_bracketed_default_port():
    assert parse_target("[::1]", default_port=1521) == Target("::1", 1521)


# --- authorization gating -------------------------------------------------

def test_unauthorized_raises():
    scope = Scope(authorized=False, allowlist=frozenset({"127.0.0.1"}))
    with pytest.raises(AuthorizationError):
        scope.check_authorized()


def test_authorized_but_empty_allowlist_raises():
    scope = Scope(authorized=True, allowlist=frozenset())
    with pytest.raises(AuthorizationError):
        scope.check_authorized()


def test_authorized_with_allowlist_ok():
    scope = Scope(authorized=True, allowlist=frozenset({"127.0.0.1"}))
    scope.check_authorized()  # no raise


def test_probe_targets_refuses_without_auth():
    scope = Scope(authorized=False, allowlist=frozenset({"127.0.0.1"}))
    with pytest.raises(AuthorizationError):
        probe_targets(["127.0.0.1:5432"], scope,
                      connector=lambda t, to: b"", sleep=lambda s: None)


# --- scope enforcement ----------------------------------------------------

def test_in_scope_case_insensitive():
    scope = Scope(authorized=True, allowlist=frozenset({"DB.Local"}))
    assert scope.in_scope(Target("db.local", 5432))


def test_out_of_scope_target_refused_in_probe_target():
    scope = Scope(authorized=True, allowlist=frozenset({"127.0.0.1"}))
    with pytest.raises(ScopeError):
        probe_target(Target("evil.example", 5432), scope,
                     connector=lambda t, to: b"")


def test_out_of_scope_target_skipped_not_connected():
    scope = Scope(authorized=True, allowlist=frozenset({"127.0.0.1"}),
                  rate_limit=0)
    connected = []

    def conn(t, to):
        connected.append(t)
        return b""

    results = probe_targets(["8.8.8.8:5432", "127.0.0.1:5432"], scope,
                            connector=conn, sleep=lambda s: None)
    # The out-of-scope host must never be handed to the connector.
    assert Target("8.8.8.8", 5432) not in connected
    refused = [r for r in results if "out of scope" in (r.error or "")]
    assert len(refused) == 1
    assert refused[0].target.host == "8.8.8.8"


# --- fingerprinting via fake connector ------------------------------------

def test_fingerprint_from_banner():
    scope = Scope(authorized=True, allowlist=frozenset({"127.0.0.1"}))
    r = probe_target(Target("127.0.0.1", 9999), scope,
                     connector=lambda t, to: b"5.7.40-MySQL community")
    assert r.reachable
    assert r.engine == "MySQL / MariaDB"


def test_fingerprint_from_port_when_no_banner():
    scope = Scope(authorized=True, allowlist=frozenset({"127.0.0.1"}))
    r = probe_target(Target("127.0.0.1", 5432), scope,
                     connector=lambda t, to: b"")
    assert r.engine == "PostgreSQL"


def test_unreachable_target_records_error():
    scope = Scope(authorized=True, allowlist=frozenset({"127.0.0.1"}))

    def boom(t, to):
        raise OSError("connection refused")

    r = probe_target(Target("127.0.0.1", 1), scope, connector=boom)
    assert not r.reachable
    assert "refused" in r.error


def test_banner_sanitized():
    scope = Scope(authorized=True, allowlist=frozenset({"127.0.0.1"}))
    r = probe_target(Target("127.0.0.1", 5432), scope,
                     connector=lambda t, to: b"ok\x00\x01\x02bytes")
    assert "\x00" not in r.banner
    assert "ok" in r.banner


# --- rate limiting --------------------------------------------------------

def test_rate_limit_sleeps_between_connections():
    scope = Scope(authorized=True,
                  allowlist=frozenset({"127.0.0.1", "localhost"}),
                  rate_limit=2.5)
    slept = []
    probe_targets(["127.0.0.1:5432", "localhost:5432"], scope,
                  connector=lambda t, to: b"",
                  sleep=lambda s: slept.append(s))
    # One delay between the two in-scope connections.
    assert slept == [2.5]


def test_rate_limit_not_applied_before_first():
    scope = Scope(authorized=True, allowlist=frozenset({"127.0.0.1"}),
                  rate_limit=5.0)
    slept = []
    probe_targets(["127.0.0.1:5432"], scope, connector=lambda t, to: b"",
                  sleep=lambda s: slept.append(s))
    assert slept == []


def test_rate_limit_zero_no_sleep():
    scope = Scope(authorized=True,
                  allowlist=frozenset({"127.0.0.1", "localhost"}),
                  rate_limit=0)
    slept = []
    probe_targets(["127.0.0.1:1", "localhost:1"], scope,
                  connector=lambda t, to: b"", sleep=lambda s: slept.append(s))
    assert slept == []


# --- real loopback fixture server (127.0.0.1 only, never external) --------

@pytest.fixture
def banner_server():
    """A tiny TCP server on 127.0.0.1 that sends a fake DB banner then closes."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
            with conn:
                conn.sendall(b"PostgreSQL 14.2 fixture")
        except OSError:
            pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    yield port
    srv.close()
    th.join(timeout=1)


def test_real_loopback_probe(banner_server):
    scope = Scope(authorized=True, allowlist=frozenset({"127.0.0.1"}),
                  rate_limit=0)
    r = probe_target(Target("127.0.0.1", banner_server), scope, timeout=2.0)
    assert r.reachable
    assert r.engine == "PostgreSQL"
    assert "PostgreSQL" in r.banner


def test_real_loopback_out_of_scope_refused(banner_server):
    # Same loopback port but host not in allowlist -> refused, never connected.
    scope = Scope(authorized=True, allowlist=frozenset({"10.0.0.1"}),
                  rate_limit=0)
    with pytest.raises(ScopeError):
        probe_target(Target("127.0.0.1", banner_server), scope, timeout=2.0)


def test_banner_includes_authorized_use_text():
    assert "AUTHORIZED USE ONLY" in P.AUTHORIZED_USE_BANNER
    assert "NO SQL" in P.AUTHORIZED_USE_BANNER
