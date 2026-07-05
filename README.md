# TitaniumGuard DNS

TitaniumGuard DNS is a friendly, operations-focused DNS server written in Rust.
It is packaged as a single binary and is intended to be easy to run locally,
ship in containers, and operate with clear health checks.

The project is open source under the Apache License, Version 2.0.

## What It Does

- Serves plain DNS over UDP and TCP.
- Can enable encrypted transports for DoT, DoH, DoQ, and DoH3.
- Hosts simple authoritative zones for internal DNS.
- Recurses only when explicitly enabled for trusted client CIDRs.
- Applies policy decisions across authoritative answers, cache hits, and recursive resolution.
- Provides memory or Redis-backed DNS response caching.
- Emits audit logs with retention and tenant-aware logging policies.
- Exposes `/live`, `/ready`, and `/metrics` for production operations.
- Exposes a localhost MCP endpoint for LLM-safe DNS operations and resolution.
- Reloads policy/config safely without accepting invalid runtime updates.

## DNS Transport Support

| Transport | Status | Configuration | Notes |
| --- | --- | --- | --- |
| DNS over UDP | Supported | `listen_addr` | Enabled by the main listener. |
| DNS over TCP | Supported | `listen_addr` | Enabled by the main listener. |
| DNS over TLS (DoT) | Supported | `transports.dot` | Requires certificate and private key paths. |
| DNS over HTTPS (DoH, HTTP/2) | Supported | `transports.doh` | Uses HTTP/2 and a configurable endpoint, default `/dns-query`. |
| DNS over QUIC (DoQ) | Supported | `transports.doq` | Uses a dedicated QUIC listener with ALPN `doq`. |
| DNS over HTTP/3 (DoH3) | Supported | `transports.doh3` | Uses a dedicated HTTP/3 listener with ALPN `h3`. |
| Oblivious DoH (ODoH) | WIP | `transports.doh.odoh` | Publishes `/.well-known/odohconfigs`; encrypted ODoH query handling is not complete yet. |
| DNSCrypt | WIP | None | Not implemented. |

## Authoritative Record Support

| Record type | Status | Configuration format | Notes |
| --- | --- | --- | --- |
| `SOA` | Supported | `zones[].soa` | Generated from the zone SOA block. |
| `NS` | Supported | `records.<owner>.NS.values` | Value is a name, for example `ns1.example.`. |
| `A` | Supported | `records.<owner>.A.values` | Value is an IPv4 address. |
| `AAAA` | Supported | `records.<owner>.AAAA.values` | Value is an IPv6 address. |
| `TXT` | Supported | `records.<owner>.TXT.values` | Each value becomes one TXT record. |
| `SRV` | Supported | `records.<owner>.SRV.values` | Value format is `<priority> <weight> <port> <target>`. |
| `ANY` query | Supported | Query only | Returns all configured RRsets for the queried owner name. |
| `CNAME` | WIP | None | Not implemented in the authoritative parser yet. |
| `MX` | WIP | None | Not implemented in the authoritative parser yet. |
| `PTR` | WIP | None | Not implemented in the authoritative parser yet. |
| `CAA` | WIP | None | Not implemented in the authoritative parser yet. |
| `SVCB` / `HTTPS` | WIP | None | Not implemented in the authoritative parser yet. |
| DNSSEC zone records | WIP | None | Authoritative signing and DNSSEC record management are not implemented. |

## Cargo Features

The default build keeps the full product surface enabled, so plain
`cargo build` and `cargo test` exercise all production feature gates. Smaller
binaries are opt-in with `--no-default-features`.

| Feature | Included by default | Enables |
| --- | --- | --- |
| `recursion` | Yes | Recursive upstream forwarding through the in-repo DNS wire implementation. |
| `redis-cache` | Yes | Redis-backed DNS response cache. |
| `audit-logging` | Yes | Tenant-aware audit logs, HMAC hashing, retention, and readiness checks. |
| `dot` | Yes | DNS over TLS. |
| `doh` | Yes | DNS over HTTPS over HTTP/2 and ODoH config publishing. |
| `doq` | Yes | DNS over QUIC. |
| `doh3` | Yes | DNS over HTTP/3. |
| `mcp` | Yes | Localhost Model Context Protocol endpoint for DNS tools. |

Example builds:

```bash
# Full build with all default features
cargo build --release

# Minimal authoritative DNS binary
cargo build --release --no-default-features

# Authoritative DNS plus DoT
cargo build --release --no-default-features --features dot

# Recursive resolver plus Redis cache, without encrypted transports
cargo build --release --no-default-features --features recursion,redis-cache
```

If a config file uses a capability that was compiled out, startup fails with a
clear validation error. For example, `caching.type = "redis"` requires
`redis-cache`, `transports.doh` requires `doh`, `transports.doq` requires
`doq`, and `transports.doh3` requires `doh3`.

## Quick Start

```bash
# Build the binary
cargo build

# Run with an explicit config file
cargo run -- --config config.json

# Run locally with default config fallback
cargo run -- --allow-default-config --allow-open-policy

# Run tests
cargo test

# Build an optimized release binary
cargo build --release
```

Production startup expects a real config file. The local fallback flag is meant
for development, demos, and tests.

## Configuration Example

```json
{
  "listen_addr": "0.0.0.0:8080",
  "policy_file_path": "policy.json",
  "caching": {
    "type": "memory",
    "max_entries": 100000
  },
  "mcp": {
    "enabled": true,
    "listen_addr": "127.0.0.1:8082",
    "endpoint": "/mcp",
    "resolve_client_ip": "127.0.0.1"
  },
  "recursion": {
    "enabled": true,
    "allowed_client_cidrs": ["10.0.0.0/8", "fd00::/8"]
  },
  "zones": [
    {
      "name": "corp.internal.",
      "soa": {
        "MNAME": "ns1.corp.internal.",
        "RNAME": "dns-admin.corp.internal.",
        "SERIAL": 2026022001,
        "REFRESH": 3600,
        "RETRY": 600,
        "EXPIRE": 1209600,
        "MINIMUM": 300,
        "ttl": 3600
      },
      "records": {
        "@": {
          "NS": { "ttl": 3600, "values": ["ns1.corp.internal."] },
          "A": { "ttl": 300, "values": ["10.10.0.53"] },
          "AAAA": { "ttl": 300, "values": ["fd00::53"] },
          "TXT": { "ttl": 300, "values": ["corp authoritative dns"] }
        },
        "api": {
          "A": { "ttl": 300, "values": ["10.10.1.10"] }
        },
        "_sip._tcp": {
          "SRV": { "ttl": 300, "values": ["10 5 5060 sip.corp.internal."] }
        }
      }
    }
  ]
}
```

`records` is a map of `owner_name -> record_type -> rrset`.

Each RRset has:

| Field | Meaning |
| --- | --- |
| `ttl` | Record TTL in seconds. |
| `values` | List of record values in the format expected by the record type. |

## Resolution Behavior

| Situation | Behavior |
| --- | --- |
| Query matches a configured zone and RRset | Returns an authoritative answer with `AA=true`. |
| Query matches a configured zone name but not the requested type | Returns `NOERROR` with the zone SOA in authority. |
| Query is inside a configured zone but name does not exist | Returns `NXDOMAIN` with the zone SOA in authority. |
| Query is outside configured zones and recursion is enabled for the client IP | Uses recursive resolution. |
| Query is outside configured zones and recursion is disabled or unauthorized | Returns `REFUSED`. |
| Policy denies a query | Returns `REFUSED`. |

## Policy Engine

DNS query evaluation is governed by the policy engine across:

- Authoritative zones
- Cache hits
- Recursive resolution

Policy config:

| Field | Meaning |
| --- | --- |
| `policy_file_path` | Optional path to policy JSON. |
| `rule_engine.max_trace_facts` | Max facts included in explain trace logs. |
| `rule_engine.enable_explain_logs` | Enables policy trace logging. |

Behavior:

- If `policy_file_path` is unset and `--allow-open-policy` is provided, DNS uses a built-in allow-all policy.
- If `policy_file_path` is set and invalid at startup, DNS fails to start.
- Invalid policy updates during live reload are rejected and the previous policy stays active.
- Removing `policy_file_path` during live reload restores the built-in default policy only when open policy is allowed.

Canonical policy spec:

- `dns_rule_engine_policy_spec.json`

## Live Reload

- DNS watches the config file path passed at startup, or `config.json` by default.
- When file content changes, it reparses and applies live-reloadable policy settings.
- Invalid updates are rejected and the previous in-memory config/policy remain active.
- Listener, transport, zone, resolver, cache, logging, health, MCP, recursion, and shutdown runtime changes require restart and are rejected during live reload.
- Reload is strict parse/validate only; missing or malformed config never falls back to defaults.

## MCP

When built with default features, TitaniumGuard DNS starts an MCP Streamable HTTP
endpoint on `127.0.0.1:8082/mcp`. The server uses the newest protocol version
supported by the bundled Rust MCP SDK and keeps the listener loopback-only by
default.

MCP config:

| Field | Meaning |
| --- | --- |
| `mcp.enabled` | Enables the MCP listener. Defaults to `true` with the `mcp` feature and `false` when compiled without it. |
| `mcp.listen_addr` | MCP HTTP listener. Defaults to `127.0.0.1:8082` and must be loopback. |
| `mcp.endpoint` | Streamable HTTP endpoint path. Defaults to `/mcp`. |
| `mcp.allowed_hosts` | Host header allowlist for DNS rebinding protection. Defaults to localhost entries. |
| `mcp.allowed_origins` | Optional browser Origin allowlist. Missing Origin still works for local clients. |
| `mcp.resolve_client_ip` | Synthetic client IP used by the `resolve` tool. Defaults to `127.0.0.1`. |

Tools:

| Tool | Meaning |
| --- | --- |
| `status` | Readiness, drain state, health, and counters. |
| `metrics` | Same text metrics exposed by `GET /metrics`. |
| `config_summary` | Non-secret runtime config summary. |
| `zones` | Configured authoritative zones, owners, and record types. |
| `resolve` | Resolves `hostname` and optional `record_type` through the live DNS policy, authoritative, cache, and recursion path. |

`resolve` supports `A`, `AAAA`, `TXT`, `SRV`, `NS`, and `SOA`. Recursive MCP
resolution obeys the normal recursion allowlist using `mcp.resolve_client_ip`;
include that IP in `recursion.allowed_client_cidrs` when MCP should resolve
external names recursively.

## Operations Runbook

### Endpoints

| Endpoint | Meaning |
| --- | --- |
| `GET /live` | Process is running. |
| `GET /ready` | Process can receive traffic. Returns `503` while draining, when required cache is unhealthy, or when enabled audit logging cannot write. |
| `GET /metrics` | Text metrics for readiness, drain state, active queries, cache health/errors, audit health/errors, policy denies, recursion denies, and reload results. |

### Recommended Probes

| Probe | Recommendation |
| --- | --- |
| Liveness | Use `/live` with a short timeout. Do not page on dependency failures from this probe. |
| Readiness | Use `/ready`; remove the instance from rotation on any `503`. |
| Metrics | Scrape `/metrics` and alert on `dns_ready 0`, `dns_cache_healthy 0` when `dns_cache_required 1`, `dns_audit_healthy 0`, rising `dns_audit_write_errors_total`, rising `dns_reload_failures_total`, and rising `dns_drain_timeouts_total`. |

### Startup Safety

- Production startup requires an existing config file.
- Production startup requires `policy_file_path` unless `--allow-open-policy` is explicitly set.
- Recursive resolution is denied by default; enable it with explicit trusted client CIDRs.
- The operational HTTP listener defaults to loopback.
- `/ready` fails closed for required Redis cache outages, audit sink failures, and shutdown drain.
- Audit logging gates readiness when enabled; startup probes the default tenant sink before accepting traffic.
- For local/dev fallback behavior, run with `--allow-default-config`.

### Redis Cache

- Memory cache is local and does not gate readiness.
- Redis cache can be optional or required with `caching.required`.
- Required Redis is checked at startup and by a periodic background probe.
- Readiness recovers after a successful bounded Redis probe.
- Redis operation timeouts use `caching.timeout_ms`.
- Repeated failures open cache health after `caching.failure_threshold`.
- Incident checks: confirm Redis reachability, authentication, service DNS, latency, and whether `dns_cache_errors_total` is rising.

### Audit Logs

- `logging.log_dir` must be service-owned and not group/world writable.
- Tenant directories and final log files must not be symlinks.
- Enabled audit logging gates readiness through a startup write probe and later write results.
- Disk incidents: check free space, inode exhaustion, mount state, file permissions, and retention settings.
- Retention is configured through default and per-tenant retention days; size storage for peak query volume plus retention.

### Shutdown And Rollout

- On SIGTERM/SIGINT, readiness flips to `503`.
- Active DNS queries drain until `shutdown.drain_timeout_seconds`.
- If drain timeout expires, `dns_drain_timeouts_total` increments and a warning is logged.
- Canary a new config/image with `/ready` and `/metrics` before widening traffic.
- Roll back by restoring the previous image/config and confirming `/ready` returns `200` and error counters stop increasing.

## Project Status

TitaniumGuard DNS is usable today for plain DNS, DoT, DoH, DoQ, DoH3, simple
authoritative zones, guarded recursion, caching, policy enforcement, and
production health checks. The biggest WIP areas are broader authoritative
record coverage, full ODoH query handling, DNSCrypt, and authoritative DNSSEC
signing.
