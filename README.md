# TitaniumGuard DNS

Open source Rust DNS service distributed as a single-binary Cargo package under
the Apache License, Version 2.0.

Live reload:
- DNS watches the config file path passed at startup (or `config.json` by default).
- When file content changes, it reparses and applies declared live-reloadable policy settings.
- Invalid updates are rejected and the previous in-memory config/policy are kept.
- Listener, transport, zone, resolver, cache, logging, health, recursion, and shutdown runtime changes require restart and are rejected during live reload.
- Reload is strict parse/validate only; missing or malformed config never falls back to defaults.

Startup safety:
- Production startup requires an existing config file.
- Production startup requires `policy_file_path` unless `--allow-open-policy` is explicitly set.
- Recursive resolution is denied by default; enable it with explicit trusted client CIDRs.
- The operational HTTP listener defaults to loopback and exposes `/live`, `/ready`, and `/metrics`.
- `/ready` fails closed for required Redis cache outages, audit sink failures, and shutdown drain.
- Audit logging is fail-closed for readiness when enabled; startup probes the default tenant sink before accepting traffic.
- For local/dev fallback behavior, run with `--allow-default-config`.

## Operations Runbook

Endpoints:
- `GET /live`: process is running.
- `GET /ready`: process can receive traffic. It returns `503` while draining, when a required cache is unhealthy, or when enabled audit logging cannot write.
- `GET /metrics`: text metrics for readiness, drain state, active queries, cache health/errors, audit health/errors, policy denies, recursion denies, and reload results.

Recommended probes:
- Liveness: `/live`, short timeout, no dependency alerts.
- Readiness: `/ready`, remove the instance from rotation on any `503`.
- Metrics scrape: `/metrics`, alert on `dns_ready 0`, `dns_cache_healthy 0` when `dns_cache_required 1`, `dns_audit_healthy 0`, increasing `dns_audit_write_errors_total`, increasing `dns_reload_failure_total`, and increasing `dns_drain_timeout_total`.

Redis cache:
- Memory cache is local and does not gate readiness.
- Redis cache can be optional or required with `caching.required`.
- Required Redis is checked at startup and by a periodic background probe; readiness recovers after a successful bounded probe.
- Redis operation timeouts use `caching.timeout_ms`; repeated failures open cache health after `caching.failure_threshold`.
- Incident checks: confirm Redis reachability, authentication, service DNS, latency, and whether `dns_cache_errors_total` is rising.

Audit logs:
- `logging.log_dir` must be service-owned and not group/world writable.
- Tenant directories and final log files must not be symlinks.
- Enabled audit logging gates readiness through a startup write probe and later write results.
- Disk incidents: check free space, inode exhaustion, mount state, file permissions, and retention settings.
- Retention is configured through default and per-tenant retention days; size storage for peak query volume plus retention.

Shutdown and rollout:
- On SIGTERM/SIGINT, readiness flips to `503` and active DNS queries drain until `shutdown.drain_timeout_seconds`.
- If drain timeout expires, `dns_drain_timeout_total` increments and a warning is logged.
- Canary a new config/image with `/ready` and `/metrics` before widening traffic.
- Roll back by restoring the previous image/config and confirming `/ready` returns `200` and error counters stop increasing.

## Policy Engine

DNS query evaluation is governed by the policy engine across all query paths:
- authoritative zones
- cache hits
- recursive resolution

Policy config:
- `policy_file_path`: optional path to policy JSON
- `rule_engine.max_trace_facts`: max facts included in explain trace logs
- `rule_engine.enable_explain_logs`: toggle policy trace logging

Behavior:
- If `policy_file_path` is unset, DNS uses built-in allow-all defaults.
- If `policy_file_path` is set and invalid at startup, DNS fails to start.
- On live config reload, invalid policy updates are rejected and previous policy stays active.
- On live config reload, removing `policy_file_path` restores the built-in default policy when open policy is allowed.
- Denied queries return DNS `REFUSED`.

Canonical policy spec:
- `dns_rule_engine_policy_spec.json`

## Commands

```bash
# Build binary
cargo build

# Run locally
cargo run -- --config config.json

# Run tests
cargo test
```

## Authoritative Zones

The DNS service can host authoritative internal zones and only recurse for
queries outside configured owned zones when recursion is enabled and the client
IP is allowed.

Resolution pipeline:
- Owned zone match -> authoritative answer (AA=true, no recursion)
- No owned zone match -> recursive resolution only when recursion is enabled and the client IP is allowed; otherwise `REFUSED`

Example `config.json` snippet:

```json
{
  "listen_addr": "0.0.0.0:8080",
  "caching": {
    "type": "memory",
    "max_entries": 100000
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

`records` is a map of `owner_name -> record_type -> rrset`, where each rrset is:
- `ttl`: record TTL
- `values`: list of string values

Supported record types for authoritative zones:
- `SOA` (from `zones.soa`)
- `NS`
- `A`
- `AAAA`
- `TXT`
- `SRV`
