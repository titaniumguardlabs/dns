# Repository Instructions

## Project Shape

TitaniumGuard DNS is a single-binary Rust DNS server. The binary target is
`titaniumguard-dns` and its entrypoint is `src/main.rs`.

Core behavior:

- Plain DNS over UDP and TCP is served from `listen_addr`.
- Optional encrypted transports are DoT, DoH, DoQ, and DoH3.
- Authoritative zones support `SOA`, `NS`, `A`, `AAAA`, `TXT`, `SRV`, and
  `ANY` queries. `CNAME`, `MX`, `PTR`, `CAA`, `SVCB`/`HTTPS`, authoritative
  DNSSEC signing, DNSCrypt, and full ODoH query handling are WIP.
- Recursive resolution is denied by default and must be explicitly enabled for
  trusted client CIDRs.
- Policy decisions apply across authoritative answers, cache hits, and
  recursive resolution.
- Caching can be memory-backed or Redis-backed.
- Audit logging is tenant-aware and can gate readiness.
- Operational endpoints are `/live`, `/ready`, and `/metrics`.
- MCP is a local-only operational interface by default at `127.0.0.1:8082/mcp`.

## Important Modules

- `src/main.rs`: startup, listener registration, live reload, shutdown drain, and
  feature-gated transport/MCP wiring.
- `src/config/`: configuration schema, defaults, validation, HPKE helpers, and
  config tests.
- `src/forwarder/`: DNS request handling, authoritative zone behavior, recursion,
  cache integration, and runtime state/metrics.
- `src/policy/`: policy parsing, facts, evaluation, compile helpers, and explain
  traces.
- `src/logging/`: audit logging, tenant policy, retention, hashing, EDNS logging,
  and health checks.
- `src/caching/`: memory and Redis cache backends.
- `src/secure.rs`: encrypted DNS transport support.
- `src/mcp.rs`: MCP tools for status, metrics, config summary, zones, and controlled
  DNS resolution through the live DNS path.
- `src/ops.rs`: HTTP operational endpoints.
- `dns_rule_engine_policy_spec.json`: canonical policy spec.

## Cargo Features

Default features intentionally enable the full production surface:

- `recursion`
- `redis-cache`
- `audit-logging`
- `dot`
- `doh`
- `doq`
- `doh3`
- `mcp`

Use default-feature builds for ordinary validation unless the task is explicitly
about a reduced binary. If a config uses a feature that was compiled out,
startup should fail with a clear validation error.

Common commands:

```bash
cargo test
cargo build
cargo build --release
cargo build --release --no-default-features
cargo build --release --no-default-features --features dot
cargo build --release --no-default-features --features recursion,redis-cache
```

The release profile uses LTO, `panic = "abort"`, stripping, one codegen unit,
and `opt-level = 3`.

## Operational Semantics

- Production startup expects an explicit config file.
- `--allow-default-config` is for local development, demos, and tests.
- `policy_file_path` is required in production unless `--allow-open-policy` is
  explicitly used.
- Invalid startup config or policy must fail startup.
- Invalid live reload updates must be rejected while the previous in-memory
  config/policy remains active.
- Live reload can update live-reloadable policy settings only. Listener,
  transport, zone, resolver, cache, logging, health, MCP, recursion, and
  shutdown runtime changes require restart and must be rejected during reload.
- Recursive resolution must remain gated by `recursion.allowed_client_cidrs`.
- Required Redis cache health and enabled audit logging must fail readiness
  closed when unhealthy.
- Shutdown flips readiness to `503`, waits for active queries to drain, and
  increments `dns_drain_timeouts_total` on drain timeout.

## Metrics And Probes

- `/live` is only process liveness.
- `/ready` returns `503` while draining, when required cache is unhealthy, or
  when enabled audit logging cannot write.
- `/metrics` is Prometheus text output generated through the Prometheus crate.
- Keep alert-oriented metric names and README examples in sync with emitted
  metrics. Current alert examples include:
  - `dns_ready 0`
  - `dns_cache_healthy 0` when `dns_cache_required 1`
  - `dns_audit_healthy 0`
  - rising `dns_audit_write_errors_total`
  - rising `dns_reload_failures_total`
  - rising `dns_drain_timeouts_total`

## MCP Semantics

- The MCP listener must remain loopback-only unless an authenticated MCP
  listener is deliberately added.
- `mcp.allowed_hosts` protects against DNS rebinding.
- `mcp.allowed_origins` is optional; missing browser Origin is allowed for local
  clients.
- `mcp.resolve_client_ip` is the synthetic source IP for the MCP `resolve` tool.
  Recursive MCP resolution must still pass the normal recursion allowlist using
  this IP.
- MCP tools are read-only operational tools: `status`, `metrics`,
  `config_summary`, `zones`, and `resolve`.
- MCP `resolve` supports `A`, `AAAA`, `TXT`, `SRV`, `NS`, and `SOA`.

## Docker

The Dockerfile is Alpine-based for both builder and runtime.

- Builder image: `rust:1.96.1-alpine`.
- Runtime image: `alpine:3.22`.
- Builder installs `build-base`, `ca-certificates`, `cmake`, `linux-headers`,
  `ninja`, `perl`, and `pkgconf`.
- Runtime installs only `ca-certificates`, creates a non-root
  `titaniumguard` user, and runs as that user.
- Exposed ports are `8080/tcp`, `8080/udp`, `8081/tcp`, and `8082/tcp`.
- The image entrypoint is `/usr/local/bin/titaniumguard-dns`.
- `BUILD_PROFILE=debug` runs `cargo build --locked --all-features`.
- `BUILD_PROFILE=release` runs
  `cargo build --locked --release --all-features`.

Useful validation:

```bash
docker build --build-arg BUILD_PROFILE=debug -t titaniumguard-dns:debug-local .
docker build --build-arg BUILD_PROFILE=release -t titaniumguard-dns:release-local .
```

## GitHub Workflow

The workflow is `.github/workflows/rust.yml`.

Workflow triggers:

- Pull requests targeting `main`.
- Pushes to `main`.
- Any tag push.

Workflow graph:

1. `test` runs first and executes `cargo test`.
2. `codeql` runs only after `test` succeeds.
3. `cargo-build` and `docker-build` both depend on `codeql`, so they run in
   parallel after CodeQL passes.

Cargo job behavior:

- Pull requests run `cargo build`.
- Pushes to `main` and tag pushes run `cargo build --release`.
- Tag pushes then run `cargo login "$CARGO_REGISTRY_TOKEN"` and
  `cargo publish --locked`.
- `CARGO_REGISTRY_TOKEN` must be configured as a repository secret.
- Crates.io versions come from `Cargo.toml`; `cargo publish` cannot override
  the version from the CLI. Keep tag names and `Cargo.toml` versions aligned.

Docker job behavior:

- Uses `docker/setup-buildx-action`.
- Logs in to GHCR only for pushes to `main` or tags.
- Uses a single `docker/build-push-action` step.
- Pull requests pass `BUILD_PROFILE=debug` and do not push.
- Pushes to `main` pass `BUILD_PROFILE=release` and push `latest`.
- Tag pushes pass `BUILD_PROFILE=release` and push the tag name.
- Published image names use `ghcr.io/${{ github.repository }}`.

## Release Expectations

Before creating a release tag:

- Update `Cargo.toml` `version`.
- Ensure the tag version matches the manifest version, with a leading `v`
  stripped if using `vX.Y.Z` tag names.
- Confirm the release path can pass `cargo build --release`.
- The tag workflow will publish the crate and push the Docker image tag only
  after tests and CodeQL pass.

## Change Guidelines

- Keep changes scoped to the requested behavior.
- Do not broaden the Docker image into a generic workspace image.
- Do not add test stages inside the Dockerfile unless explicitly requested;
  CI owns tests.
- Preserve the default all-features product surface unless the task is
  specifically about feature reduction.
- Keep README operational examples synchronized with code, workflow behavior,
  Docker build arguments, and emitted metrics.
- When changing workflow behavior, keep the existing job graph unless the user
  asks for a new graph.
- When changing release behavior, avoid adding new jobs unless the user asks;
  reuse existing jobs where possible.
- Use `rg` for repo searches.
- Prefer focused validation commands that match the touched area, then broaden
  to `cargo test` or Docker builds when the blast radius warrants it.

## Validation Checklist

Use the smallest meaningful set for the change:

- Rust code: `cargo test`.
- Compile-only changes: `cargo build`.
- Release-sensitive changes: `cargo build --release`.
- Dockerfile profile changes:
  - `docker build --build-arg BUILD_PROFILE=debug -t titaniumguard-dns:debug-local .`
  - `docker build --build-arg BUILD_PROFILE=release -t titaniumguard-dns:release-local .`
- Workflow changes: parse `.github/workflows/rust.yml` and use `actionlint` if
  available.
- Metrics endpoint changes: include focused `ops` and `forwarder::runtime`
  tests, and keep `/metrics` README names current.
