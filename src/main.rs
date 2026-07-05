mod caching;
mod config;
mod dns;
mod forwarder;
#[path = "livereload/lib.rs"]
mod livereload;
mod logging;
#[cfg(feature = "mcp")]
mod mcp;
mod ops;
mod policy;
mod secure;
mod server;

use caching::DnsRecordCache;
use caching::build_dns_record_cache;
use config::{AppConfig, DEFAULT_CONFIG_PATH};
use forwarder::{Forwarder, RuntimeState};
use livereload::watch_file;
use logging::LoggingPipeline;
use policy::PolicyRuntime;
use secure::register_secure_transports;
use std::env;
use std::future;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::runtime::Builder;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep, timeout};
#[cfg(feature = "mcp")]
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

type DynResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone)]
struct CliArgs {
    config_path: String,
    allow_default_config: bool,
    allow_open_policy: bool,
}

impl CliArgs {
    fn from_env() -> DynResult<Self> {
        Self::parse(env::args().skip(1))
    }

    fn parse<I>(args: I) -> DynResult<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut args = args.into_iter();
        let mut config_path: Option<String> = None;
        let mut allow_default_config = false;
        let mut allow_open_policy = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--allow-default-config" => allow_default_config = true,
                "--allow-open-policy" => allow_open_policy = true,
                "--config" => {
                    let value = args.next().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "--config requires a value")
                    })?;
                    config_path = Some(value);
                }
                _ if arg.starts_with("--config=") => {
                    config_path = Some(arg.trim_start_matches("--config=").to_string());
                }
                _ if arg.starts_with('-') => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown argument: {arg}"),
                    )
                    .into());
                }
                _ => {
                    config_path = Some(arg);
                }
            }
        }

        Ok(Self {
            config_path: config_path.unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string()),
            allow_default_config,
            allow_open_policy,
        })
    }
}

fn require_policy_file_if_needed(config: &AppConfig, allow_open_policy: bool) -> DynResult<()> {
    if allow_open_policy {
        return Ok(());
    }
    if config.policy_file_path.as_deref().is_none() {
        return Err("policy_file_path is required unless --allow-open-policy is set".into());
    }
    Ok(())
}

fn main() -> DynResult<()> {
    Builder::new_multi_thread()
        .worker_threads(runtime_worker_threads())
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> DynResult<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = CliArgs::from_env()?;
    let config_path = args.config_path.clone();
    let config = if args.allow_default_config {
        AppConfig::load_or_default(&args.config_path)?
    } else {
        AppConfig::load_required(&args.config_path)?
    };
    config.validate(!args.allow_default_config)?;
    require_policy_file_if_needed(&config, args.allow_open_policy)?;
    let runtime_config = Arc::new(RwLock::new(config.clone()));
    let runtime_state = RuntimeState::default();
    let policy_runtime = Arc::new(
        PolicyRuntime::from_file_or_default(
            config.policy_file_path.as_deref(),
            config.rule_engine.clone(),
        )
        .await?,
    );
    tokio::spawn(run_config_reloader(
        config_path.clone(),
        runtime_config.clone(),
        policy_runtime.clone(),
        runtime_state.clone(),
        args.allow_open_policy,
        !args.allow_default_config,
    ));
    let logging_pipeline = Arc::new(LoggingPipeline::from_config(&config.logging));
    logging_pipeline.clone().start_retention_task();

    let root_hints = config.root_hints();
    let cache = build_dns_record_cache(&config.caching)?;
    let cache_healthy = cache.check_health().await;
    runtime_state.update_cache_health(cache.is_required(), cache_healthy, cache.error_count());
    spawn_required_cache_health_probe(cache.clone(), runtime_state.clone());
    runtime_state.update_audit_health(true, 0);
    let forwarder = Forwarder::with_cache_and_recursion(
        &root_hints,
        &config.zones,
        cache,
        logging_pipeline,
        policy_runtime,
        runtime_state.clone(),
        &config.recursion,
    )?;
    let audit_healthy = match forwarder.check_audit_health() {
        Ok(healthy) => healthy,
        Err(err) => {
            warn!(error = %err, "dns audit sink health check failed");
            false
        }
    };
    runtime_state.update_audit_health(audit_healthy, forwarder.audit_write_error_count());
    let health_listener = ops::bind(config.health.listen_addr).await?;
    #[cfg(feature = "mcp")]
    let mcp_listener = if config.mcp.enabled {
        Some(TcpListener::bind(config.mcp.listen_addr).await?)
    } else {
        None
    };
    #[cfg(feature = "mcp")]
    let mcp_cancellation = CancellationToken::new();
    let udp_socket = UdpSocket::bind(config.listen_addr).await?;
    let tcp_listener = TcpListener::bind(config.listen_addr).await?;
    info!("listening on udp {}", config.listen_addr);
    info!("listening on tcp {}", config.listen_addr);
    let udp_task = tokio::spawn(server::serve_udp(udp_socket, forwarder.clone()));
    let tcp_task = tokio::spawn(server::serve_tcp(
        tcp_listener,
        forwarder.clone(),
        Duration::from_secs(10),
    ));
    register_secure_transports(&config, forwarder.clone()).await?;
    let secure_task = None;
    runtime_state.mark_ready();
    tokio::spawn(ops::serve(health_listener, runtime_state.clone()));
    #[cfg(feature = "mcp")]
    if let Some(listener) = mcp_listener {
        let forwarder = forwarder.clone();
        let runtime_state = runtime_state.clone();
        let runtime_config = runtime_config.clone();
        let mcp_config = config.mcp.clone();
        let cancellation = mcp_cancellation.child_token();
        tokio::spawn(async move {
            if let Err(err) = mcp::serve(
                listener,
                forwarder,
                runtime_state,
                runtime_config,
                mcp_config,
                cancellation,
            )
            .await
            {
                warn!(error = %err, "mcp server stopped");
            }
        });
    }

    tokio::select! {
        result = udp_task => join_server_task("udp dns", result)?,
        result = tcp_task => join_server_task("tcp dns", result)?,
        result = wait_optional_server_task("secure dns", secure_task) => result?,
        _ = shutdown_signal() => {
            info!("shutdown signal received; draining dns");
            #[cfg(feature = "mcp")]
            mcp_cancellation.cancel();
            runtime_state.mark_draining();
            let drain = Duration::from_secs(config.shutdown.drain_timeout_seconds);
            if timeout(drain, wait_until_idle(runtime_state.clone())).await.is_err() {
                runtime_state.inc_drain_timeouts();
                warn!(
                    drain_timeout_seconds = config.shutdown.drain_timeout_seconds,
                    "dns drain timeout elapsed before active queries completed"
                );
            }
        }
    }
    Ok(())
}

async fn wait_optional_server_task(
    name: &'static str,
    task: Option<JoinHandle<io::Result<()>>>,
) -> io::Result<()> {
    match task {
        Some(task) => join_server_task(name, task.await),
        None => future::pending().await,
    }
}

fn join_server_task(
    name: &'static str,
    result: Result<io::Result<()>, tokio::task::JoinError>,
) -> io::Result<()> {
    match result {
        Ok(result) => result,
        Err(err) => Err(io::Error::other(format!("{name} task failed: {err}"))),
    }
}

fn spawn_required_cache_health_probe(cache: Arc<dyn DnsRecordCache>, runtime_state: RuntimeState) {
    if !cache.is_required() {
        return;
    }

    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            let healthy = cache.check_health().await;
            runtime_state.update_cache_health(cache.is_required(), healthy, cache.error_count());
        }
    });
}

fn runtime_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install sigterm handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn wait_until_idle(runtime_state: RuntimeState) {
    while !runtime_state.is_idle() {
        sleep(Duration::from_millis(25)).await;
    }
}

async fn run_config_reloader(
    config_path: String,
    runtime_config: Arc<RwLock<AppConfig>>,
    policy_runtime: Arc<PolicyRuntime>,
    runtime_state: RuntimeState,
    allow_open_policy: bool,
    strict_mode: bool,
) {
    info!("starting config reload watcher on {}", config_path);
    let mut listener = watch_file(config_path.clone());
    while let Some(_event) = listener.next_event().await {
        match AppConfig::load_required(&config_path) {
            Ok(next) => {
                if let Err(err) = next.validate(strict_mode) {
                    runtime_state.inc_reload_failures();
                    warn!("failed dns config validation during reload: {}", err);
                    continue;
                }
                if let Err(err) = require_policy_file_if_needed(&next, allow_open_policy) {
                    runtime_state.inc_reload_failures();
                    warn!("failed dns policy guard during reload: {}", err);
                    continue;
                }
                {
                    let current = runtime_config.read().await;
                    if restart_required(&current, &next) {
                        runtime_state.inc_reload_requires_restart();
                        warn!(
                            "dns config reload contains restart-required changes; keeping active runtime"
                        );
                        continue;
                    }
                }
                if let Err(err) = policy_runtime
                    .reload_if_configured(
                        next.policy_file_path.as_deref(),
                        next.rule_engine.clone(),
                    )
                    .await
                {
                    runtime_state.inc_reload_failures();
                    warn!(
                        "failed to reload policy file from {}: {}",
                        next.policy_file_path
                            .as_ref()
                            .map_or_else(|| "<unset>".to_string(), ToString::to_string),
                        err
                    );
                    continue;
                }
                let mut current = runtime_config.write().await;
                *current = next;
                runtime_state.inc_reload_successes();
                info!("reloaded dns config from {}", config_path);
            }
            Err(err) => {
                runtime_state.inc_reload_failures();
                warn!("failed to reload dns config from {}: {}", config_path, err);
            }
        }
    }
    error!("config reload watcher stopped for {}", config_path);
}

fn restart_required(current: &AppConfig, next: &AppConfig) -> bool {
    format!("{:?}", current.listen_addr) != format!("{:?}", next.listen_addr)
        || format!("{:?}", current.resolvers) != format!("{:?}", next.resolvers)
        || format!("{:?}", current.zones) != format!("{:?}", next.zones)
        || format!("{:?}", current.transports) != format!("{:?}", next.transports)
        || format!("{:?}", current.caching) != format!("{:?}", next.caching)
        || format!("{:?}", current.logging) != format!("{:?}", next.logging)
        || format!("{:?}", current.health) != format!("{:?}", next.health)
        || format!("{:?}", current.mcp) != format!("{:?}", next.mcp)
        || format!("{:?}", current.recursion) != format!("{:?}", next.recursion)
        || format!("{:?}", current.shutdown) != format!("{:?}", next.shutdown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parser_supports_strict_flags() {
        let parsed = CliArgs::parse(vec![
            "--config=/tmp/dns.json".to_string(),
            "--allow-default-config".to_string(),
            "--allow-open-policy".to_string(),
        ])
        .expect("args should parse");
        assert_eq!(parsed.config_path, "/tmp/dns.json");
        assert!(parsed.allow_default_config);
        assert!(parsed.allow_open_policy);
    }

    #[test]
    fn policy_file_is_required_without_override() {
        let config = AppConfig::default();
        let err = require_policy_file_if_needed(&config, false).expect_err("should fail");
        assert!(err.to_string().contains("policy_file_path is required"));
    }
}
