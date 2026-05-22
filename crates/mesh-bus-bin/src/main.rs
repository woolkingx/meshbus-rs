//! mesh-bus binary: check/status/run YAML config.

mod operator_http;

use mesh_bus_runtime::{
    Config, EgressCfg, IngressCfg, LogFormat, OperatorCfg, parse_config, preflight_config, run,
    status_text,
};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse(std::env::args().skip(1));
    if let Command::Admin(admin) = cli.cmd {
        return run_admin(
            admin,
            &cli.path,
            cli.admin_api.as_deref(),
            cli.admin_token_file.as_deref(),
        );
    }

    let yaml = read_config_yaml(&cli.path)?;
    let cfg = parse_config(&yaml)?;

    match cli.cmd {
        Command::Check => {
            let base_dir = cli
                .path
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            preflight_config(&cfg, &base_dir)?;
            println!("ok {}", cli.path.display());
            Ok(())
        }
        Command::Status => {
            println!("{}", status_text(&cfg));
            Ok(())
        }
        Command::Run => {
            init_logging(cfg.logging.level.clone(), cfg.logging.format);
            let shutdown_signal = ShutdownSignal::new()?;
            let config_fingerprint = config_fingerprint(&yaml);
            log_startup_evidence(&cfg, &cli.path, &config_fingerprint);
            let base_dir = cli
                .path
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let operator_listener = match cfg.operator.as_ref() {
                Some(OperatorCfg::LocalHttp { listen, .. }) => Some(
                    tokio::net::TcpListener::bind(listen)
                        .await
                        .map_err(|e| anyhow::anyhow!("bind operator {listen}: {e}"))?,
                ),
                None => None,
            };
            let operator_cfg = if operator_listener.is_some() {
                let cfg = parse_config(&yaml)?;
                let auth_token = operator_http::load_auth_token(&cfg)?;
                Some((cfg, auth_token))
            } else {
                None
            };
            let handle = run(cfg, &base_dir).await?;
            if let (Some(listener), Some((operator_cfg, auth_token))) =
                (operator_listener, operator_cfg)
            {
                let snapshot = handle.snapshot_client();
                tokio::spawn(operator_http::serve_local_http(
                    listener,
                    operator_cfg,
                    cli.path.clone(),
                    yaml.clone(),
                    snapshot,
                    env!("CARGO_PKG_VERSION"),
                    auth_token,
                ));
            }

            shutdown_signal.wait().await?;
            if let Err(e) = handle
                .shutdown_with_timeout(std::time::Duration::from_secs(10))
                .await
            {
                tracing::warn!(target: "mesh_bus.bin", "shutdown drain timed out: {e}");
            }

            Ok(())
        }
        Command::Admin(_) => unreachable!("admin commands return before runtime config parsing"),
    }
}

fn read_config_yaml(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))
}

fn config_fingerprint(yaml: &str) -> String {
    let digest = Sha256::digest(yaml.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn log_startup_evidence(cfg: &Config, config_path: &Path, fingerprint: &str) {
    tracing::info!(
        target: "mesh_bus.bin",
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        config_fingerprint = fingerprint,
        status = %status_text(cfg),
        "mesh_bus_starting"
    );
    for peer in &cfg.peers {
        tracing::info!(
            target: "mesh_bus.bin",
            peer_id = peer.id,
            node_id = peer.node_id,
            route_groups = %join_labels(&peer.route_groups),
            meshsec = peer.meshsec.is_some(),
            "startup_peer"
        );
    }
    for ingress in &cfg.ingresses {
        log_ingress_startup(ingress);
    }
    for egress in &cfg.egresses {
        log_egress_startup(egress);
    }
}

fn log_ingress_startup(ingress: &IngressCfg) {
    match ingress {
        IngressCfg::Socks5 { listen, auth, .. } => tracing::info!(
            target: "mesh_bus.bin",
            kind = "Socks5",
            listen,
            auth = auth.as_ref().is_some_and(|a| !a.users.is_empty()),
            "startup_ingress"
        ),
        IngressCfg::HttpConnect { listen, auth, .. } => tracing::info!(
            target: "mesh_bus.bin",
            kind = "HttpConnect",
            listen,
            auth = auth.as_ref().is_some_and(|a| !a.users.is_empty()),
            "startup_ingress"
        ),
        IngressCfg::Tcp {
            listen,
            route_group,
            ..
        }
        | IngressCfg::Udp {
            listen,
            route_group,
            ..
        } => tracing::info!(
            target: "mesh_bus.bin",
            kind = ingress_kind(ingress),
            listen,
            route_group = route_group.as_deref().unwrap_or("-"),
            "startup_ingress"
        ),
        IngressCfg::MeshPeerUdp { listen, .. } => tracing::info!(
            target: "mesh_bus.bin",
            kind = "MeshPeerUdp",
            listen,
            "startup_ingress"
        ),
    }
}

fn log_egress_startup(egress: &EgressCfg) {
    tracing::info!(
        target: "mesh_bus.bin",
        kind = egress_kind(egress),
        exit_id = egress.id(),
        wan_id = egress.wan_id(),
        route_groups = %join_labels(egress.groups()),
        peer_id = egress_peer_id(egress),
        "startup_egress"
    );
}

fn ingress_kind(ingress: &IngressCfg) -> &'static str {
    match ingress {
        IngressCfg::Socks5 { .. } => "Socks5",
        IngressCfg::HttpConnect { .. } => "HttpConnect",
        IngressCfg::Tcp { .. } => "Tcp",
        IngressCfg::Udp { .. } => "Udp",
        IngressCfg::MeshPeerUdp { .. } => "MeshPeerUdp",
    }
}

fn egress_kind(egress: &EgressCfg) -> &'static str {
    match egress {
        EgressCfg::Tcp { .. } => "Tcp",
        EgressCfg::Socks5 { .. } => "Socks5",
        EgressCfg::Socks5Udp { .. } => "Socks5Udp",
        EgressCfg::Udp { .. } => "Udp",
        EgressCfg::MeshPeerUdp { .. } => "MeshPeerUdp",
        EgressCfg::ServiceTcp { .. } => "ServiceTcp",
        EgressCfg::ServiceUdp { .. } => "ServiceUdp",
    }
}

fn egress_peer_id(egress: &EgressCfg) -> &str {
    match egress {
        EgressCfg::MeshPeerUdp { peer_id, .. } => peer_id,
        _ => "-",
    }
}

fn join_labels(labels: &[String]) -> String {
    if labels.is_empty() {
        "-".to_string()
    } else {
        labels.join(",")
    }
}

struct ShutdownSignal {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl ShutdownSignal {
    fn new() -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            let terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(|e| anyhow::anyhow!("signal: {e}"))?;
            Ok(Self { terminate })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    async fn wait(mut self) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    result.map_err(|e| anyhow::anyhow!("signal: {e}"))?;
                }
                _ = self.terminate.recv() => {}
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .map_err(|e| anyhow::anyhow!("signal: {e}"))?;
            Ok(())
        }
    }
}

struct Cli {
    cmd: Command,
    path: PathBuf,
    admin_api: Option<String>,
    admin_token_file: Option<PathBuf>,
}

enum Command {
    Run,
    Check,
    Status,
    Admin(AdminCommand),
}

#[derive(Clone)]
enum AdminCommand {
    Status,
    ConfigCheck,
    ConfigEffective,
    MetricsSnapshot,
    Probe(ProbeCommand),
    Diagnose(DiagnoseCommand),
}

#[derive(Clone)]
struct ProbeCommand {
    kind: ProbeKind,
    target: String,
}

#[derive(Clone, Default)]
struct DiagnoseCommand {
    remote_ssh: Option<String>,
}

#[derive(Clone, Copy)]
enum ProbeKind {
    Socks5Connect,
    HttpConnect,
    MeshPeer,
}

impl ProbeKind {
    fn api_path(self) -> &'static str {
        match self {
            Self::Socks5Connect => "/probe/socks5",
            Self::HttpConnect => "/probe/http-connect",
            Self::MeshPeer => "/probe/mesh-peer",
        }
    }
}

impl Cli {
    fn parse(mut args: impl Iterator<Item = String>) -> Self {
        match args.next().as_deref() {
            Some("admin") => {
                let (cmd, path, admin_api, admin_token_file) = parse_admin_args(args);
                Self {
                    cmd: Command::Admin(cmd),
                    path,
                    admin_api,
                    admin_token_file,
                }
            }
            Some("run") => Self {
                cmd: Command::Run,
                path: parse_path_arg(args),
                admin_api: None,
                admin_token_file: None,
            },
            Some("check") => Self {
                cmd: Command::Check,
                path: parse_path_arg(args),
                admin_api: None,
                admin_token_file: None,
            },
            Some("status") => Self {
                cmd: Command::Status,
                path: parse_path_arg(args),
                admin_api: None,
                admin_token_file: None,
            },
            Some(path) => Self {
                cmd: Command::Run,
                path: path.into(),
                admin_api: None,
                admin_token_file: None,
            },
            None => Self {
                cmd: Command::Run,
                path: PathBuf::from("config/example.yaml"),
                admin_api: None,
                admin_token_file: None,
            },
        }
    }
}

fn parse_admin_args(
    args: impl Iterator<Item = String>,
) -> (AdminCommand, PathBuf, Option<String>, Option<PathBuf>) {
    let args: Vec<String> = args.collect();
    let (mut cmd, start) = match args.first().map(String::as_str) {
        Some("status") => (AdminCommand::Status, 1),
        Some("config-check") => (AdminCommand::ConfigCheck, 1),
        Some("config-effective") => (AdminCommand::ConfigEffective, 1),
        Some("metrics-snapshot") => (AdminCommand::MetricsSnapshot, 1),
        Some("diagnose") => (AdminCommand::Diagnose(DiagnoseCommand::default()), 1),
        Some("probe") => match args.get(1).map(String::as_str) {
            Some("socks5-connect") => (
                AdminCommand::Probe(ProbeCommand {
                    kind: ProbeKind::Socks5Connect,
                    target: "https://example.com".to_string(),
                }),
                2,
            ),
            Some("http-connect") => (
                AdminCommand::Probe(ProbeCommand {
                    kind: ProbeKind::HttpConnect,
                    target: "https://example.com".to_string(),
                }),
                2,
            ),
            Some("mesh-peer") => (
                AdminCommand::Probe(ProbeCommand {
                    kind: ProbeKind::MeshPeer,
                    target: "mesh-peer".to_string(),
                }),
                2,
            ),
            _ => (AdminCommand::Status, 0),
        },
        _ => (AdminCommand::Status, 0),
    };
    let mut path = PathBuf::from("config/example.yaml");
    let mut api = None;
    let mut token_file = None;
    let mut idx = start;
    while idx < args.len() {
        match args[idx].as_str() {
            "--config" => {
                if let Some(value) = args.get(idx + 1) {
                    path = value.into();
                }
                idx += 2;
            }
            "--api" => {
                if let Some(value) = args.get(idx + 1) {
                    api = Some(value.clone());
                }
                idx += 2;
            }
            "--token-file" => {
                if let Some(value) = args.get(idx + 1) {
                    token_file = Some(value.into());
                }
                idx += 2;
            }
            "--target" => {
                if let (AdminCommand::Probe(probe), Some(value)) = (&mut cmd, args.get(idx + 1)) {
                    probe.target = value.clone();
                }
                idx += 2;
            }
            "--peer" => {
                if let (AdminCommand::Probe(probe), Some(value)) = (&mut cmd, args.get(idx + 1)) {
                    probe.target = value.clone();
                }
                idx += 2;
            }
            "--remote-ssh" => {
                if let (AdminCommand::Diagnose(diagnose), Some(value)) =
                    (&mut cmd, args.get(idx + 1))
                {
                    diagnose.remote_ssh = Some(value.clone());
                }
                idx += 2;
            }
            other => {
                path = other.into();
                idx += 1;
            }
        }
    }
    (cmd, path, api, token_file)
}

fn parse_path_arg(mut args: impl Iterator<Item = String>) -> PathBuf {
    match args.next().as_deref() {
        Some("--config") => args
            .next()
            .unwrap_or_else(|| "config/example.yaml".into())
            .into(),
        Some(path) => path.into(),
        None => PathBuf::from("config/example.yaml"),
    }
}

fn run_admin(
    cmd: AdminCommand,
    path: &Path,
    api: Option<&str>,
    token_file: Option<&Path>,
) -> anyhow::Result<()> {
    if let Some(api) = api {
        return run_admin_api(cmd, api, token_file);
    }
    let yaml = read_config_yaml(path)?;
    let base_dir = path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    match cmd {
        AdminCommand::Status => {
            let cfg = parse_config(&yaml)?;
            let response = mesh_bus_operator_api::status_response(
                &cfg,
                path,
                &yaml,
                env!("CARGO_PKG_VERSION"),
            );
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
        AdminCommand::ConfigCheck => {
            let response = mesh_bus_operator_api::config_check_response(path, &yaml, &base_dir);
            println!("{}", serde_json::to_string_pretty(&response)?);
            if response.ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "operator config-check failed for {}",
                    path.display()
                ))
            }
        }
        AdminCommand::ConfigEffective => {
            let cfg = parse_config(&yaml)?;
            preflight_config(&cfg, &base_dir)?;
            let response = mesh_bus_operator_api::effective_config_response(path, &yaml)?;
            print!("{}", response.redacted_yaml);
            Ok(())
        }
        AdminCommand::MetricsSnapshot => Err(anyhow::anyhow!(
            "admin metrics-snapshot requires --api <url>"
        )),
        AdminCommand::Probe(_) => Err(anyhow::anyhow!("admin probe requires --api <url>")),
        AdminCommand::Diagnose(_) => Err(anyhow::anyhow!("admin diagnose requires --api <url>")),
    }
}

fn run_admin_api(cmd: AdminCommand, api: &str, token_file: Option<&Path>) -> anyhow::Result<()> {
    let path = match cmd {
        AdminCommand::Status => "/status",
        AdminCommand::ConfigEffective => "/config/effective",
        AdminCommand::MetricsSnapshot => "/metrics/snapshot",
        AdminCommand::Probe(probe) => {
            let token = match token_file {
                Some(path) => Some(read_token_file(path)?),
                None => None,
            };
            let body = serde_json::json!({ "target": probe.target }).to_string();
            let response = http_post_json(api, probe.kind.api_path(), &body, token.as_deref())?;
            println!("{response}");
            return Ok(());
        }
        AdminCommand::Diagnose(diagnose) => {
            let token = match token_file {
                Some(path) => Some(read_token_file(path)?),
                None => None,
            };
            let response = http_post_json(api, "/diagnose/bundle", "{}", token.as_deref())?;
            let mut value: serde_json::Value = serde_json::from_str(&response)?;
            if let Some(remote) = diagnose.remote_ssh {
                value["remote"] = remote_diagnose(&remote)?;
            }
            println!("{}", serde_json::to_string_pretty(&value)?);
            return Ok(());
        }
        AdminCommand::ConfigCheck => {
            return Err(anyhow::anyhow!(
                "admin config-check is config-only in M0; use --config <file>"
            ));
        }
    };
    let token = match token_file {
        Some(path) => Some(read_token_file(path)?),
        None => None,
    };
    let body = http_get(api, path, token.as_deref())?;
    println!("{body}");
    Ok(())
}

fn read_token_file(path: &Path) -> anyhow::Result<String> {
    let token = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read token file {}: {e}", path.display()))?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(anyhow::anyhow!("token file {} is empty", path.display()));
    }
    Ok(token)
}

fn remote_diagnose(remote: &str) -> anyhow::Result<serde_json::Value> {
    let systemd = ssh_capture(remote, "systemctl is-active mesh-bus.service || true")?;
    let sockets = ssh_capture(remote, "ss -lntup 2>/dev/null | grep mesh-bus || true")?;
    let journal = ssh_capture(
        remote,
        "journalctl -u mesh-bus.service -n 80 --no-pager 2>/dev/null || true",
    )?;
    let process = ssh_capture(
        remote,
        "pid=$(pidof mesh-bus 2>/dev/null || true); if [ -n \"$pid\" ]; then printf 'pid=%s\\n' \"$pid\"; grep -E '^(VmRSS|Threads|FDSize):' /proc/$pid/status; printf 'fd_count='; ls /proc/$pid/fd | wc -l; fi",
    )?;
    Ok(serde_json::json!({
        "ssh": remote,
        "systemd": redact_text(&systemd),
        "process": redact_text(&process),
        "sockets": redact_text(&sockets),
        "journal_tail": redact_text(&journal),
    }))
}

fn ssh_capture(remote: &str, command: &str) -> anyhow::Result<String> {
    let output = std::process::Command::new("ssh")
        .arg(remote)
        .arg(command)
        .output()
        .map_err(|e| anyhow::anyhow!("ssh {remote}: {e}"))?;
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text)
}

fn redact_text(input: &str) -> String {
    input
        .lines()
        .filter(|line| {
            !line.contains("static_key_hex")
                && !line.contains("MESH_BUS_MESHSEC_KEY_HEX")
                && !line.contains("password=")
                && !line.contains("Authorization:")
                && !line.contains("Bearer ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn http_get(api: &str, path: &str, token: Option<&str>) -> anyhow::Result<String> {
    http_request(api, "GET", path, "", token)
}

fn http_post_json(
    api: &str,
    path: &str,
    body: &str,
    token: Option<&str>,
) -> anyhow::Result<String> {
    http_request(api, "POST", path, body, token)
}

fn http_request(
    api: &str,
    method: &str,
    path: &str,
    body: &str,
    token: Option<&str>,
) -> anyhow::Result<String> {
    let authority = api
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("operator api URL must start with http://, got {api}"))?;
    let authority = authority.trim_end_matches('/');
    let mut stream =
        TcpStream::connect(authority).map_err(|e| anyhow::anyhow!("connect {api}: {e}"))?;
    let auth = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let content = if body.is_empty() {
        String::new()
    } else {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\n{auth}{content}Connection: close\r\n\r\n{body}"
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("operator api {api} returned malformed HTTP response"))?;
    if !head.starts_with("HTTP/1.1 200 ") {
        return Err(anyhow::anyhow!(
            "operator api {api}{path} failed: {}",
            head.lines().next().unwrap_or(head)
        ));
    }
    Ok(body.to_string())
}

fn init_logging(level: String, format: LogFormat) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        LogFormat::Compact => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .compact()
            .init(),
        LogFormat::Pretty => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .pretty()
            .init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init(),
    }
}
