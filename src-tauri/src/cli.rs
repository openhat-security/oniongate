//! `oniongate` — the headless companion.
//!
//! The CLI links the same core modules as the GUI. Full protected-session
//! orchestration parity is still pre-stable: `start` currently owns managed Tor
//! but not the GUI's TUN/firewall/proxy sequence.

use clap::{Parser, Subcommand};

use crate::settings;
use crate::tor;

#[derive(Parser)]
#[command(
    name = "oniongate",
    about = "OnionGate — headless companion for Tor routing and onion hosting",
    version,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show connection, bootstrap, and recovery status.
    Status,
    /// Connect Tor using the saved strategy.
    Start,
    /// Best-effort cleanup using the recovery journal and live process discovery.
    Stop,
    /// Request a new Tor identity (NEWNYM).
    Newnym {
        /// Terminate processes with live clearnet sockets, then NEWNYM.
        #[arg(long)]
        kill_clearnet: bool,
    },
    /// List configured bridge lines.
    Bridges,
    /// Print current settings as JSON.
    Settings,
    /// Publish and manage onion sites.
    #[command(subcommand)]
    Host(HostCommand),
    /// Privileged helper daemon (install, status, remove).
    #[command(subcommand)]
    Helper(HelperCommand),
}

#[derive(Subcommand)]
enum HelperCommand {
    /// Show whether the helper is installed and reachable.
    Status,
    /// Install or refresh the helper and start it.
    Start,
    /// Unload and remove the helper.
    Stop,
}

#[derive(Subcommand)]
enum HostCommand {
    /// List permanent and temporary sites.
    Ls,
    /// Create a permanent site that keeps its address across restarts.
    Add {
        /// Name used to identify the site.
        nickname: String,
        /// Loopback port your server already listens on.
        #[arg(long)]
        local_port: u16,
        /// Port visitors use on the onion address.
        #[arg(long, default_value_t = 80)]
        onion_port: u16,
        /// Create it public instead of requiring client authorization.
        #[arg(long)]
        public: bool,
    },
    /// Delete a permanent site and destroy its key.
    Rm {
        /// Site id as shown by `host ls`.
        id: String,
    },
    /// Publish a temporary site whose key is discarded immediately.
    Temp {
        /// Loopback port your server already listens on.
        #[arg(long)]
        local_port: u16,
        /// Port visitors use on the onion address.
        #[arg(long, default_value_t = 80)]
        onion_port: u16,
        /// Create it public instead of requiring client authorization.
        #[arg(long)]
        public: bool,
    },
    /// Check a site's listener, publication, and headers.
    Audit {
        /// Permanent site id, or a temporary site's onion address.
        id: String,
    },
    /// Manage client authorization for a permanent site.
    #[command(subcommand)]
    Auth(AuthCommand),
}

#[derive(Subcommand)]
enum AuthCommand {
    /// List credential names issued for a site.
    Ls { id: String },
    /// Issue a credential. The private half is printed once and never stored.
    Add { id: String, name: String },
    /// Revoke a single credential by name.
    Rm { id: String, name: String },
    /// Require client authorization.
    On { id: String },
    /// Stop requiring client authorization, making the site public.
    Off { id: String },
}

/// Exit codes: 0 success, 1 runtime failure, 2 usage error.
pub async fn run(args: &[String]) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            let usage = matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp
                    | clap::error::ErrorKind::DisplayVersion
                    | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            );
            let _ = err.print();
            return if usage { 0 } else { 2 };
        }
    };

    match cli.command.unwrap_or(Command::Status) {
        Command::Status => status().await,
        Command::Start => start().await,
        Command::Stop => stop().await,
        Command::Newnym { kill_clearnet } => newnym(kill_clearnet).await,
        Command::Bridges => {
            let s = settings::load();
            if s.bridge_lines.is_empty() {
                println!("(no bridges configured)");
            } else {
                for line in &s.bridge_lines {
                    println!("{line}");
                }
            }
            0
        }
        Command::Settings => match serde_json::to_string_pretty(&settings::load()) {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(e) => fail(e.to_string()),
        },
        Command::Host(command) => host(command).await,
        Command::Helper(command) => helper(command),
    }
}

fn helper(command: HelperCommand) -> i32 {
    match command {
        HelperCommand::Status => {
            let status = crate::helper::service::status();
            println!("supported={}", status.supported);
            println!("installed={}", status.installed);
            println!("running={}", status.running);
            println!("detail={}", status.detail);
            if status.running {
                0
            } else {
                1
            }
        }
        HelperCommand::Start => report(crate::helper::service::ensure()),
        HelperCommand::Stop => report(crate::helper::service::uninstall()),
    }
}

fn fail(message: String) -> i32 {
    eprintln!("error: {message}");
    1
}

fn report(result: Result<String, String>) -> i32 {
    match result {
        Ok(message) => {
            println!("{message}");
            0
        }
        Err(e) => fail(e),
    }
}

async fn newnym(kill_clearnet: bool) -> i32 {
    if kill_clearnet {
        let _ = crate::egress_watch::sample_now();
        match crate::apps_lifecycle::kill_clearnet_processes().await {
            Ok(kill) => println!("{}", kill.detail),
            Err(e) => return fail(e),
        }
    }
    report(tor::new_identity().await)
}

async fn status() -> i32 {
    let s = settings::load();
    println!("tor_installed={}", tor::find_tor_binary().is_some());
    println!("socks_up={}", tor::socks_reachable());
    println!("control_up={}", tor::control_reachable());
    println!("dns_up={}", tor::dns_reachable());
    println!("smart_connect={}", s.smart_connect);
    println!("bridges_enabled={}", s.bridges_enabled);
    println!("bridge_count={}", s.bridge_lines.len());
    println!("connection_mode={}", s.connection_mode);
    println!("kill_switch={}", s.kill_switch);
    println!("exit_country={}", s.exit_country);
    let recovery = crate::session::recovery_status();
    println!("session_phase={:?}", recovery.phase);
    println!("recovery_needed={}", recovery.needed);
    println!(
        "permanent_sites={}",
        crate::onion_service::persistent::list().len()
    );
    println!("temporary_sites={}", crate::onion_service::list().len());
    let watch = crate::egress_watch::sample_now();
    println!("egress_watch_active={}", watch.watching);
    println!("egress_bypass={}", watch.bypass);
    if tor::control_reachable() {
        match tor::bootstrap_progress().await {
            Ok(p) => println!("bootstrap={p}"),
            Err(e) => println!("bootstrap_error={e}"),
        }
    }
    0
}

async fn start() -> i32 {
    if let Err(e) = crate::session::begin_connect() {
        return fail(e);
    }
    let mut managed = None;
    let outcome = if settings::load().smart_connect {
        tor::smart_connect(&mut managed).await.map(|r| r.message)
    } else {
        tor::start_tor(&mut managed).await
    };
    match outcome {
        Ok(msg) => {
            let _ = crate::session::set_phase(
                crate::session::SessionPhase::Degraded,
                Some(
                    "CLI start brought up managed Tor only; TUN, kill switch, and proxy are not applied"
                        .into(),
                ),
            );
            println!("{msg}");
            println!(
                "session_phase=Degraded (managed Tor only; use the desktop app for a Protected boundary)"
            );
            // Keep the managed child alive for the session rather than killing
            // it when this process exits.
            std::mem::forget(managed);
            0
        }
        Err(e) => {
            let _ =
                crate::session::set_phase(crate::session::SessionPhase::Degraded, Some(e.clone()));
            fail(e)
        }
    }
}

async fn stop() -> i32 {
    let journal = crate::session::load();
    let managed_tor = tokio::sync::Mutex::new(None);
    let managed_singbox = tokio::sync::Mutex::new(None);
    let managed_snowflake = tokio::sync::Mutex::new(None);
    let saved_proxy = std::sync::Mutex::new(journal.original_proxy.unwrap_or_default());
    report(
        crate::cleanup::teardown_session(
            &managed_tor,
            &managed_singbox,
            &managed_snowflake,
            &saved_proxy,
            crate::cleanup::TeardownMode::RestoreHost,
        )
        .await,
    )
}

async fn host(command: HostCommand) -> i32 {
    use crate::onion_service::persistent;

    match command {
        HostCommand::Ls => {
            let sites = persistent::list();
            if sites.is_empty() {
                println!("(no permanent sites)");
            }
            for site in &sites {
                println!(
                    "{}\t{}\t{}\t127.0.0.1:{} -> :{}\t{}",
                    site.id,
                    site.nickname,
                    site.hostname.as_deref().unwrap_or("(publishing)"),
                    site.local_port,
                    site.virtual_port,
                    if site.auth_enabled {
                        format!("auth:{}", site.clients.len())
                    } else {
                        "public".into()
                    }
                );
            }
            for project in crate::onion_service::list() {
                println!(
                    "(temporary)\t-\t{}\t127.0.0.1:{} -> :{}\t{}",
                    project.hostname,
                    project.local_port,
                    project.virtual_port,
                    if project.private { "auth" } else { "public" }
                );
            }
            0
        }
        HostCommand::Add {
            nickname,
            local_port,
            onion_port,
            public,
        } => match persistent::add(&nickname, local_port, onion_port, !public).await {
            Ok(site) => {
                match &site.hostname {
                    Some(host) => println!("{host}"),
                    None => println!(
                        "{} created; Tor is still publishing its address (run `host ls`)",
                        site.id
                    ),
                }
                if !public {
                    println!(
                        "Client authorization is on. Issue a credential with: \
                         oniongate host auth add {} <name>",
                        site.id
                    );
                }
                0
            }
            Err(e) => fail(e),
        },
        HostCommand::Rm { id } => report(persistent::remove(&id).await),
        HostCommand::Temp {
            local_port,
            onion_port,
            public,
        } => match crate::onion_service::start(local_port, onion_port, !public).await {
            Ok(project) => {
                println!("{}", project.hostname);
                if let Some(credential) = &project.client_credential {
                    println!(
                        "{}:{}",
                        project.hostname.trim_end_matches(".onion"),
                        credential
                    );
                }
                println!("This site disappears when Tor stops. Its key is already discarded.");
                0
            }
            Err(e) => fail(e),
        },
        HostCommand::Audit { id } => {
            let audit = if persistent::get(&id).is_some() {
                crate::onion_service::audit_permanent(&id).await
            } else {
                crate::onion_service::audit_temporary(id.trim_end_matches(".onion")).await
            };
            match audit {
                Ok(audit) => {
                    println!("listener={}", audit.listener.detail);
                    println!("loopback_only={}", audit.listener.loopback_only);
                    println!("published={}", audit.published);
                    if let Some(ms) = audit.latency_ms {
                        println!("latency_ms={ms}");
                    }
                    if let Some(code) = audit.http_status {
                        println!("http_status={code}");
                    }
                    if !audit.security_headers.is_empty() {
                        println!("security_headers={}", audit.security_headers.join(","));
                    }
                    for warning in &audit.warnings {
                        println!("warning={warning}");
                    }
                    0
                }
                Err(e) => fail(e),
            }
        }
        HostCommand::Auth(command) => auth(command).await,
    }
}

async fn auth(command: AuthCommand) -> i32 {
    use crate::onion_service::persistent;

    match command {
        AuthCommand::Ls { id } => match persistent::get(&id) {
            Some(site) => {
                println!("auth_enabled={}", site.auth_enabled);
                for name in &site.clients {
                    println!("{name}");
                }
                0
            }
            None => fail("No permanent site with that id".into()),
        },
        AuthCommand::Add { id, name } => match persistent::add_client(&id, &name).await {
            Ok(issued) => {
                // Printed once. Nothing writes this to disk.
                match &issued.auth_private_line {
                    Some(line) => println!("{line}"),
                    None => println!("{}", issued.credential),
                }
                eprintln!(
                    "Copy the line above into the client's <name>.auth_private file. \
                     It is not stored and cannot be shown again."
                );
                0
            }
            Err(e) => fail(e),
        },
        AuthCommand::Rm { id, name } => report(persistent::revoke_client(&id, &name).await),
        AuthCommand::On { id } => match persistent::set_auth_enabled(&id, true).await {
            Ok(_) => {
                println!("Client authorization is on");
                0
            }
            Err(e) => fail(e),
        },
        AuthCommand::Off { id } => match persistent::set_auth_enabled(&id, false).await {
            Ok(_) => {
                println!("Client authorization is off — anyone with the address can connect");
                0
            }
            Err(e) => fail(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn bare_invocation_defaults_to_status() {
        let cli = Cli::try_parse_from(["oniongate"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn host_add_requires_a_local_port() {
        assert!(Cli::try_parse_from(["oniongate", "host", "add", "blog"]).is_err());
        assert!(
            Cli::try_parse_from(["oniongate", "host", "add", "blog", "--local-port", "3000"])
                .is_ok()
        );
    }

    #[test]
    fn onion_port_defaults_to_eighty() {
        let cli = Cli::try_parse_from(["oniongate", "host", "add", "blog", "--local-port", "3000"])
            .unwrap();
        match cli.command {
            Some(Command::Host(HostCommand::Add {
                onion_port, public, ..
            })) => {
                assert_eq!(onion_port, 80);
                // Authorization is on unless explicitly opted out of.
                assert!(!public);
            }
            _ => panic!("expected host add"),
        }
    }

    #[test]
    fn auth_subcommands_parse() {
        assert!(Cli::try_parse_from(["oniongate", "host", "auth", "add", "blog", "alice"]).is_ok());
        assert!(Cli::try_parse_from(["oniongate", "host", "auth", "rm", "blog", "alice"]).is_ok());
        assert!(Cli::try_parse_from(["oniongate", "host", "auth", "off", "blog"]).is_ok());
        assert!(Cli::try_parse_from(["oniongate", "host", "auth", "add", "blog"]).is_err());
    }

    #[test]
    fn newnym_kill_clearnet_flag_parses() {
        let cli = Cli::try_parse_from(["oniongate", "newnym", "--kill-clearnet"]).unwrap();
        match cli.command {
            Some(Command::Newnym { kill_clearnet }) => assert!(kill_clearnet),
            _ => panic!("expected newnym"),
        }
        let cli = Cli::try_parse_from(["oniongate", "newnym"]).unwrap();
        match cli.command {
            Some(Command::Newnym { kill_clearnet }) => assert!(!kill_clearnet),
            _ => panic!("expected newnym"),
        }
    }

    #[test]
    fn helper_subcommands_parse() {
        assert!(Cli::try_parse_from(["oniongate", "helper", "status"]).is_ok());
        assert!(Cli::try_parse_from(["oniongate", "helper", "start"]).is_ok());
        assert!(Cli::try_parse_from(["oniongate", "helper", "stop"]).is_ok());
        assert!(Cli::try_parse_from(["oniongate", "helper"]).is_err());
    }
}
