use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use clap_repl::ClapEditor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};

const LISTEN_ADDR: &str = "127.0.0.1:10999";
const TOR_PROXY: &str = "127.0.0.1";
const TOR_PORT: &str = "10808";
const TABLE: &str = "100";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Parser)]
#[command(name = "vpn-proxy", about = "HTTP proxy on 127.0.0.1:10999 routed through tun0 (openvpn)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Start openvpn (if needed) + the HTTP proxy on 127.0.0.1:10999
    Start {
        /// .ovpn to use if openvpn isn't running (default: last used)
        config: Option<String>,
    },
    /// Stop the proxy and the app-managed openvpn
    Stop,
    /// Show proxy, tun0 and openvpn status
    Status,
    /// Switch openvpn to another .tcp. config (restarts tunnel, proxy follows)
    Switch {
        /// Config name, e.g. nl-free-165 (empty = list available)
        config: Option<String>,
    },
    /// Switch openvpn to a random .tcp. config from a directory
    SwitchRandom {
        /// Directory to pick a random config from
        dir: String,
    },
    /// Stop everything and quit
    Exit,
}

#[derive(Default)]
struct ProxyState {
    task: Option<tokio::task::JoinHandle<()>>,
    tun_ip: Option<Ipv4Addr>,
    vpn_child: Option<Child>,
    vpn_config: Option<PathBuf>,
}

// ---------- sync helpers (shell out) ----------

fn run(prog: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run `{prog}`: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn sh(args: &[&str]) -> Result<String, String> {
    run("ip", args)
}

/// IPv4 address currently assigned to tun0.
fn tun_ip() -> Result<Ipv4Addr, String> {
    let out = sh(&["-o", "-4", "addr", "show", "dev", "tun0"])
        .map_err(|_| "tun0 is not up".to_string())?;
    let mut it = out.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "inet" {
            if let Some(cidr) = it.next() {
                if let Some((addr, _)) = cidr.split_once('/') {
                    if let Ok(ip) = addr.parse() {
                        return Ok(ip);
                    }
                }
            }
        }
    }
    Err("tun0 has no IPv4 address".to_string())
}

/// Send everything *from* the tun IP through tun0 (table 100), leaving the
/// main table — and the rest of the system — untouched.
fn routes_up(ip: Ipv4Addr) -> Result<(), String> {
    let _ = sh(&["route", "add", "default", "dev", "tun0", "table", TABLE]);
    let _ = sh(&["rule", "add", "from", &ip.to_string(), "table", TABLE]);
    if sh(&["rule", "show"])?.contains(&format!("from {} lookup {TABLE}", ip)) {
        Ok(())
    } else {
        Err("policy rule not installed — are you root?".to_string())
    }
}

fn routes_down(ip: Ipv4Addr) {
    let _ = sh(&["rule", "del", "from", &ip.to_string(), "table", TABLE]);
    let _ = sh(&["route", "del", "default", "dev", "tun0", "table", TABLE]);
}

/// Current tun IP, keeping the policy rule in sync (self-heals if openvpn
/// reconnected with a new IP behind our back).
fn ensure_routing(state: &Arc<Mutex<ProxyState>>) -> Result<Ipv4Addr, String> {
    let ip = tun_ip()?;
    let mut s = state.lock().unwrap();
    if s.tun_ip != Some(ip) {
        if let Some(old) = s.tun_ip.take() {
            routes_down(old);
        }
        routes_up(ip).map_err(|e| {
            s.tun_ip = None;
            e
        })?;
        s.tun_ip = Some(ip);
    }
    Ok(ip)
}

fn openvpn_config() -> Option<String> {
    let out = run("pgrep", &["-a", "openvpn"]).ok()?;
    let args: Vec<&str> = out.split_whitespace().collect();
    args.windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| w[1].to_owned())
}

// ---------- openvpn process ownership ----------

/// True if an openvpn process (ours or external) is alive.
fn vpn_process_alive(state: &Arc<Mutex<ProxyState>>) -> bool {
    let mut s = state.lock().unwrap();
    if let Some(child) = s.vpn_child.as_mut() {
        if child.try_wait().ok().flatten().is_none() {
            return true;
        }
    }
    openvpn_config().is_some()
}

/// SIGTERM a child (lets openvpn clean up tun0), SIGKILL if stubborn, then reap.
fn terminate_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        let _ = child.wait(); // reap zombie
        return;
    }
    let pid = child.id().to_string();
    let _ = run("kill", &[&pid]);
    for _ in 0..50 {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Proton TCP configs ship `up/down /etc/openvpn/update-resolv-conf`
/// (Debian-only, missing on Arch). We manage routes ourselves via table 100
/// and don't want pushed DNS touching system resolv.conf, so strip those
/// lines via a temp copy — the originals stay untouched.
fn sanitized_config(cfg: &std::path::Path) -> Result<PathBuf, String> {
    let content = std::fs::read_to_string(cfg)
        .map_err(|e| format!("cannot read {}: {e}", cfg.display()))?;
    let mut out = String::with_capacity(content.len());
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with("up ") || t.starts_with("down ") || t == "up" || t == "down" {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    let tmp = std::env::temp_dir().join(format!(
        "open-switch-{}.ovpn",
        cfg.file_stem().and_then(|s| s.to_str()).unwrap_or("vpn")
    ));
    std::fs::write(&tmp, out).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    Ok(tmp)
}

/// Launch supervised openvpn for cfg; waits for tun0 (kills child on timeout).
/// --http-proxy rides on the CLI so any stock TCP config tunnels via Tor untouched.
fn vpn_spawn(orig: &std::path::Path) -> Result<Child, String> {
    let dir = orig.parent().unwrap_or(std::path::Path::new("."));
    let auth = dir.join("auth.txt");
    if !auth.is_file() {
        return Err(format!("auth.txt not found next to {}", orig.display()));
    }
    let cfg = sanitized_config(orig)?;
    let log = dir.join("openvpn.log");
    let mut child = Command::new("openvpn")
        .arg("--config")
        .arg(cfg)
        .arg("--auth-user-pass")
        .arg(&auth)
        .arg("--auth-nocache")
        .arg("--route-nopull")
        .arg("--http-proxy")
        .arg(TOR_PROXY)
        .arg(TOR_PORT)
        .arg("--log")
        .arg(&log)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to launch openvpn: {e}"))?;
    if !wait_for_tun(false, 70) {
        terminate_child(&mut child);
        let mut msg = format!(
            "openvpn did not bring up tun0 within 70s, tail of {}:",
            log.display()
        );
        if let Ok(text) = std::fs::read_to_string(&log) {
            for l in text.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev() {
                msg.push_str(&format!("\n  {l}"));
            }
        }
        return Err(msg);
    }
    Ok(child)
}

// ---------- async HTTP proxy ----------

async fn dial_via(ip: Ipv4Addr, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
    let addr = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no IPv4 address"))?;
    let sock = TcpSocket::new_v4()?;
    sock.bind(SocketAddr::new(ip.into(), 0))?;
    tokio::time::timeout(CONNECT_TIMEOUT, sock.connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?
}

async fn handle_client(mut client: tokio::net::TcpStream, state: Arc<Mutex<ProxyState>>) {
    // read the request headers (plus maybe the start of a body)
    let mut head = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        match client.read(&mut tmp).await {
            Ok(0) | Err(_) => return, // client went away, nothing to answer
            Ok(n) => {
                head.extend_from_slice(&tmp[..n]);
                if head.len() > 65536 {
                    eprintln!("proxy: oversized headers, dropping");
                    return;
                }
                if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            }
        }
    };
    let text = String::from_utf8_lossy(&head[..header_end]).into_owned();
    let extra = head[header_end..].to_vec(); // body bytes already read / pipelined data
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("HTTP/1.1");

    // (host:port, first bytes for upstream, is CONNECT tunnel)
    let (hostport, prefix, is_connect): (String, Vec<u8>, bool) = if method == "CONNECT" {
        (target.to_owned(), Vec::new(), true)
    } else if let Some(rest) = target.strip_prefix("http://") {
        let (hp, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        // rewrite absolute-form to origin-form, keep the headers as-is
        let mut req = format!("{method} {path} {version}").into_bytes();
        req.extend_from_slice(text[request_line.len()..].as_bytes());
        (hp.to_owned(), req, false)
    } else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return;
    };

    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_owned(), port),
            Err(_) => (hostport.clone(), if is_connect { 443 } else { 80 }),
        },
        None => (hostport.clone(), if is_connect { 443 } else { 80 }),
    };
    let host = host.trim_matches(|c| c == '[' || c == ']').to_owned();

    // resolve the tun IP fresh for every connection; never silently drop
    let mut ip = match ensure_routing(&state) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("proxy: tunnel down ({e}), refusing {method} {hostport}");
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return;
        }
    };
    let mut upstream = match dial_via(ip, &host, port).await {
        Ok(u) => u,
        Err(e) => {
            // tunnel may have reconnected with a new IP — refresh once and retry
            eprintln!("proxy: dial {hostport} via {ip} failed ({e}), refreshing tun IP");
            match ensure_routing(&state) {
                Ok(fresh) if fresh != ip => {
                    ip = fresh;
                    match dial_via(ip, &host, port).await {
                        Ok(u) => u,
                        Err(e) => {
                            eprintln!("proxy: redial {hostport} via {ip} failed ({e})");
                            let _ = client
                                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                                .await;
                            return;
                        }
                    }
                }
                _ => {
                    let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                }
            }
        }
    };
    if is_connect {
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
    } else if upstream.write_all(&prefix).await.is_err() {
        return;
    }
    if !extra.is_empty() && upstream.write_all(&extra).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

async fn run_proxy(state: Arc<Mutex<ProxyState>>) {
    let listener = match TcpListener::bind(LISTEN_ADDR).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {LISTEN_ADDR}: {e}");
            return;
        }
    };
    println!("listening on {LISTEN_ADDR}");
    loop {
        match listener.accept().await {
            Ok((client, _)) => {
                tokio::spawn(handle_client(client, state.clone()));
            }
            Err(_) => continue,
        }
    }
}

// ---------- REPL commands ----------

fn cmd_start(
    state: &Arc<Mutex<ProxyState>>,
    rt: &tokio::runtime::Handle,
    config: Option<String>,
) {
    {
        let s = state.lock().unwrap();
        if let Some(h) = &s.task {
            if !h.is_finished() {
                println!("already running on {LISTEN_ADDR}");
                return;
            }
        }
    }
    // 1. tunnel: reuse a live one, else launch our own supervised openvpn
    if !vpn_process_alive(state) {
        let cfg = match config {
            Some(n) => match resolve_config(&n) {
                Ok(c) => c,
                Err(e) => {
                    println!("{e}");
                    return;
                }
            },
            None => match state.lock().unwrap().vpn_config.clone() {
                Some(c) => c,
                None => {
                    println!("no openvpn running — run: switch <config> or start <config>");
                    return;
                }
            },
        };
        println!("starting openvpn with {} ...", cfg.display());
        match vpn_spawn(&cfg) {
            Ok(child) => {
                let mut s = state.lock().unwrap();
                s.vpn_child = Some(child);
                s.vpn_config = Some(cfg);
            }
            Err(e) => {
                println!("{e}");
                return;
            }
        }
    }
    if let Err(e) = ensure_routing(state) {
        println!("cannot start: {e}");
        return;
    }
    let ip = state.lock().unwrap().tun_ip.unwrap();
    state.lock().unwrap().task = Some(rt.spawn(run_proxy(state.clone())));
    // if bind failed the task exits immediately — roll back instead of lying
    std::thread::sleep(Duration::from_millis(400));
    let mut s = state.lock().unwrap();
    if s.task.as_ref().is_some_and(|h| h.is_finished()) {
        routes_down(ip);
        s.task = None;
        s.tun_ip = None;
        println!("failed to start, see error above");
    } else {
        println!("started: http proxy on {LISTEN_ADDR} via tun0 ({ip})");
    }
}

fn cmd_stop(state: &Arc<Mutex<ProxyState>>) {
    let mut s = state.lock().unwrap();
    match s.task.take() {
        Some(h) => {
            h.abort();
            println!("stopped proxy on {LISTEN_ADDR}");
        }
        None => println!("proxy not running"),
    }
    if let Some(ip) = s.tun_ip.take() {
        routes_down(ip);
    }
    let child = s.vpn_child.take();
    drop(s);
    match child {
        Some(mut c) => {
            if c.try_wait().ok().flatten().is_none() {
                terminate_child(&mut c);
                println!("openvpn stopped");
            } else {
                println!("openvpn had already exited");
            }
        }
        None if openvpn_config().is_some() => {
            println!("openvpn left running (not started by app)")
        }
        None => {}
    }
}

fn cmd_status(state: &Arc<Mutex<ProxyState>>) {
    let s = state.lock().unwrap();
    match (&s.task, s.tun_ip) {
        (Some(h), Some(ip)) if !h.is_finished() => {
            println!("proxy: running on {LISTEN_ADDR} via tun0 ({ip})")
        }
        _ => println!("proxy: stopped"),
    }
    drop(s);
    match tun_ip() {
        Ok(ip) => println!("tun0: {ip}"),
        Err(_) => println!("tun0: down"),
    }
    let managed = state
        .lock()
        .unwrap()
        .vpn_child
        .as_mut()
        .is_some_and(|c| c.try_wait().ok().flatten().is_none());
    match openvpn_config() {
        Some(c) => println!(
            "openvpn: {c}{}",
            if managed { " (managed)" } else { " (external)" }
        ),
        None => println!("openvpn: not running"),
    }
}

/// Sorted *.tcp.ovpn files directly inside dir.
fn tcp_configs_in(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.ends_with(".tcp.ovpn"))
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn list_configs() {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let names: Vec<String> = tcp_configs_in(&cwd)
        .iter()
        .filter_map(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(str::to_owned)
        })
        .collect();
    if names.is_empty() {
        println!("no *.tcp.ovpn configs in {}", cwd.display());
    } else {
        println!("available (switch <name>):");
        for n in names {
            println!("  {n}");
        }
    }
}

/// Reject non-TCP configs (UDP cannot go through the proxy).
fn ensure_tcp(path: &std::path::Path) -> Result<(), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if content.lines().any(|l| l.trim() == "proto tcp") {
        Ok(())
    } else {
        Err(format!(
            "{} is not TCP — UDP cannot go through the proxy, pick a .tcp. config",
            path.display()
        ))
    }
}

/// Uniform-ish index without extra deps (urandom, time fallback).
fn random_index(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let mut b = [0u8; 8];
        if std::io::Read::read_exact(&mut f, &mut b).is_ok() {
            return (u64::from_le_bytes(b) % n as u64) as usize;
        }
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as usize % n)
        .unwrap_or(0)
}

/// Resolve a `switch` argument to an absolute .ovpn path, rejecting UDP.
fn resolve_config(name: &str) -> Result<PathBuf, String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut cands = if name.contains('/') {
        vec![PathBuf::from(name)]
    } else {
        let mut v = vec![cwd.join(name), cwd.join(format!("{name}.tcp.ovpn"))];
        if let Ok(rd) = std::fs::read_dir(&cwd) {
            let mut extra: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(name) && n.ends_with(".tcp.ovpn"))
                })
                .collect();
            extra.sort();
            v.append(&mut extra);
        }
        v
    };
    let path = cands
        .drain(..)
        .find(|p| p.is_file())
        .ok_or_else(|| format!("no such config: {name}"))?;
    ensure_tcp(&path)?;
    path.canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", path.display()))
}

fn wait_for_tun(gone: bool, secs: u64) -> bool {
    for _ in 0..secs {
        match (tun_ip().is_ok(), gone) {
            (false, true) | (true, false) => return true,
            _ => std::thread::sleep(Duration::from_secs(1)),
        }
    }
    matches!((tun_ip().is_ok(), gone), (false, true) | (true, false))
}

fn cmd_switch(state: &Arc<Mutex<ProxyState>>, name: Option<String>) {
    let Some(name) = name else {
        list_configs();
        return;
    };
    let cfg = match resolve_config(&name) {
        Ok(c) => c,
        Err(e) => {
            println!("{e}");
            return;
        }
    };
    do_switch(state, &cfg);
}

fn cmd_switch_random(state: &Arc<Mutex<ProxyState>>, dir: String) {
    let Ok(d) = PathBuf::from(&dir).canonicalize() else {
        println!("not a directory: {dir}");
        return;
    };
    if !d.is_dir() {
        println!("not a directory: {}", d.display());
        return;
    }
    let mut cands = tcp_configs_in(&d);
    if cands.is_empty() {
        println!("no *.tcp.ovpn configs in {}", d.display());
        return;
    }
    // avoid an immediate no-op re-pick when alternatives exist
    if cands.len() > 1 {
        let cur = state.lock().unwrap().vpn_config.clone();
        if let Some(c) = cur {
            cands.retain(|p| *p != c);
        }
    }
    let pick = cands[random_index(cands.len())].clone();
    if let Err(e) = ensure_tcp(&pick) {
        println!("{e}");
        return;
    }
    println!("random pick: {}", pick.display());
    do_switch(state, &pick);
}

fn do_switch(state: &Arc<Mutex<ProxyState>>, cfg: &std::path::Path) {
    let cfg = cfg.canonicalize().unwrap_or_else(|_| cfg.to_path_buf());
    println!("switching openvpn to {} ...", cfg.display());
    if let Some(mut c) = state.lock().unwrap().vpn_child.take() {
        terminate_child(&mut c);
    }
    let _ = run("pkill", &["-x", "openvpn"]); // take over strays
    if !wait_for_tun(true, 12) {
        println!("old openvpn did not stop, aborting switch");
        return;
    }
    let child = match vpn_spawn(&cfg) {
        Ok(c) => c,
        Err(e) => {
            println!("{e}");
            return;
        }
    };
    {
        let mut s = state.lock().unwrap();
        s.vpn_child = Some(child);
        s.vpn_config = Some(cfg.clone());
    }
    let Ok(ip) = tun_ip() else {
        println!("tun0 vanished right after coming up");
        return;
    };
    {
        // proxy (if running) follows automatically; just re-point its rule
        let mut s = state.lock().unwrap();
        let running = s.task.as_ref().is_some_and(|h| !h.is_finished());
        if let Some(old) = s.tun_ip.take() {
            routes_down(old);
        }
        if running {
            match routes_up(ip) {
                Ok(()) => s.tun_ip = Some(ip),
                Err(e) => println!("warning: {e}"),
            }
        }
    }
    println!("openvpn now: {} (tun0 {ip})", cfg.display());
    println!("verify exit IP: curl -x http://{LISTEN_ADDR} https://api.ipify.org");
}

#[tokio::main]
async fn main() {
    let rt = tokio::runtime::Handle::current();
    let state = Arc::new(Mutex::new(ProxyState::default()));
    println!("commands: start | stop | status | switch [config] | switch-random <dir> | exit  (proxy: {LISTEN_ADDR})");
    let st = state.clone();
    ClapEditor::<Cli>::builder().build().repl(move |cli| match cli.cmd {
        Cmd::Start { config } => cmd_start(&st, &rt, config),
        Cmd::Stop => cmd_stop(&st),
        Cmd::Status => cmd_status(&st),
        Cmd::Switch { config } => cmd_switch(&st, config),
        Cmd::SwitchRandom { dir } => cmd_switch_random(&st, dir),
        Cmd::Exit => {
            cmd_stop(&st);
            std::process::exit(0);
        }
    });
    cmd_stop(&state); // Ctrl-D: leave no routes behind
}
