use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use std::{collections::BTreeMap, net::IpAddr, path::PathBuf};
use x2shell_check::{
    collector,
    config::{self, Config},
    evidence_lab, fingerprints, portal, scanner,
};
#[derive(Parser)]
#[command(
    name = "x2shell-check",
    version,
    about = "x2shell-check · 服务暴露面自查台"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// 导出或校验可配置的网站特征库
    Fingerprints {
        #[command(subcommand)]
        action: FingerprintCommand,
    },
    /// 生成配置和随机个人账号密码，扫描范围默认为空
    Init {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long, default_value = "admin")]
        user: String,
        /// 免密码访问，各浏览器会话独立隔离
        #[arg(long)]
        allow_anonymous: bool,
        /// 允许省略网段/端口白名单；非空列表仍生效
        #[arg(long)]
        allow_without_whitelist: bool,
    },
    /// 增加个人账号；配置修改后须重启服务
    AddUser {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long)]
        user: String,
    },
    /// 新增独立管理员账号，可查看全站历史；密码随机生成
    AddAdmin {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long, default_value = "admin")]
        user: String,
    },
    /// 启动 Web 自查台
    Serve {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1")]
        bind: IpAddr,
        #[arg(long, default_value_t = 8080)]
        port: u16,
        #[arg(long)]
        fingerprints: Option<PathBuf>,
    },
    /// 检测单个 URL，退出码 0=达到上游基线，1=疑似受影响，2=参数/配置错误，3=未知
    Check {
        #[arg(value_parser = check_target)]
        target: String,
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long)]
        headers_only: bool,
        /// 覆盖 config.json 中的特征库文件（相对当前目录）
        #[arg(long)]
        fingerprints: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// 在当前 Linux 主机执行只读采集，JSON 输出至 stdout
    Collect(collector::CollectArgs),
    /// 使用内置合成数据离线验证六项证据规则；不连接目标、不执行 PHP
    OfflinePoc {
        /// 输出完整 JSON，而不是人类可读摘要
        #[arg(long)]
        json: bool,
    },
    /// 离线比较两份主机运行时报告，严格区分 Web 与 CLI
    CompareReports {
        /// 修复前的 php-selfcheck-host/v1 JSON
        #[arg(long)]
        before: PathBuf,
        /// 修复后的 php-selfcheck-host/v1 JSON
        #[arg(long)]
        after: PathBuf,
        /// 输出完整 JSON，而不是人类可读摘要
        #[arg(long)]
        json: bool,
    },
}
#[derive(Subcommand)]
enum FingerprintCommand {
    /// 将内置完整特征库导出为可编辑 JSON，不覆盖已有文件
    Export {
        #[arg(long, default_value = "fingerprints.json")]
        output: PathBuf,
    },
    /// 校验 JSON、规则 ID、正则和资源上限，输出有效库信息
    Validate {
        #[arg(long)]
        file: PathBuf,
    },
}
fn fingerprint_override(cfg: &mut Config, file: Option<PathBuf>) -> Result<()> {
    if let Some(file) = file {
        cfg.fingerprint_file = Some(std::fs::canonicalize(file)?.to_string_lossy().into_owned());
    }
    Ok(())
}
fn check_target(value: &str) -> std::result::Result<String, String> {
    scanner::normalize(value)
        .map(|u| u.to_string())
        .map_err(|e| e.to_string())
}

const COLLECT_WORKER: &str = "--internal-collect-worker";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const COLLECT_OUTPUT: &str = "--internal-collect-output";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_COLLECT_OUTPUT: usize = 1024 * 1024;

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn supervise_collect(seconds: u64, format: collector::CollectFormat) -> Result<i32> {
    use std::{process::Stdio, time::Duration};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        signal::unix::{SignalKind, signal},
        time::{Instant, sleep_until, timeout},
    };

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    #[cfg(target_os = "linux")]
    let reap_helpers = unsafe {
        libc::prctl(
            libc::PR_SET_CHILD_SUBREAPER,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } == 0;
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .arg(COLLECT_WORKER)
        .args(std::env::args_os().skip(1))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()?;
    // Keep the sole write end alive until the worker group has been stopped.
    let _liveness = child.stdin.take().expect("piped worker liveness");
    let pid = child.id().expect("new worker has a process ID") as libc::pid_t;
    let mut pipe = child.stdout.take().expect("piped worker output");
    let mut output = Vec::new();
    let result = async {
        // The collector's host report budget is 190 kB. Allow extra space for CSV formatting.
        (&mut pipe)
            .take(MAX_COLLECT_OUTPUT as u64 + 1)
            .read_to_end(&mut output)
            .await?;
        if output.len() > MAX_COLLECT_OUTPUT {
            return Err(std::io::Error::other("本机巡检报告超过输出上限"));
        }
        // Observe exit while retaining the group leader's PID reservation.
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let code = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                )
            };
            if code == 0 {
                if unsafe { info.si_pid() } == pid {
                    return Ok(());
                }
            } else {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    let (result, interruption) = tokio::select! {
        result = result => (Some(result), None),
        _ = sleep_until(deadline) => (None, None),
        _ = interrupt.recv() => (None, Some(130)),
        _ = terminate.recv() => (None, Some(143)),
        _ = hangup.recv() => (None, Some(129)),
    };
    // Signal before reaping the leader. Its numerical process group cannot be recycled here.
    if !matches!(&result, Some(Err(error)) if error.raw_os_error() == Some(libc::ECHILD)) {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let status = tokio::time::timeout(Duration::from_millis(100), child.wait()).await;
    #[cfg(target_os = "linux")]
    if reap_helpers && child.id().is_none() {
        let _ = tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                // The worker is reaped. Any remaining children in this group are orphaned helpers.
                match unsafe { libc::waitpid(-pid, std::ptr::null_mut(), libc::WNOHANG) } {
                    ..=-1 => break,
                    0 => tokio::time::sleep(Duration::from_millis(5)).await,
                    _ => {}
                }
            }
        })
        .await;
    }
    if let Some(code) = interruption {
        return Ok(code);
    }
    let (exit_code, output_deadline) = if let Some(result) = result {
        if result.is_err() {
            return Ok(2);
        }
        let status = status??;
        (status.code().unwrap_or(3), deadline)
    } else {
        if !matches!(format, collector::CollectFormat::Json) {
            return Ok(3);
        }
        let report = serde_json::json!({
            "schema":"php-selfcheck-host/v1","source":"developer_supplied_unverified","status":"timeout",
            "coverage":{"scan_timed_out":true,"scan_timeout_seconds":seconds},
            "audit":{"evidence_incomplete":true,"reason":"scan_timeout"}
        });
        output = serde_json::to_vec_pretty(&report)?;
        output.push(b'\n');
        // The acquisition deadline has elapsed. Allow a short, bounded attempt to deliver
        // the timeout record to a reader that is still consuming output.
        (3, Instant::now() + Duration::from_millis(250))
    };
    if output.is_empty() || Instant::now() >= output_deadline {
        return Ok(if output.is_empty() { exit_code } else { 3 });
    }

    // A separate process owns blocking stdout writes. Making the inherited descriptor
    // nonblocking would also change the caller's open file description.
    let mut publisher = tokio::process::Command::new(std::env::current_exe()?)
        .arg(COLLECT_OUTPUT)
        .arg(seconds.to_string())
        .stdin(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()?;
    let mut input = publisher.stdin.take().expect("piped report input");
    let publish = async {
        input.write_all(&(output.len() as u32).to_be_bytes()).await?;
        input.write_all(&output).await?;
        publisher.wait().await
    };
    let code = tokio::select! {
        result = publish => return Ok(match result {
            Ok(status) if status.success() => exit_code,
            _ => 2,
        }),
        _ = sleep_until(output_deadline) => 3,
        _ = interrupt.recv() => 130,
        _ = terminate.recv() => 143,
        _ = hangup.recv() => 129,
    };
    let _ = publisher.start_kill();
    let _ = timeout(Duration::from_millis(100), publisher.wait()).await;
    Ok(code)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn watch_collect_supervisor(seconds: u64) -> Result<()> {
    // A manually invoked internal worker must never signal an inherited process group.
    ensure!(
        unsafe { libc::getpid() == libc::getpgrp() },
        "巡检工作进程未处于独立进程组"
    );
    std::thread::Builder::new()
        .name("collect-watchdog".into())
        .spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds + 1);
            let mut parent = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let timeout = remaining.as_millis() as libc::c_int;
                let ready = unsafe { libc::poll(&mut parent, 1, timeout) };
                if ready >= 0
                    || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    // Only the supervisor holds a writer. EOF after SIGKILL is observable even
                    // when the worker is blocked in a synchronous filesystem operation.
                    unsafe { libc::kill(0, libc::SIGKILL) };
                    break;
                }
            }
        })?;
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args_os();
    let executable = args.next().expect("executable argument");
    let mut args = args.peekable();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if args.next_if(|arg| arg == COLLECT_OUTPUT).is_some() {
        use std::io::{Read as _, Write as _};
        let seconds = args
            .next()
            .and_then(|arg| arg.to_str()?.parse::<u64>().ok())
            .filter(|seconds| (1..=3600).contains(seconds))
            .ok_or_else(|| anyhow::anyhow!("无效的巡检报告写入期限"))?;
        let mut input = std::io::stdin().lock();
        let mut size = [0; 4];
        input.read_exact(&mut size)?;
        let size = u32::from_be_bytes(size) as usize;
        ensure!(size <= MAX_COLLECT_OUTPUT, "巡检报告超过输出上限");
        let mut report = vec![0; size];
        input.read_exact(&mut report)?;
        watch_collect_supervisor(seconds)?;
        let mut output = std::io::stdout().lock();
        let status = output.write_all(&report).and_then(|()| output.flush());
        std::process::exit(if status.is_ok() { 0 } else { 2 });
    }
    let collect_worker = args.next_if(|arg| arg == COLLECT_WORKER).is_some();
    let command = Cli::parse_from(std::iter::once(executable).chain(args)).command;
    let mut runtime = if matches!(&command, Command::Collect(_)) {
        tokio::runtime::Builder::new_current_thread()
    } else {
        tokio::runtime::Builder::new_multi_thread()
    };
    runtime
        .enable_all()
        .build()?
        .block_on(run(command, collect_worker))
}

async fn run(command: Command, collect_worker: bool) -> Result<()> {
    match command {
        Command::Fingerprints { action } => match action {
            FingerprintCommand::Export { output } => {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output)?;
                file.write_all(fingerprints::BUILTIN.as_bytes())?;
                println!("内置特征库已导出：{}", output.display());
            }
            FingerprintCommand::Validate { file } => {
                let library = fingerprints::Library::load(&file)?;
                println!("{}", serde_json::to_string_pretty(library.metadata())?);
            }
        },
        Command::Init {
            config: path,
            user,
            allow_anonymous,
            allow_without_whitelist,
        } => {
            ensure!(
                config::valid_user(&user),
                "账号仅允许 1–64 位字母、数字、下划线、点和横线"
            );
            let password = config::token(20);
            let cfg = Config {
                collection_defaults: Default::default(),
                public_origin: "http://127.0.0.1:8080".into(),
                admins: BTreeMap::from([(user.clone(), config::password_hash(&password, None)?)]),
                allow_anonymous,
                probe_multipart: false,
                probe_upload_progress: false,
                headers_only: false,
                fingerprint_file: None,
                fingerprint_library: None,
                allow_without_whitelist,
                allowed_networks: vec![],
                allowed_domains: vec![],
                allowed_ports: if allow_without_whitelist {
                    vec![]
                } else {
                    vec![80, 443, 8080, 8443]
                },
                database: "data/selfcheck.sqlite3".into(),
                users: if allow_anonymous {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([(user.clone(), config::password_hash(&password, None)?)])
                },
            };
            config::write_config(&path, &cfg, true)?;
            if allow_anonymous {
                println!(
                    "配置已生成。免密码扫描已启用，各浏览器会话独立隔离。\n管理员账号: {user}\n管理员随机密码: {password}\n管理员入口: /admin"
                );
            } else {
                println!(
                    "配置已生成。首次账号: {user}\n随机密码: {password}\n请保存密码。管理员入口: /admin。"
                );
            }
            if allow_without_whitelist {
                println!("允许不配置白名单；已填写的限制仍生效。");
            } else {
                println!("扫描范围为空，需配置 allowed_networks 后检测。");
            }
        }
        Command::AddUser { config: path, user } => {
            ensure!(config::valid_user(&user), "账号格式错误");
            let mut cfg = config::load(&path)?;
            ensure!(!cfg.users.contains_key(&user), "账号已存在，不覆盖");
            let password = config::token(20);
            cfg.users
                .insert(user.clone(), config::password_hash(&password, None)?);
            config::write_config(&path, &cfg, false)?;
            println!("账号: {user}\n随机密码: {password}\n重启服务后生效。");
        }
        Command::AddAdmin { config: path, user } => {
            ensure!(config::valid_user(&user), "管理员账号格式错误");
            let mut cfg = config::load(&path)?;
            ensure!(!cfg.admins.contains_key(&user), "管理员账号已存在，不覆盖");
            let password = config::token(20);
            cfg.admins
                .insert(user.clone(), config::password_hash(&password, None)?);
            config::write_config(&path, &cfg, false)?;
            println!("管理员账号: {user}\n随机密码: {password}\n重启后访问 /admin 登录。");
        }
        Command::Serve {
            config: path,
            bind,
            port,
            fingerprints,
        } => {
            let path = std::fs::canonicalize(path)?;
            let mut cfg = config::load(&path)?;
            fingerprint_override(&mut cfg, fingerprints)?;
            cfg.validate(&path, bind)?;
            portal::serve(cfg, std::net::SocketAddr::new(bind, port)).await?;
        }
        Command::Check {
            target,
            config: path,
            headers_only,
            json: as_json,
            fingerprints,
        } => {
            let loaded: Result<config::Config> = (|| {
                let mut cfg = config::load(&path)?;
                fingerprint_override(&mut cfg, fingerprints.clone())?;
                cfg.validate(&path, "127.0.0.1".parse()?)?;
                if let Some(file) = fingerprints {
                    cfg.fingerprint_library = Some(fingerprints::Library::load(&file)?);
                }
                cfg.headers_only |= headers_only;
                Ok(cfg)
            })();
            let cfg = match loaded {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("配置错误: {e}");
                    std::process::exit(2);
                }
            };
            let mut result = scanner::scan(&target, &cfg).await;
            let code = scanner::check_exit_code(&result);
            result["exit_code"] = serde_json::json!(code);
            result["patch_status"] = serde_json::json!(match code {
                0 => "ok",
                1 => "potentially_vulnerable",
                _ => "unknown",
            });
            if as_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "{}: {}\n{}",
                    result["verdict"].as_str().unwrap_or("无法判断"),
                    target,
                    result["reason"].as_str().unwrap_or("")
                );
            }
            std::process::exit(code.into());
        }
        Command::Collect(args) => {
            let fail_on_risk = args.fail_on_risk;
            let format = args.format;
            if args.demo {
                let report = x2shell_check::java4shell::demo_report();
                println!(
                    "{}",
                    x2shell_check::java4shell::format_audit(&report, format)?.trim_end()
                );
                ensure!(report["audit"]["demo_passed"] == true, "Java 演示判定失败");
                return Ok(());
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if !collect_worker {
                std::process::exit(supervise_collect(args.scan_timeout, format).await?);
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            watch_collect_supervisor(args.scan_timeout)?;
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let _ = collect_worker;
            let options = args.resolve()?;
            let java_only = options.java_command
                && !(options.nginx2root
                    || options.apache2root
                    || options.middleware
                    || options.php_command
                    || options.package_audit);
            ensure!(
                matches!(format, collector::CollectFormat::Json) || java_only,
                "文本和 CSV 格式只支持 Java 专项"
            );
            ensure!(
                !fail_on_risk
                    || options.java_command
                    || options.nginx2root
                    || options.apache2root
                    || options.middleware,
                "--fail-on-risk 需要启用至少一个专项"
            );
            #[cfg(target_os = "linux")]
            let report = collector::collect_with_options(&options).await;
            #[cfg(target_os = "macos")]
            let report = {
                ensure!(
                    java_only
                        && !options.java_attach
                        && !options.java_assume_flags_effective
                        && options.java_root.is_empty()
                        && options.java_jdk.is_empty()
                        && options.java_root_depth.is_none()
                        && options.java_cpuinfo.is_none(),
                    "macOS 仅支持 Java 启动器降级盘点与应用目录清单"
                );
                x2shell_check::java4shell::collect_macos(&options).await
            };
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let report = {
                let _ = &options;
                anyhow::bail!("主机采集支持 Linux，macOS 支持 Java 降级盘点");
                #[allow(unreachable_code)]
                serde_json::Value::Null
            };
            {
                use std::io::Write as _;
                let mut output = std::io::stdout().lock();
                writeln!(
                    output,
                    "{}",
                    x2shell_check::java4shell::format_audit(&report, format)?.trim_end()
                )?;
                output.flush()?;
            }
            if fail_on_risk {
                if report["audit"]["risk_gate_hit"] == true {
                    std::process::exit(1);
                }
                if report["audit"]["evidence_incomplete"] == true {
                    std::process::exit(3);
                }
            }
        }
        Command::OfflinePoc { json: as_json } => {
            let result = evidence_lab::offline_poc()?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", evidence_lab::human_poc(&result));
            }
            ensure!(
                result["summary"]["all_passed"] == true,
                "离线证据规则验证失败"
            );
        }
        Command::CompareReports {
            before,
            after,
            json: as_json,
        } => {
            let before = evidence_lab::read_report(&before)?;
            let after = evidence_lab::read_report(&after)?;
            let result = evidence_lab::compare_reports(&before, &after)?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", evidence_lab::human_comparison(&result));
            }
        }
    }
    Ok(())
}
