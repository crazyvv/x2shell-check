use clap::Parser;
use x2shell_check::collector::{CollectArgs, CollectOptions};
#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    collect: CollectArgs,
}
#[test]
fn cli_and_json_options_override_and_dependencies() {
    let options = Cli::parse_from([
        "collect",
        "--middleware",
        "--php-modules=true",
        "--ports",
        "--web-probe",
        "--web-host",
        "app.example",
    ])
    .collect
    .resolve()
    .unwrap();
    assert!(options.middleware && options.php_modules && options.ports && options.web_probe);
    assert!(
        Cli::parse_from(["collect", "--web-probe"])
            .collect
            .resolve()
            .is_err()
    );
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("options.json");
    std::fs::write(
        &file,
        r#"{"middleware":true,"ports":true,"web_probe":true}"#,
    )
    .unwrap();
    let options = Cli::parse_from([
        "collect",
        "--options",
        file.to_str().unwrap(),
        "--web-probe=false",
    ])
    .collect
    .resolve()
    .unwrap();
    assert!(options.ports && !options.web_probe);
    let default = Cli::parse_from(["collect"]).collect.resolve().unwrap();
    assert!(
        !default.middleware
            && !default.web_probe
            && !default.php_command
            && !default.java_command
            && !default.package_audit
    );
    let enabled = Cli::parse_from([
        "collect",
        "--php-command",
        "--java-command",
        "--package-audit",
    ])
    .collect
    .resolve()
    .unwrap();
    assert!(
        enabled.php_command && enabled.java_command && enabled.package_audit && !enabled.middleware
    );
}
#[test]
fn invalid_host_path_protocol_and_limits_are_rejected() {
    for host in [
        "user:secret@example.com",
        "example.com/path",
        "example.com:8080",
    ] {
        let c = CollectOptions {
            web_host: Some(host.into()),
            ..Default::default()
        };
        assert!(c.validate().is_err(), "{host}");
    }
    for path in ["//example.com/", "/\r\nX:1", "/#fragment", "/\\other"] {
        assert!(
            CollectOptions {
                web_path: path.into(),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        CollectOptions {
            max_web_probes: 65,
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        CollectOptions {
            web_schemes: vec!["file".into()],
            ..Default::default()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn custom_web_fingerprints_resolve_relative_to_options_file() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("fingerprints.json");
    std::fs::write(&rules, include_str!("../fingerprints.example.json")).unwrap();
    let options = dir.path().join("options.json");
    std::fs::write(&options, r#"{"fingerprint_file":"fingerprints.json"}"#).unwrap();
    let cfg = Cli::parse_from(["collect", "--options", options.to_str().unwrap()])
        .collect
        .resolve()
        .unwrap();
    assert_eq!(cfg.fingerprint_file.as_ref(), Some(&rules));
    assert!(!cfg.web_probe);
    std::fs::write(&rules, "invalid JSON").unwrap();
    assert!(
        Cli::parse_from(["collect", "--options", options.to_str().unwrap()])
            .collect
            .resolve()
            .is_err()
    );
}

#[test]
fn java_demo_uses_synthetic_cases_in_all_formats() {
    let executable = env!("CARGO_BIN_EXE_x2shell-check");
    let output = std::process::Command::new(executable)
        .args(["collect", "--demo"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["scope"], "synthetic_java_demo");
    assert_eq!(report["audit"]["passed"], 6);
    for format in ["txt", "csv"] {
        let output = std::process::Command::new(executable)
            .args(["collect", "--demo", "--format", format])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("build_gap")
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn explicit_java_launcher_checks_build_and_rejects_conflicting_metadata() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let launcher = bin.join("java");
    fs::create_dir(&bin).unwrap();
    fs::write(&launcher, concat!(
        "#!/bin/sh\n",
        "test \"$#\" = 1 && test \"$1\" = -version || exit 2\n",
        "printf '%s\\n' 'openjdk version \"17.0.21\"' 'OpenJDK Runtime Environment (build 17.0.21+9)' >&2\n",
    )).unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
    for (disk, code, status) in [("17.0.21+9", 1, "potential"), ("17.0.21+8", 3, "unknown")] {
        fs::write(dir.path().join("release"), format!(
            "JAVA_VERSION=\"17.0.21\"\nJAVA_RUNTIME_VERSION=\"{disk}\"\nIMPLEMENTOR=\"OpenJDK\"\n"
        )).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_x2shell-check"))
            .current_dir(dir.path())
            .args(["collect", "--java-path", "./bin/java", "--fail-on-risk"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{:?}", output);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["java4shell"]["runtimes"][0]["status"], status);
        assert!(report["java4shell"]["runtime_audit"].is_null());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn batch_java_inventory_does_not_execute_discovered_java() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("executed");
    let launcher = dir.path().join("java");
    fs::write(&launcher, "#!/bin/sh\n: > \"$JAVA_TEST_MARKER\"\n").unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
    let path = std::env::join_paths(
        std::iter::once(dir.path().to_owned())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_x2shell-check"))
        .args(["collect", "--all"])
        .env("PATH", path)
        .env("JAVA_TEST_MARKER", &marker)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["java4shell"]["runtime_audit"].is_object());
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn middleware_inventory_does_not_execute_discovered_programs() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("executed");
    for name in ["apache2", "nginx"] {
        let launcher = dir.path().join(name);
        fs::write(&launcher, "#!/bin/sh\n: > \"$MIDDLEWARE_TEST_MARKER\"\n").unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_x2shell-check"))
        .args(["collect", "--middleware", "--php-modules"])
        .env("PATH", dir.path())
        .env("MIDDLEWARE_TEST_MARKER", &marker)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["middleware"]["binaries"][dir.path().join("nginx").to_str().unwrap()]["status"],
        "unknown"
    );
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn java_command_limits_report_complete_json_and_stop_helpers() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let launcher = dir.path().join("java");
    let helper = dir.path().join("helper-pid");
    fs::write(
        &launcher,
        "#!/bin/sh\nprintf '%s\\n' 'java version \"21.0.13.1\"' >&2\nhead -c 65537 /dev/zero >&2\n",
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_x2shell-check"))
            .args(["collect", "--java-path"])
            .arg(&launcher)
            .args(args)
            .env("JAVA_TEST_HELPER", &helper)
            .output()
            .unwrap()
    };
    let output = run(&["--fail-on-risk"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["java4shell"]["runtimes"][0]["reason"],
        "launcher_output_limit"
    );

    fs::write(
        &launcher,
        "#!/bin/sh\ntrap '' TERM\nsleep 20 &\nprintf '%s\\n' \"$!\" > \"$JAVA_TEST_HELPER\"\nwait\n",
    )
    .unwrap();
    let output = run(&["--scan-timeout", "2"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage"]["scan_timed_out"], true);
    assert_eq!(report["audit"]["evidence_incomplete"], true);
    let pid = fs::read_to_string(helper).unwrap();
    let proc = format!("/proc/{}/stat", pid.trim());
    let active = || {
        fs::read_to_string(&proc).is_ok_and(|stat| {
            stat.rsplit_once(')').is_some_and(|(_, fields)| {
                !matches!(fields.split_whitespace().next(), Some("Z" | "X"))
            })
        })
    };
    for _ in 0..10 {
        if !active() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!active(), "helper still running after scan timeout");
}
#[cfg(target_os = "linux")]
#[test]
fn java_installed_package_requires_matching_runtime_build() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let os = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let package = if os.contains("ID=debian\n") && os.contains("VERSION_CODENAME=trixie") {
        "21.0.13.1+2-1~deb13u1"
    } else if os.contains("ID=ubuntu\n") && os.contains("VERSION_ID=\"24.04\"") {
        "21.0.13.1+2-1~24.04.1"
    } else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let jdk = temp.path().join("jdk");
    let tools = temp.path().join("tools");
    fs::create_dir_all(jdk.join("lib/server")).unwrap();
    fs::create_dir(&tools).unwrap();
    fs::write(jdk.join("lib/server/libjvm.so"), "").unwrap();
    let owner = tools.join("dpkg-query");
    let compare = tools.join("dpkg");
    fs::write(&owner, concat!("#!/bin/sh\n", "case $1 in\n-S) printf 'openjdk-21-jre-headless:amd64: %s\\n' \"$3\";;\n",
        "-W) printf 'openjdk-21-jre-headless:amd64\\t%s\\topenjdk-21\\t%s\\tinstalled\\n' \"$PACKAGE_FIXTURE\" \"$PACKAGE_FIXTURE\";;\n*) exit 2;;\nesac\n")).unwrap();
    fs::write(&compare, "#!/bin/sh\ntest \"$2\" = \"$4\"\n").unwrap();
    for tool in [&owner, &compare] {
        fs::set_permissions(tool, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let cpu = temp.path().join("cpuinfo");
    fs::write(&cpu, "processor: 0\nflags: avx512f avx512bw avx512vbmi bmi2\n").unwrap();
    for (build, expected) in [("21.0.13.1+2", "not_affected"), ("21.0.13.1+1", "unknown")] {
        fs::write(jdk.join("release"), format!("JAVA_VERSION=\"21.0.13.1\"\nJAVA_RUNTIME_VERSION=\"{build}\"\nIMPLEMENTOR=\"Debian\"\n")).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_x2shell-check"))
            .args(["collect", "--java-command", "--java-no-processes", "--java-jdk"])
            .arg(&jdk).arg("--java-cpuinfo").arg(&cpu)
            .env("PATH", &tools).env("PACKAGE_FIXTURE", package)
            .output().unwrap();
        assert!(out.status.success(), "{out:?}");
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let row = &report["java4shell"]["runtime_audit"]["installations"][0];
        assert_eq!(row["status"], expected);
        assert_eq!(row["package_evidence"]["patch_status"], "meets_vendor_reference");
        assert_eq!(row["package_evidence"]["release_build_matches"], build.ends_with("+2"));
    }
}

#[cfg(unix)]
#[test]
fn explicit_java_flags_report_origins_in_an_isolated_launcher() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let temp = tempfile::tempdir().unwrap();
    let java = temp.path().join("java");
    fs::write(&java, concat!("#!/bin/sh\n",
        "case \" $* \" in\n",
        " *' -XX:-UseBASE64Intrinsics '*) printf 'bool UseBASE64Intrinsics = false {product} {command line}\\n';;\n",
        " *' -XX:+PrintFlagsFinal '*) if [ \"${JAVA_TOOL_OPTIONS:-}\" = -XX:-UseBASE64Intrinsics ]; then ",
        "printf 'bool UseBASE64Intrinsics = false {product} {environment}\\n'; else ",
        "printf 'bool UseBASE64Intrinsics = true {product} {default}\\n'; fi;;\n",
        " *) printf 'openjdk version \"21.0.13.1\"\\n';;\nesac\n")).unwrap();
    fs::set_permissions(&java, fs::Permissions::from_mode(0o700)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_x2shell-check"))
        .args(["collect", "--java-default-flags", "--java-path"]).arg(java)
        .env("JAVA_TOOL_OPTIONS", "-XX:-UseBASE64Intrinsics").output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let row = &report["java4shell"]["runtimes"][0];
    let flags = &row["launcher_flag_probe"];
    assert_eq!(flags["scope"], "isolated_launcher");
    assert_eq!(flags["default"]["origins"]["UseBASE64Intrinsics"], "default");
    assert_eq!(flags["base64_disabled_override"]["UseBASE64Intrinsics"], false);
    assert_eq!(flags["base64_disabled_override"]["origins"]["UseBASE64Intrinsics"], "command line");
    assert_eq!(flags["base64_disabled_environment"]["origins"]["UseBASE64Intrinsics"], "environment");
    assert_eq!(row["effective_flags_complete"], false);
}
