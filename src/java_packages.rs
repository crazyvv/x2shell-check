//! Read-only installed-package evidence for the Java runtime audit.
use crate::collector::{run, which};
use serde::Serialize;
use std::{collections::BTreeSet, path::Path, time::Duration};
use tokio::time::{Instant, timeout_at};

const RULES: &str = include_str!("../rules/java4shell-packages.tsv");
const MAX_LOOKUPS: usize = 12;

#[derive(Clone, Serialize)]
pub(crate) struct Evidence {
    manager: &'static str,
    distribution: String,
    distribution_version: String,
    name: String,
    source_package: String,
    version: String,
    reference_version: Option<&'static str>,
    advisory: Option<&'static str>,
    patch_status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_candidates: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_changelog_mentions_cve: Option<bool>,
}

impl Evidence {
    pub(crate) fn matching_build(&self, build: &str) -> bool {
        normalized_build(self.manager, &self.version)
            .zip(normalized_build("jvm", build).or_else(|| {
                (self.manager == "apk")
                    .then(|| normalized_build("apk", build))
                    .flatten()
            }))
            .is_some_and(|(package, runtime)| package == runtime)
    }

    pub(crate) fn report(&self, build: Option<&str>) -> serde_json::Value {
        let mut report = serde_json::json!(self);
        report["release_build_matches"] =
            serde_json::json!(build.is_some_and(|v| self.matching_build(v)));
        report
    }

    pub(crate) fn fixed(&self) -> bool {
        self.patch_status == "meets_vendor_reference"
    }
}

fn normalized_build<'a>(manager: &str, version: &'a str) -> Option<(&'a str, u32)> {
    let version = version.rsplit(':').next()?;
    let (base, build) = match manager {
        "rpm" => version.split_once('-')?.0.rsplit_once('.')?,
        "apk" => version.split_once("_p")?,
        _ => version.split_once('+')?,
    };
    if !base
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return None;
    }
    Some((base, build.split(['-', '.']).next()?.parse().ok()?))
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".:_~+-^".contains(&byte))
}

async fn query(deadline: Instant, program: &str, args: &[&str]) -> Option<String> {
    let executable = which(program)?;
    let limit = deadline.min(Instant::now() + Duration::from_secs(2));
    if limit <= Instant::now() {
        return None;
    }
    let result = timeout_at(limit, run(&executable, args)).await.ok()?;
    if result["exit_code"] != 0 {
        return None;
    }
    result["output"].as_str().map(str::to_owned)
}

pub(crate) struct PackageScan {
    distro: String,
    branch: String,
    remaining: usize,
    deadline: Option<Instant>,
    pub(crate) limited: bool,
    details: bool,
}

impl PackageScan {
    pub(crate) fn new(os: &str, details: bool) -> Self {
        let get = |key: &str| {
            os.lines()
                .filter_map(|line| line.split_once('='))
                .find(|(name, _)| *name == key)
                .map_or("", |(_, value)| value.trim_matches('"'))
        };
        let distro = get("ID");
        let version = get("VERSION_ID");
        let branch = match distro {
            "debian" => get("VERSION_CODENAME"),
            "rhel" | "rocky" | "almalinux" => version.split('.').next().unwrap_or(""),
            "alpine" => {
                if version.contains("_alpha") {
                    "edge"
                } else if version.matches('.').count() >= 2 {
                    version.rsplit_once('.').map_or(version, |(base, _)| base)
                } else {
                    version
                }
            }
            _ => version,
        };
        Self {
            distro: distro.into(),
            branch: branch.into(),
            remaining: MAX_LOOKUPS,
            deadline: None,
            limited: false,
            details,
        }
    }

    pub(crate) async fn lookup(&mut self, path: &Path) -> Option<Evidence> {
        let path = path.to_str()?;
        if !path.ends_with("/libjvm.so")
            || !path.starts_with('/')
            || path.chars().any(char::is_control)
        {
            return None;
        }
        let manager = match self.distro.as_str() {
            "debian" | "ubuntu" => "dpkg",
            "rhel" | "rocky" | "almalinux" | "amzn" => "rpm",
            "alpine" => "apk",
            _ => return None,
        };
        if self.remaining == 0 {
            self.limited = true;
            return None;
        }
        self.remaining -= 1;
        let deadline = *self
            .deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(8));
        if deadline <= Instant::now() {
            self.limited = true;
            return None;
        }
        let (name, source, version) = match manager {
            "dpkg" => {
                let owner = query(deadline, "dpkg-query", &["-S", "--", path]).await?;
                let (name, owned) = owner.trim_end_matches('\n').rsplit_once(": ")?;
                if owned != path || !token(name) {
                    return None;
                }
                let format = "-f=${binary:Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\t${db:Status-Status}\\n";
                let data = query(deadline, "dpkg-query", &["-W", format, "--", name]).await?;
                let fields: Vec<_> = data.trim_end_matches('\n').split('\t').collect();
                let [found, version, source, source_version, "installed"] = fields.as_slice()
                else {
                    return None;
                };
                if *found != name || *version != *source_version || !source.starts_with("openjdk-")
                {
                    return None;
                }
                (name.to_owned(), (*source).to_owned(), (*version).to_owned())
            }
            "rpm" => {
                let format =
                    "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{VENDOR}\\t%{SOURCERPM}\\n";
                let data = query(deadline, "rpm", &["-qf", "--qf", format, "--", path]).await?;
                let fields: Vec<_> = data.trim_end_matches('\n').split('\t').collect();
                let [name, version, vendor, source_rpm] = fields.as_slice() else {
                    return None;
                };
                let vendor = vendor.to_ascii_lowercase();
                let expected_vendor = match self.distro.as_str() {
                    "rhel" => "red hat",
                    "rocky" => "rocky",
                    "almalinux" => "almalinux",
                    _ => "amazon",
                };
                let source = source_rpm
                    .strip_suffix(".src.rpm")?
                    .rsplitn(3, '-')
                    .nth(2)?;
                if !source.starts_with("java-")
                    || !vendor.contains(expected_vendor)
                    || !(*name == source
                        || name.strip_prefix(source).is_some_and(|s| s == "-headless"))
                {
                    return None;
                }
                ((*name).to_owned(), source.to_owned(), (*version).to_owned())
            }
            "apk" => {
                let data = query(deadline, "apk", &["info", "-W", "--", path]).await?;
                let (owned, package) = data.trim_end_matches('\n').rsplit_once(" is owned by ")?;
                if owned.trim_start_matches('/') != path.trim_start_matches('/') || !token(package)
                {
                    return None;
                }
                let (name, version) = package.match_indices('-').find_map(|(i, _)| {
                    package[i + 1..]
                        .starts_with(|c: char| c.is_ascii_digit())
                        .then(|| (&package[..i], &package[i + 1..]))
                })?;
                let source = name.split('-').next()?;
                if !source.starts_with("openjdk")
                    || !matches!(
                        name.strip_prefix(source),
                        Some("" | "-jre" | "-jre-headless" | "-jdk")
                    )
                {
                    return None;
                }
                (name.to_owned(), source.to_owned(), version.to_owned())
            }
            _ => unreachable!(),
        };
        if !token(&name) || !token(&source) || !token(&version) {
            return None;
        }
        let rule = RULES.lines().find_map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            let [m, distro, branch, package, minimum, advisory] = fields.as_slice() else {
                return None;
            };
            (*m == manager
                && *distro == self.distro
                && *branch == self.branch
                && *package == source)
                .then_some((*minimum, *advisory))
        });
        let patch_status = if let Some((minimum, _)) = rule {
            let good = match manager {
                "apk" => query(deadline, "apk", &["version", "-t", &version, minimum])
                    .await
                    .and_then(|value| match value.trim() {
                        "=" | ">" => Some(true),
                        "<" => Some(false),
                        _ => None,
                    }),
                "rpm" if self.distro == "amzn" => {
                    let version = version.split_once(':').map_or(version.as_str(), |(_, v)| v);
                    timeout_at(
                        deadline,
                        crate::hostaudit::java_package_at_least("rpm", version, minimum),
                    )
                    .await
                    .ok()
                    .flatten()
                }
                _ => timeout_at(
                    deadline,
                    crate::hostaudit::java_package_at_least(manager, &version, minimum),
                )
                .await
                .ok()
                .flatten(),
            };
            match good {
                Some(true) => "meets_vendor_reference",
                Some(false) => "below_vendor_reference",
                None => "unknown",
            }
        } else {
            "unknown"
        };
        let (repository_candidates, local_changelog_mentions_cve) = if manager == "dpkg"
            && self.details
        {
            let candidates = query(
                deadline,
                "apt-cache",
                &[
                    "-o",
                    "Dir::Cache::pkgcache=",
                    "-o",
                    "Dir::Cache::srcpkgcache=",
                    "madison",
                    &name,
                ],
            )
            .await
            .map(|out| {
                out.lines()
                    .filter_map(|line| line.split('|').nth(1))
                    .map(str::trim)
                    .filter(|version| token(version))
                    .take(12)
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            });
            let bin = name.split(':').next().unwrap_or(&name);
            let changelog = format!("/usr/share/doc/{bin}/changelog.Debian.gz");
            let mentions =
                if std::fs::metadata(&changelog).is_ok_and(|m| m.is_file() && m.len() <= 131_072) {
                    query(deadline, "gzip", &["-cd", "--", &changelog])
                        .await
                        .map(|out| out.contains("CVE-2026-114938"))
                } else {
                    None
                };
            (candidates, mentions)
        } else {
            (None, None)
        };
        Some(Evidence {
            manager,
            distribution: self.distro.clone(),
            distribution_version: self.branch.clone(),
            name,
            source_package: source,
            version,
            reference_version: rule.map(|r| r.0),
            advisory: rule.map(|r| r.1),
            patch_status,
            repository_candidates,
            local_changelog_mentions_cve,
        })
    }
}
