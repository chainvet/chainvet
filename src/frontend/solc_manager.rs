use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;

use crate::norm::SourceFile;
use crate::util::error::{Error, Result};

const SOLC_LIST_BASE: &str = "https://binaries.soliditylang.org";
const SOLC_PATH_ENV: &str = "SOLC_PATH";
const SOLC_CACHE_ENV: &str = "STATIC_SOLC_DIR";
const LIST_TTL_SECS: u64 = 60 * 60 * 24;

pub struct SolcManager {
    cache_dir: PathBuf,
    platform: SolcPlatform,
    list_ttl: Duration,
}

impl SolcManager {
    pub fn new() -> Result<Self> {
        let cache_dir = default_cache_dir()?;
        fs::create_dir_all(&cache_dir)?;
        Ok(Self {
            cache_dir,
            platform: SolcPlatform::detect()?,
            list_ttl: Duration::from_secs(LIST_TTL_SECS),
        })
    }

    pub fn prepare(&self, sources: &[SourceFile]) -> Result<PathBuf> {
        if let Ok(path) = env::var(SOLC_PATH_ENV) {
            return Ok(PathBuf::from(path));
        }

        let reqs = collect_version_reqs(sources);
        match self.load_list() {
            Ok(list) => {
                let version = select_version(&reqs, &list)?;
                self.ensure_solc(&version, &list)
            }
            Err(err) => {
                if let Some(path) = solc_in_path() {
                    return Ok(path);
                }
                Err(err)
            }
        }
    }

    pub fn check_solc(&self, solc_path: &Path) -> Result<()> {
        let output = Command::new(solc_path).arg("--version").output()?;
        if !output.status.success() {
            return Err(Error::msg("solc failed to run"));
        }
        Ok(())
    }

    fn ensure_solc(&self, version: &SolcVersion, list: &SolcList) -> Result<PathBuf> {
        let bin_dir = self
            .cache_dir
            .join(format!("solc-v{version}"));
        let bin_path = bin_dir.join(self.platform.exe_name());
        if bin_path.exists() {
            return Ok(bin_path);
        }

        fs::create_dir_all(&bin_dir)?;
        let url = self.binary_url(version, list)?;
        download_file(&url, &bin_path)?;
        set_executable(&bin_path)?;
        Ok(bin_path)
    }

    fn binary_url(&self, version: &SolcVersion, list: &SolcList) -> Result<String> {
        let filename = list
            .releases
            .get(&version.to_string())
            .ok_or_else(|| Error::msg("solc release not found in list"))?;
        Ok(format!("{}/{}/{}", SOLC_LIST_BASE, self.platform.as_str(), filename))
    }

    fn load_list(&self) -> Result<SolcList> {
        let path = self.list_path();
        let mut refresh = true;

        if let Ok(meta) = fs::metadata(&path) {
            if is_fresh(&meta, self.list_ttl) {
                refresh = false;
            }
        }

        if refresh {
            let url = self.list_url();
            if let Err(err) = download_file(&url, &path) {
                if !path.exists() {
                    return Err(err);
                }
            }
        }

        let raw = fs::read_to_string(&path)?;
        let list: SolcList = serde_json::from_str(&raw)
            .map_err(|err| Error::msg(format!("solc list parse error: {err}")))?;
        Ok(list)
    }

    fn list_url(&self) -> String {
        format!("{}/{}/list.json", SOLC_LIST_BASE, self.platform.as_str())
    }

    fn list_path(&self) -> PathBuf {
        self.cache_dir
            .join(format!("list-{}.json", self.platform.as_str()))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SolcPlatform {
    LinuxAmd64,
    MacOsAmd64,
    MacOsArm64,
    WindowsAmd64,
}

impl SolcPlatform {
    pub fn detect() -> Result<Self> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => Ok(SolcPlatform::LinuxAmd64),
            ("macos", "x86_64") => Ok(SolcPlatform::MacOsAmd64),
            ("macos", "aarch64") => Ok(SolcPlatform::MacOsArm64),
            ("windows", "x86_64") => Ok(SolcPlatform::WindowsAmd64),
            _ => Err(Error::msg("unsupported platform for solc downloads")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SolcPlatform::LinuxAmd64 => "linux-amd64",
            SolcPlatform::MacOsAmd64 => "macosx-amd64",
            SolcPlatform::MacOsArm64 => "macosx-arm64",
            SolcPlatform::WindowsAmd64 => "windows-amd64",
        }
    }

    pub fn exe_name(&self) -> &'static str {
        match self {
            SolcPlatform::WindowsAmd64 => "solc.exe",
            _ => "solc",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct SolcVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl SolcVersion {
    pub fn parse(input: &str) -> Option<Self> {
        let mut trimmed = input.trim();
        if let Some(stripped) = trimmed.strip_prefix('v') {
            trimmed = stripped;
        }

        let mut parts = trimmed.split('.');
        let major = parse_part(parts.next()?)?;
        let minor = match parts.next() {
            Some(value) => parse_part(value)?,
            None => 0,
        };
        let patch = match parts.next() {
            Some(value) => parse_part(value)?,
            None => 0,
        };

        Some(Self { major, minor, patch })
    }
}

impl fmt::Display for SolcVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone)]
struct VersionReq {
    comparators: Vec<Comparator>,
}

impl VersionReq {
    fn parse(spec: &str) -> Option<Self> {
        let mut comparators = Vec::new();
        for token in spec.split_whitespace() {
            if let Some(comp) = Comparator::parse(token) {
                comparators.push(comp);
            }
        }

        if comparators.is_empty() {
            if let Some(comp) = Comparator::parse(spec) {
                comparators.push(comp);
            }
        }

        if comparators.is_empty() {
            return None;
        }

        Some(Self { comparators })
    }

    fn matches(&self, version: &SolcVersion) -> bool {
        self.comparators.iter().all(|comp| comp.matches(version))
    }
}

#[derive(Debug, Clone)]
struct Comparator {
    op: Op,
    version: SolcVersion,
}

impl Comparator {
    fn parse(token: &str) -> Option<Self> {
        let token = token.trim();
        let (op, rest) = if let Some(value) = token.strip_prefix(">=") {
            (Op::Gte, value)
        } else if let Some(value) = token.strip_prefix("<=") {
            (Op::Lte, value)
        } else if let Some(value) = token.strip_prefix('>') {
            (Op::Gt, value)
        } else if let Some(value) = token.strip_prefix('<') {
            (Op::Lt, value)
        } else if let Some(value) = token.strip_prefix('=') {
            (Op::Eq, value)
        } else if let Some(value) = token.strip_prefix('^') {
            (Op::Caret, value)
        } else if let Some(value) = token.strip_prefix('~') {
            (Op::Tilde, value)
        } else {
            (Op::Eq, token)
        };

        let version = parse_version_token(rest)?;
        Some(Self { op, version })
    }

    fn matches(&self, version: &SolcVersion) -> bool {
        match self.op {
            Op::Eq => version == &self.version,
            Op::Gt => version > &self.version,
            Op::Gte => version >= &self.version,
            Op::Lt => version < &self.version,
            Op::Lte => version <= &self.version,
            Op::Caret => {
                let upper = caret_upper_bound(&self.version);
                version >= &self.version && version < &upper
            }
            Op::Tilde => {
                let upper = tilde_upper_bound(&self.version);
                version >= &self.version && version < &upper
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
    Caret,
    Tilde,
}

#[derive(Debug, Deserialize)]
struct SolcList {
    releases: HashMap<String, String>,
    #[serde(rename = "latestRelease")]
    latest_release: String,
}

fn select_version(reqs: &[VersionReq], list: &SolcList) -> Result<SolcVersion> {
    let mut versions: Vec<SolcVersion> = list
        .releases
        .keys()
        .filter_map(|value| SolcVersion::parse(value))
        .collect();
    versions.sort();

    if versions.is_empty() {
        return Err(Error::msg("no solc releases available"));
    }

    if reqs.is_empty() {
        if let Some(version) = SolcVersion::parse(&list.latest_release) {
            return Ok(version);
        }
        return Ok(*versions.last().expect("versions is non-empty"));
    }

    for version in versions.iter().rev() {
        if reqs.iter().all(|req| req.matches(version)) {
            return Ok(*version);
        }
    }

    Err(Error::msg("no solc version satisfies pragma requirements"))
}

fn collect_version_reqs(sources: &[SourceFile]) -> Vec<VersionReq> {
    let mut reqs = Vec::new();
    for source in sources {
        for spec in extract_pragmas(&source.source) {
            if let Some(req) = VersionReq::parse(&spec) {
                reqs.push(req);
            }
        }
    }
    reqs
}

fn extract_pragmas(source: &str) -> Vec<String> {
    let mut specs = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(idx) = trimmed.find("pragma solidity") {
            let after = &trimmed[idx + "pragma solidity".len()..];
            if let Some(end) = after.find(';') {
                let spec = after[..end].trim();
                if !spec.is_empty() {
                    specs.push(spec.to_string());
                }
            }
        }
    }
    specs
}

fn caret_upper_bound(version: &SolcVersion) -> SolcVersion {
    if version.major > 0 {
        SolcVersion {
            major: version.major + 1,
            minor: 0,
            patch: 0,
        }
    } else if version.minor > 0 {
        SolcVersion {
            major: 0,
            minor: version.minor + 1,
            patch: 0,
        }
    } else {
        SolcVersion {
            major: 0,
            minor: 0,
            patch: version.patch + 1,
        }
    }
}

fn tilde_upper_bound(version: &SolcVersion) -> SolcVersion {
    SolcVersion {
        major: version.major,
        minor: version.minor + 1,
        patch: 0,
    }
}

fn parse_part(input: &str) -> Option<u64> {
    let len = input
        .bytes()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if len == 0 {
        return None;
    }
    input[..len].parse().ok()
}

fn parse_version_token(token: &str) -> Option<SolcVersion> {
    let start = token
        .bytes()
        .position(|b| b.is_ascii_digit())?;
    let mut end = start;
    for (idx, b) in token.bytes().enumerate().skip(start) {
        if !(b.is_ascii_digit() || b == b'.') {
            break;
        }
        end = idx + 1;
    }
    SolcVersion::parse(&token[start..end])
}

fn solc_in_path() -> Option<PathBuf> {
    let output = Command::new("solc").arg("--version").output().ok()?;
    if output.status.success() {
        Some(PathBuf::from("solc"))
    } else {
        None
    }
}

fn default_cache_dir() -> Result<PathBuf> {
    if let Ok(value) = env::var(SOLC_CACHE_ENV) {
        return Ok(PathBuf::from(value));
    }

    if let Ok(value) = env::var("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(value).join("static/solc"));
    }

    if let Ok(value) = env::var("HOME") {
        return Ok(PathBuf::from(value).join(".cache/static/solc"));
    }

    if let Ok(value) = env::var("USERPROFILE") {
        return Ok(PathBuf::from(value).join(".cache/static/solc"));
    }

    Err(Error::msg("unable to determine cache directory"))
}

fn is_fresh(meta: &fs::Metadata, ttl: Duration) -> bool {
    if let Ok(modified) = meta.modified() {
        if let Ok(elapsed) = modified.elapsed() {
            return elapsed < ttl;
        }
    }
    false
}

fn download_file(url: &str, dest: &Path) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| Error::msg("download destination has no parent"))?;
    fs::create_dir_all(parent)?;

    let tmp = dest.with_extension("tmp");
    let tmp_str = tmp
        .to_str()
        .ok_or_else(|| Error::msg("download path is not valid UTF-8"))?;
    if let Err(err) = download_with_command("curl", &["-fL", "-o", tmp_str, url]) {
        if let Err(err2) = download_with_command("wget", &["-O", tmp_str, url]) {
            let message = format!("download failed: {err}; fallback failed: {err2}");
            return Err(Error::msg(message));
        }
    }

    fs::rename(tmp, dest)?;
    Ok(())
}

fn download_with_command(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd).args(args).status();
    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => Err(Error::msg(format!("{cmd} exited with error"))),
        Err(err) => Err(Error::msg(format!("{cmd} failed: {err}"))),
    }
}

fn set_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}
