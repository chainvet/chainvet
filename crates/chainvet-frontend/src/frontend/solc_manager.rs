use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;

use chainvet_core::norm::SourceFile;
use chainvet_core::util::error::{Error, Result};

const SOLC_LIST_BASE: &str = "https://binaries.soliditylang.org";
const SOLC_PATH_ENV: &str = "SOLC_PATH";
const SOLC_CACHE_ENV: &str = "STATIC_SOLC_DIR";
const SOLC_OFFLINE_ENV: &str = "STATIC_SOLC_OFFLINE";
const SOLC_SEARCH_PATHS_ENV: &str = "STATIC_SOLC_SEARCH_PATHS";
const LIST_TTL_SECS: u64 = 60 * 60 * 24;

pub struct SolcManager {
    cache_dir: PathBuf,
    platform: SolcPlatform,
    list_ttl: Duration,
}

impl SolcManager {
    pub fn new() -> Result<Self> {
        let cache_dir = resolve_cache_dir()?;
        Ok(Self {
            cache_dir,
            platform: SolcPlatform::detect()?,
            list_ttl: Duration::from_secs(LIST_TTL_SECS),
        })
    }

    pub fn prepare(&self, sources: &[SourceFile]) -> Result<PathBuf> {
        let reqs = collect_version_reqs(sources);

        if let Ok(path) = env::var(SOLC_PATH_ENV) {
            return Ok(PathBuf::from(path));
        }

        if let Some(path) = solc_in_path() {
            let path_version = detect_solc_version(&path);
            let path_satisfies_reqs = reqs.is_empty()
                || path_version
                    .as_ref()
                    .map(|version| reqs.iter().all(|req| req.matches(version)))
                    .unwrap_or(false);
            if path_satisfies_reqs {
                return Ok(path);
            }
        }

        if let Some(cached) = self.find_cached_solc(&reqs)? {
            return Ok(cached);
        }
        if let Some(local) = find_local_solc_binary(&reqs, self.platform, Some(&self.cache_dir)) {
            return Ok(local);
        }

        match self.load_list() {
            Ok(list) => {
                let version = select_version(&reqs, &list)?;
                self.ensure_solc(&version, &list)
            }
            Err(err) => {
                if let Some(local) =
                    find_local_solc_binary(&reqs, self.platform, Some(&self.cache_dir))
                {
                    return Ok(local);
                }
                if reqs.is_empty() {
                    if let Some(local) =
                        find_local_solc_binary(&[], self.platform, Some(&self.cache_dir))
                    {
                        return Ok(local);
                    }
                }
                Err(Error::msg(format!(
                    "{err}; set {SOLC_PATH_ENV}=<solc-binary>, set {SOLC_SEARCH_PATHS_ENV}, or pre-populate cache at {}",
                    self.cache_dir.display()
                )))
            }
        }
    }

    pub fn prepare_legacy_retry(
        &self,
        sources: &[SourceFile],
        current_solc: &Path,
    ) -> Result<Option<PathBuf>> {
        if !has_legacy_solidity_markers(sources) {
            return Ok(None);
        }

        let Some(current_version) = detect_solc_version(current_solc) else {
            return Ok(None);
        };
        let reqs = collect_version_reqs(sources);

        let local = find_local_solc_binaries(&reqs, self.platform, Some(&self.cache_dir));
        if let Some((_, path)) = local
            .into_iter()
            .find(|(version, _)| version < &current_version)
        {
            return Ok(Some(path));
        }

        let list = match self.load_list() {
            Ok(list) => list,
            Err(_) => return Ok(None),
        };
        let Some(version) = select_legacy_retry_version(&reqs, &list, current_version) else {
            return Ok(None);
        };
        self.ensure_solc(&version, &list).map(Some)
    }

    pub fn check_solc(&self, solc_path: &Path) -> Result<()> {
        let output = Command::new(solc_path).arg("--version").output()?;
        if !output.status.success() {
            return Err(Error::msg("solc failed to run"));
        }
        Ok(())
    }

    fn ensure_solc(&self, version: &SolcVersion, list: &SolcList) -> Result<PathBuf> {
        let bin_dir = self.cache_dir.join(format!("solc-v{version}"));
        let bin_path = bin_dir.join(self.platform.exe_name());
        if bin_path.exists() {
            return Ok(bin_path);
        }

        if is_offline_mode() {
            return Err(Error::msg(format!(
                "offline mode ({SOLC_OFFLINE_ENV}=1): missing cached solc {version}"
            )));
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
        Ok(format!(
            "{}/{}/{}",
            SOLC_LIST_BASE,
            self.platform.as_str(),
            filename
        ))
    }

    fn load_list(&self) -> Result<SolcList> {
        let path = self.list_path();
        let mut refresh = true;

        if let Ok(meta) = fs::metadata(&path) {
            if is_fresh(&meta, self.list_ttl) {
                refresh = false;
            }
        }

        if refresh && !is_offline_mode() {
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

    fn find_cached_solc(&self, reqs: &[VersionReq]) -> Result<Option<PathBuf>> {
        let Ok(entries) = fs::read_dir(&self.cache_dir) else {
            return Ok(None);
        };

        let mut candidates = Vec::new();
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let Some(version_str) = name.strip_prefix("solc-v") else {
                continue;
            };
            let Some(version) = SolcVersion::parse(version_str) else {
                continue;
            };
            if !reqs.is_empty() && !reqs.iter().all(|req| req.matches(&version)) {
                continue;
            }
            let bin = path.join(self.platform.exe_name());
            if bin.exists() {
                candidates.push((version, bin));
            }
        }

        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(candidates.pop().map(|(_, path)| path))
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

        Some(Self {
            major,
            minor,
            patch,
        })
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
    let versions = matching_versions(reqs, list);

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

fn select_legacy_retry_version(
    reqs: &[VersionReq],
    list: &SolcList,
    current_version: SolcVersion,
) -> Option<SolcVersion> {
    matching_versions(reqs, list)
        .into_iter()
        .find(|version| version < &current_version)
}

fn matching_versions(reqs: &[VersionReq], list: &SolcList) -> Vec<SolcVersion> {
    let mut versions: Vec<SolcVersion> = list
        .releases
        .keys()
        .filter_map(|value| SolcVersion::parse(value))
        .collect();
    versions.sort();
    if reqs.is_empty() {
        return versions;
    }
    versions
        .into_iter()
        .filter(|version| reqs.iter().all(|req| req.matches(version)))
        .collect()
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
    if reqs.is_empty() && has_legacy_solidity_markers(sources) {
        // For legacy benchmark contracts with no pragma (0.4-era syntax), defaulting to
        // latest solc causes parser errors and forces frontend partial mode.
        // Bound selection to legacy compiler range so full-mode compilation remains possible.
        if let Some(req) = VersionReq::parse("<=0.4.26") {
            reqs.push(req);
        }
    }
    reqs
}

fn has_legacy_solidity_markers(sources: &[SourceFile]) -> bool {
    sources
        .iter()
        .any(|source| source_has_legacy_solidity_markers(&source.source))
}

fn source_has_legacy_solidity_markers(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    has_legacy_anonymous_fallback(&lower)
        || has_legacy_named_constructor(&lower)
        || lower.contains("throw;")
        || lower.contains(" constant returns")
        || lower.contains(") constant")
        || lower.contains("var ")
        || lower.contains("sha3(")
        || lower.contains("msg.gas")
        || lower.contains("suicide(")
        || lower.contains("_}")
        || lower.contains("_ }")
}

fn has_legacy_anonymous_fallback(source: &str) -> bool {
    let mut rest = source;
    while let Some(idx) = rest.find("function") {
        let after = &rest[idx + "function".len()..];
        let trimmed = after.trim_start();
        if trimmed.starts_with('(') {
            return true;
        }
        rest = after;
    }
    false
}

fn has_legacy_named_constructor(source: &str) -> bool {
    let contract_names = legacy_contract_names(source);
    contract_names
        .iter()
        .any(|name| source.contains(&format!("function {name}(")))
}

fn legacy_contract_names(source: &str) -> Vec<String> {
    let tokens: Vec<&str> = source
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| !token.is_empty())
        .collect();
    let mut names = Vec::new();
    let mut idx = 0;
    while idx + 1 < tokens.len() {
        if matches!(tokens[idx], "contract" | "library" | "interface") {
            names.push(tokens[idx + 1].to_string());
            idx += 2;
            continue;
        }
        idx += 1;
    }
    names
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
    let len = input.bytes().take_while(|b| b.is_ascii_digit()).count();
    if len == 0 {
        return None;
    }
    input[..len].parse().ok()
}

fn parse_version_token(token: &str) -> Option<SolcVersion> {
    let start = token.bytes().position(|b| b.is_ascii_digit())?;
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

fn resolve_cache_dir() -> Result<PathBuf> {
    for candidate in cache_dir_candidates() {
        if ensure_writable_dir(&candidate).is_ok() {
            return Ok(candidate);
        }
    }

    Err(Error::msg(
        "unable to find a writable cache directory for solc",
    ))
}

fn cache_dir_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(value) = env::var(SOLC_CACHE_ENV) {
        candidates.push(PathBuf::from(value));
    }

    if let Ok(value) = env::var("XDG_CACHE_HOME") {
        candidates.push(PathBuf::from(value).join("static/solc"));
    }

    if let Ok(value) = env::var("HOME") {
        candidates.push(PathBuf::from(value).join(".cache/static/solc"));
    }

    if let Ok(value) = env::var("USERPROFILE") {
        candidates.push(PathBuf::from(value).join(".cache/static/solc"));
    }

    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd.join(".cache/static/solc"));
    }

    candidates.push(env::temp_dir().join("static-solc-cache"));
    candidates
}

fn ensure_writable_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let probe_path = path.join(".write-probe");
    let mut probe = fs::File::create(&probe_path)?;
    probe.write_all(b"ok")?;
    drop(probe);
    let _ = fs::remove_file(&probe_path);
    Ok(())
}

fn is_offline_mode() -> bool {
    match env::var(SOLC_OFFLINE_ENV) {
        Ok(value) => matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"),
        Err(_) => false,
    }
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
    if let Err(err) = download_with_command("curl", &["-fsSL", "-o", tmp_str, url]) {
        if let Err(err2) = download_with_command("wget", &["-q", "-O", tmp_str, url]) {
            let message = format!("download failed: {err}; fallback failed: {err2}");
            return Err(Error::msg(message));
        }
    }

    fs::rename(tmp, dest)?;
    Ok(())
}

fn download_with_command(cmd: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(cmd).args(args).output();
    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.lines().next().unwrap_or("no stderr");
            Err(Error::msg(format!("{cmd} exited with error: {detail}")))
        }
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

fn find_local_solc_binary(
    reqs: &[VersionReq],
    platform: SolcPlatform,
    preferred_cache: Option<&Path>,
) -> Option<PathBuf> {
    let parsed = find_local_solc_binaries(reqs, platform, preferred_cache);
    parsed.last().map(|(_, path)| path.clone())
}

fn find_local_solc_binaries(
    reqs: &[VersionReq],
    platform: SolcPlatform,
    preferred_cache: Option<&Path>,
) -> Vec<(SolcVersion, PathBuf)> {
    let mut candidates = Vec::new();
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();

    for root in local_solc_search_roots(platform, preferred_cache) {
        collect_solc_candidates(&root, 5, &mut seen_paths, &mut candidates);
    }

    let mut parsed = Vec::new();
    for candidate in candidates {
        if let Some(version) = detect_solc_version(&candidate) {
            if !reqs.is_empty() && !reqs.iter().all(|req| req.matches(&version)) {
                continue;
            }
            parsed.push((version, candidate));
        }
    }
    if parsed.is_empty() {
        return Vec::new();
    }

    parsed.sort_by(|a, b| a.0.cmp(&b.0));
    parsed
}

fn local_solc_search_roots(platform: SolcPlatform, preferred_cache: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(cache) = preferred_cache {
        roots.push(cache.to_path_buf());
    }

    if let Ok(value) = env::var(SOLC_SEARCH_PATHS_ENV) {
        for path in env::split_paths(&value) {
            roots.push(path);
        }
    }

    for candidate in cache_dir_candidates() {
        roots.push(candidate);
    }

    if let Ok(home) = env::var("HOME") {
        let home = PathBuf::from(home);
        roots.push(home.join(".cache/static/solc"));
        roots.push(home.join(".cache/hardhat-nodejs/compilers-v2"));
        roots.push(home.join(".local/share/svm"));
        roots.push(home.join(".foundry/bin"));
    }

    if let Ok(userprofile) = env::var("USERPROFILE") {
        let profile = PathBuf::from(userprofile);
        roots.push(profile.join(".cache/static/solc"));
    }

    if matches!(platform, SolcPlatform::WindowsAmd64) {
        if let Ok(program_data) = env::var("ProgramData") {
            roots.push(PathBuf::from(program_data));
        }
    }

    roots
}

fn collect_solc_candidates(
    path: &Path,
    depth: usize,
    seen_paths: &mut HashSet<PathBuf>,
    out: &mut Vec<PathBuf>,
) {
    if depth == 0 {
        return;
    }

    let Ok(metadata) = fs::metadata(path) else {
        return;
    };

    if metadata.is_file() {
        if is_solc_candidate(path) && seen_paths.insert(path.to_path_buf()) {
            out.push(path.to_path_buf());
        }
        return;
    }

    if !metadata.is_dir() {
        return;
    }

    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        collect_solc_candidates(&entry.path(), depth.saturating_sub(1), seen_paths, out);
    }
}

fn is_solc_candidate(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".js") {
        return false;
    }
    lower == "solc"
        || lower == "solc.exe"
        || lower.starts_with("solc-")
        || lower.starts_with("solc-linux-")
}

fn detect_solc_version(path: &Path) -> Option<SolcVersion> {
    if let Some(version) = detect_solc_version_hint(path) {
        return Some(version);
    }

    let output = Command::new(path).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(version) = parse_version_token(stdout.as_ref()) {
        return Some(version);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    parse_version_token(stderr.as_ref())
}

fn detect_solc_version_hint(path: &Path) -> Option<SolcVersion> {
    for component in version_hint_components(path) {
        if let Some(version) = parse_version_hint_component(&component) {
            return Some(version);
        }
    }
    None
}

fn parse_version_hint_component(component: &str) -> Option<SolcVersion> {
    if let Some(idx) = component.rfind("-v") {
        if let Some(version) = parse_version_token(&component[idx + 2..]) {
            return Some(version);
        }
    }
    if let Some(stripped) = component.strip_prefix("solc-v") {
        if let Some(version) = parse_version_token(stripped) {
            return Some(version);
        }
    }
    if let Some(stripped) = component.strip_prefix("solc-") {
        if let Some(version) = parse_version_token(stripped) {
            return Some(version);
        }
    }

    let trimmed = component.trim_start();
    if trimmed.starts_with('v') || trimmed.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        return parse_version_token(trimmed);
    }

    None
}

fn version_hint_components(path: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
        out.push(name.to_string());
    }
    if let Some(parent) = path.parent() {
        if let Some(name) = parent.file_name().and_then(|value| value.to_str()) {
            out.push(name.to_string());
        }
        if let Some(grand) = parent.parent() {
            if let Some(name) = grand.file_name().and_then(|value| value.to_str()) {
                out.push(name.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainvet_core::norm::SourceFile;

    fn mk_source(id: u32, body: &str) -> SourceFile {
        SourceFile {
            id,
            path: format!("C{id}.sol"),
            source: body.to_string(),
        }
    }

    #[test]
    fn legacy_markers_detect_function_style_fallback_without_pragma() {
        let src = r#"
contract C {
    function() {
    }
}
"#;
        let reqs = collect_version_reqs(&[mk_source(0, src)]);
        assert!(!reqs.is_empty());
        let v = SolcVersion {
            major: 0,
            minor: 4,
            patch: 26,
        };
        assert!(reqs.iter().all(|req| req.matches(&v)));
    }

    #[test]
    fn pragma_still_controls_version_selection_when_present() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    function f() external {}
}
"#;
        let reqs = collect_version_reqs(&[mk_source(0, src)]);
        assert!(!reqs.is_empty());
        let modern = SolcVersion {
            major: 0,
            minor: 8,
            patch: 21,
        };
        let legacy = SolcVersion {
            major: 0,
            minor: 4,
            patch: 26,
        };
        assert!(reqs.iter().all(|req| req.matches(&modern)));
        assert!(!reqs.iter().all(|req| req.matches(&legacy)));
    }

    #[test]
    fn legacy_markers_detect_constant_functions_without_pragma() {
        let src = r#"
contract OpenAddressLottery {
    function luckyNumberOfAddress(address addr) constant returns (uint n) {
        return 7;
    }
}
"#;
        let reqs = collect_version_reqs(&[mk_source(0, src)]);
        assert!(!reqs.is_empty());
        let legacy = SolcVersion {
            major: 0,
            minor: 4,
            patch: 26,
        };
        let modern = SolcVersion {
            major: 0,
            minor: 8,
            patch: 34,
        };
        assert!(reqs.iter().all(|req| req.matches(&legacy)));
        assert!(!reqs.iter().all(|req| req.matches(&modern)));
    }

    #[test]
    fn legacy_markers_detect_named_constructor_without_pragma() {
        let src = r#"
contract C {
    function C() {
    }
}
"#;
        let reqs = collect_version_reqs(&[mk_source(0, src)]);
        assert!(!reqs.is_empty());
        let legacy = SolcVersion {
            major: 0,
            minor: 4,
            patch: 26,
        };
        let modern = SolcVersion {
            major: 0,
            minor: 8,
            patch: 34,
        };
        assert!(reqs.iter().all(|req| req.matches(&legacy)));
        assert!(!reqs.iter().all(|req| req.matches(&modern)));
    }

    #[test]
    fn legacy_retry_prefers_older_matching_release() {
        let req = VersionReq::parse("^0.4.9").expect("version req");
        let list = SolcList {
            releases: HashMap::from([
                ("0.4.10".to_string(), "solc-0.4.10".to_string()),
                ("0.4.15".to_string(), "solc-0.4.15".to_string()),
                ("0.4.26".to_string(), "solc-0.4.26".to_string()),
                ("0.5.17".to_string(), "solc-0.5.17".to_string()),
            ]),
            latest_release: "0.5.17".to_string(),
        };
        let current = SolcVersion {
            major: 0,
            minor: 4,
            patch: 26,
        };
        let retry = select_legacy_retry_version(&[req], &list, current).expect("retry version");
        assert_eq!(
            retry,
            SolcVersion {
                major: 0,
                minor: 4,
                patch: 10,
            }
        );
    }
}
