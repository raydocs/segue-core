//! Process-mode flags, log file and exit codes for `segue-kernel`.
//!
//! Exit codes (also the appendix of `docs/design/app/macos.md`):
//!
//! | code | when |
//! |---|---|
//! | 0 | `--help`, or a clean shutdown: `SIGTERM` / `SIGINT` closed the listeners, flushed fake-IP state and removed the control token |
//! | 1 | the process was up and a listener failed |
//! | 2 | the arguments are not a known command |
//! | 3 | the kernel JSON, `--state-dir` or `--log` path was rejected |
//! | 4 | macOS utun, address, MTU or route install failed; routes already added were removed |
//!
//! `--state-dir` is the runtime directory (token, fake-IP journal, the copy of
//! the last good policy bundle). It does not move the config file, a delivered
//! policy bundle, tickets or `chnroute_file`. `--log` appends the same lines
//! that are written to stderr.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Process exit status. The numeric values are the contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    Clean = 0,
    Runtime = 1,
    Usage = 2,
    Config = 3,
    Tun = 4,
}

impl ExitCode {
    pub fn to_process(self) -> std::process::ExitCode {
        std::process::ExitCode::from(self as u8)
    }
}

/// Why `run` stopped before a clean exit.
#[derive(Debug)]
pub enum RunFailure {
    Config(String),
    Runtime(String),
    Tun(String),
}

impl RunFailure {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn runtime(msg: impl Into<String>) -> Self {
        Self::Runtime(msg.into())
    }

    pub fn tun(msg: impl Into<String>) -> Self {
        Self::Tun(msg.into())
    }

    pub fn code(&self) -> ExitCode {
        match self {
            Self::Config(_) => ExitCode::Config,
            Self::Runtime(_) => ExitCode::Runtime,
            Self::Tun(_) => ExitCode::Tun,
        }
    }
}

impl std::fmt::Display for RunFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(m) | Self::Runtime(m) | Self::Tun(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for RunFailure {}

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
pub enum Args {
    Help,
    Keygen(PathBuf),
    /// Arguments after `sign-bundle`, still parsed by the signer.
    Sign(Vec<String>),
    Run(RunArgs),
}

/// `segue-kernel [run] [--state-dir DIR] [--log PATH] <kernel.json>`.
#[derive(Debug, PartialEq, Eq)]
pub struct RunArgs {
    pub config: PathBuf,
    pub state_dir: Option<PathBuf>,
    pub log: Option<PathBuf>,
}

pub fn parse_args(args: &[String]) -> Result<Args, String> {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Args::Help);
    }
    if args[0] == "sign-bundle" {
        return Ok(Args::Sign(args[1..].to_vec()));
    }
    if args[0] == "policy-keygen" {
        if args.len() != 2 || args[1].starts_with('-') {
            return Err("policy-keygen needs one key file".into());
        }
        return Ok(Args::Keygen(PathBuf::from(&args[1])));
    }

    let mut config = None;
    let mut state_dir = None;
    let mut log = None;
    let mut saw_run = false;
    let mut i = 0;
    if args[0] == "run" {
        saw_run = true;
        i = 1;
    }
    while i < args.len() {
        let a = &args[i];
        if a == "--state-dir" || a == "--log" {
            let value = args.get(i + 1).filter(|v| !v.starts_with('-'));
            let Some(value) = value else {
                return Err(format!("{a} needs a path"));
            };
            if a == "--state-dir" {
                state_dir = Some(PathBuf::from(value));
            } else {
                log = Some(PathBuf::from(value));
            }
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            return Err(format!("unknown argument {a}"));
        }
        if config.is_some() {
            return Err(format!("unexpected argument {a}"));
        }
        config = Some(PathBuf::from(a));
        i += 1;
    }
    let Some(config) = config else {
        return Err(if saw_run {
            "run needs a kernel json file".into()
        } else {
            "need a kernel json file, policy-keygen or sign-bundle".into()
        });
    };
    Ok(Args::Run(RunArgs {
        config,
        state_dir,
        log,
    }))
}

/// Stderr plus an optional append-only log (mode 0600).
pub struct Log {
    file: Option<Mutex<File>>,
}

impl Log {
    pub fn stderr() -> Self {
        Self { file: None }
    }

    pub fn open(path: Option<&Path>) -> io::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::stderr());
        };
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path)?;
        Ok(Self {
            file: Some(Mutex::new(file)),
        })
    }

    pub fn line(&self, msg: impl std::fmt::Display) {
        eprintln!("segue-kernel: {msg}");
        self.record(msg);
    }

    /// Append one line to the `--log` file and do not touch stderr.
    ///
    /// Fatal startup errors are printed by `main` and must also land in the
    /// file. `line` would print them a second time.
    pub fn record(&self, msg: impl std::fmt::Display) {
        let Some(file) = &self.file else {
            return;
        };
        let Ok(mut file) = file.lock() else {
            return;
        };
        let _ = writeln!(file, "segue-kernel: {msg}");
        let _ = file.flush();
    }
}

/// Create `dir` (and parents) and restrict it to the owner.
pub fn create_state_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_string()).collect()
    }

    #[test]
    fn exit_codes_are_the_documented_numbers() {
        assert_eq!(ExitCode::Clean as u8, 0);
        assert_eq!(ExitCode::Runtime as u8, 1);
        assert_eq!(ExitCode::Usage as u8, 2);
        assert_eq!(ExitCode::Config as u8, 3);
        assert_eq!(ExitCode::Tun as u8, 4);
        assert_eq!(RunFailure::config("a").code(), ExitCode::Config);
        assert_eq!(RunFailure::runtime("a").code(), ExitCode::Runtime);
        assert_eq!(RunFailure::tun("a").code(), ExitCode::Tun);
        assert_eq!(RunFailure::tun("utun: denied").to_string(), "utun: denied");
    }

    #[test]
    fn record_appends_a_fatal_line_without_a_second_stderr_path() {
        let path =
            std::env::temp_dir().join(format!("segue-kernel-log-{}-record", std::process::id()));
        let log = Log::open(Some(&path)).unwrap();
        log.record("tun mtu: ioctl SIOCSIFMTU: Operation not permitted (os error 1) (errno 1)");
        drop(log);
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(text.contains("ioctl SIOCSIFMTU"), "{text}");
        assert!(text.contains("errno 1"), "{text}");
        Log::stderr().record("not stored");
    }

    #[test]
    fn parses_run_flags_in_either_order() {
        let bare = parse_args(&s(&["kernel.json"])).unwrap();
        assert_eq!(
            bare,
            Args::Run(RunArgs {
                config: PathBuf::from("kernel.json"),
                state_dir: None,
                log: None,
            })
        );
        let flagged = parse_args(&s(&[
            "run",
            "--log",
            "kernel.log",
            "--state-dir",
            "/var/run/segue",
            "kernel.json",
        ]))
        .unwrap();
        assert_eq!(
            flagged,
            Args::Run(RunArgs {
                config: PathBuf::from("kernel.json"),
                state_dir: Some(PathBuf::from("/var/run/segue")),
                log: Some(PathBuf::from("kernel.log")),
            })
        );
        let after = parse_args(&s(&["cfg.json", "--state-dir", "state"])).unwrap();
        match after {
            Args::Run(r) => {
                assert_eq!(r.config, PathBuf::from("cfg.json"));
                assert_eq!(r.state_dir.unwrap(), PathBuf::from("state"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_bad_arguments_and_keeps_the_dev_tools() {
        assert!(matches!(parse_args(&s(&["--help"])), Ok(Args::Help)));
        assert!(matches!(parse_args(&[]), Ok(Args::Help)));
        assert!(parse_args(&s(&["run"])).is_err());
        assert!(parse_args(&s(&["--state-dir"])).is_err());
        assert!(parse_args(&s(&["--nope", "a.json"])).is_err());
        assert!(parse_args(&s(&["a.json", "b.json"])).is_err());
        assert_eq!(
            parse_args(&s(&["policy-keygen", "k"])).unwrap(),
            Args::Keygen(PathBuf::from("k"))
        );
        assert!(parse_args(&s(&["policy-keygen"])).is_err());
        assert_eq!(
            parse_args(&s(&["sign-bundle", "--key", "k"])).unwrap(),
            Args::Sign(vec!["--key".into(), "k".into()])
        );
    }

    #[test]
    fn state_dir_is_owner_only_and_log_appends() {
        let dir = std::env::temp_dir().join(format!("segue-proc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let state = dir.join("state");
        create_state_dir(&state).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&state).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        let log_path = dir.join("kernel.log");
        let log = Log::open(Some(&log_path)).unwrap();
        log.line("first");
        log.line("second");
        drop(log);
        let text = fs::read_to_string(&log_path).unwrap();
        assert_eq!(text, "segue-kernel: first\nsegue-kernel: second\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&log_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
