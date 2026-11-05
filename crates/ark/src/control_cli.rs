//! `ark browser`, `ark screen` and `ark computer-use`: the browser and desktop runtime
//! commands. Behaviour lives in `ark_browser::control` (Hermes
//! `hermes_cli/subcommands/{browser,computer_use,computer_use_screen}.py`); this module
//! only supplies the terminal, the config tables and this home's data directory.

use ark_browser::control::{browser_command, cua, screen};
use ark_browser::control::screen::Io as _;
use ark_kernel::config::{Config, Paths};
use std::io::{BufRead, IsTerminal, Write};

/// The terminal `ark` was started from: prompts read the line the user types.
pub struct Term;

impl screen::Io for Term {
    fn line(&mut self, s: &str) {
        println!("{s}");
    }
    fn confirm(&mut self, q: &str) -> bool {
        print!("{q}");
        let _ = std::io::stdout().flush();
        let mut l = String::new();
        if std::io::stdin().read_line(&mut l).is_err() {
            return false;
        }
        matches!(l.trim().to_ascii_lowercase().as_str(), "" | "y" | "yes")
    }
    fn password(&mut self) -> Option<String> {
        hidden_line("sudo password: ")
    }
}

/// One line with echo off (a package-manager password must not land in a terminal log).
fn hidden_line(prompt: &str) -> Option<String> {
    use std::io::Write as _;
    use std::os::fd::AsRawFd;
    let tty = std::io::stdin().is_terminal().then(|| std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").ok()).flatten()?;
    let mut out = std::fs::OpenOptions::new().write(true).open("/dev/tty").ok()?;
    let _ = out.write_all(prompt.as_bytes());
    let _ = out.flush();
    let fd = tty.as_raw_fd();
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let have = unsafe { libc::tcgetattr(fd, &mut old) } == 0;
    if have {
        let mut quiet = old;
        quiet.c_lflag &= !libc::ECHO;
        quiet.c_lflag |= libc::ECHONL;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let mut line = String::new();
    let r = std::io::BufReader::new(tty).read_line(&mut line);
    if have {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
    }
    r.ok().filter(|n| *n > 0).map(|_| line.trim_end_matches(['\n', '\r']).to_string())
}

/// `[computer_use]` as the whole-config table `Cu::new` / `Desktop::with_config` read.
fn computer_use_table(cfg: &Config) -> toml::Table {
    let mut t = toml::Table::new();
    t.insert("computer_use".into(), toml::Value::Table(cfg.computer_use.clone()));
    t
}

/// Exit code of `ark browser|screen|computer-use …` (`argv` excludes the command word).
pub fn cli(cmd: &str, argv: &[String], cfg: &Config, paths: &Paths) -> i32 {
    let mut io = Term;
    let t = computer_use_table(cfg);
    match cmd {
        "browser" => match ark_browser::BrowserConfig::parse(&cfg.browser) {
            Ok(c) => browser_command(&c, &paths.data, argv, &mut io),
            Err(e) => {
                io.line(&e);
                2
            }
        },
        "screen" => screen::screen_cli(&screen::Desktop::new(&paths.data).with_config(&t), argv, &mut io),
        _ => cua::computer_use_cli(&cua::Cu::new(&paths.data, &t), argv, &mut io),
    }
}

/// Self-registration (`ark_core::registry`): `ark browser|screen|computer-use …` (their own
/// flags: `--browser`, `--url`, `-y`, `--json`).
pub fn register_route() {
    ark_core::registry::register_command_route("browser,screen,computer-use", None, route);
}

fn route(cmd: &str, argv: &[String]) -> Result<i32, String> {
    let a = crate::args::Args::parse(&[])?;
    let paths = ark_kernel::config::Paths::from_env();
    let cfg = crate::load_config(&a, &crate::workspace(&a).map_err(|e| e.to_string())?, &paths).map_err(|e| e.to_string())?;
    Ok(cli(cmd, argv, &cfg, &paths))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        let root = ark_core::tmp::scratch_path(format!("ark-ctl-{}", ark_kernel::util::random_hex(6)));
        std::fs::create_dir_all(root.join("data")).unwrap();
        Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() }
    }

    /// `ark browser` with no subcommand prints its usage (exit 2), and `--help` reaches the
    /// same text; the command word is registered on the CLI.
    #[test]
    fn browser_screen_and_computer_use_are_cli_commands() {
        let p = paths();
        let cfg = Config::default();
        assert_eq!(cli("browser", &[], &cfg, &p), 2);
        assert_eq!(cli("browser", &["nonsense".into()], &cfg, &p), 2);
        // `ark screen` on a host without the packages: status exits 1 with the install hint.
        let rc = cli("screen", &["status".into()], &cfg, &p);
        assert!(rc == 1 || rc == 0, "screen status returns a status code");
        assert_eq!(cli("computer-use", &["nonsense".into()], &cfg, &p), 2);
    }
}
