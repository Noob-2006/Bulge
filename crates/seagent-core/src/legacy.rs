//! The product was called `ark` before it became SE Agent (`seagent`). What an older install
//! left behind keeps working:
//!
//! * `ARK_*` environment variables are read as their `SEAGENT_*` names when those are unset
//!   ([`adopt_env`], called first thing in `main`);
//! * the per-user directories `~/.config/ark`, `~/.local/share/ark`, `~/.cache/ark` (XDG) are
//!   moved to their `seagent` names the first time, when the new ones do not exist yet
//!   ([`migrate_user_dirs`]); system installs are moved by the package scripts;
//! * a project's `.ark/` directory is read while it has no `.seagent/` ([`project_dir`]).

use std::path::{Path, PathBuf};

const OLD_ENV: &str = "ARK_";
const NEW_ENV: &str = "SEAGENT_";

/// `(old, new)` names of every `ARK_*` variable in `vars` whose `SEAGENT_*` twin is not set.
pub fn env_renames(vars: &[(String, String)]) -> Vec<(String, String)> {
    let set: std::collections::HashSet<&str> = vars.iter().map(|(k, _)| k.as_str()).collect();
    vars.iter()
        .filter_map(|(k, _)| {
            let new = format!("{NEW_ENV}{}", k.strip_prefix(OLD_ENV)?);
            (!set.contains(new.as_str())).then(|| (k.clone(), new))
        })
        .collect()
}

/// Copy `ARK_*` variables to their `SEAGENT_*` names (the new name wins when both are set).
/// Call before any thread starts: it changes the process environment.
pub fn adopt_env() {
    let vars: Vec<(String, String)> = std::env::vars().collect();
    for (old, new) in env_renames(&vars) {
        if let Some(v) = std::env::var_os(&old) {
            std::env::set_var(new, v);
        }
    }
}

/// The per-user directories to move: `(old, new)` for each XDG root whose `ark` directory
/// exists while the `seagent` one does not.
pub fn user_dir_moves(home: &Path, env: &dyn Fn(&str) -> Option<String>, exists: &dyn Fn(&Path) -> bool) -> Vec<(PathBuf, PathBuf)> {
    let root = |var: &str, def: &str| env(var).filter(|s| !s.is_empty()).map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| home.join(def));
    [("XDG_CONFIG_HOME", ".config"), ("XDG_DATA_HOME", ".local/share"), ("XDG_CACHE_HOME", ".cache")]
        .iter()
        .map(|(v, d)| root(v, d))
        .map(|r| (r.join("ark"), r.join("seagent")))
        .filter(|(old, new)| exists(old) && !exists(new))
        .collect()
}

/// Move the pre-rename per-user directories into place (user mode only: nothing to do when
/// `SEAGENT_HOME` or `SEAGENT_MODE` chooses another layout). Returns one line per move.
pub fn migrate_user_dirs() -> Vec<String> {
    if std::env::var_os("SEAGENT_HOME").is_some() || std::env::var("SEAGENT_MODE").is_ok_and(|m| m.trim().eq_ignore_ascii_case("system")) {
        return vec![];
    }
    let home = crate::layout::home();
    let env = |k: &str| std::env::var(k).ok();
    let moves = user_dir_moves(&home, &env, &|p: &Path| p.symlink_metadata().is_ok());
    moves
        .into_iter()
        .map(|(old, new)| match std::fs::rename(&old, &new) {
            Ok(()) => format!("moved {} to {} (ark is now SE Agent)", old.display(), new.display()),
            Err(e) => format!("could not move {} to {}: {e}; move it by hand", old.display(), new.display()),
        })
        .collect()
}

/// A project's own directory: `.seagent/`, or a pre-rename `.ark/` while there is no `.seagent/`.
pub fn project_dir(workspace: &Path) -> PathBuf {
    let new = workspace.join(".seagent");
    let old = workspace.join(".ark");
    if !new.exists() && old.is_dir() {
        old
    } else {
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_variables_fill_in_only_what_the_new_names_leave_unset() {
        let v = |k: &str| (k.to_string(), "x".to_string());
        let r = env_renames(&[v("ARK_HOME"), v("ARK_MODE"), v("SEAGENT_MODE"), v("PATH"), v("MARK_X")]);
        assert_eq!(r, vec![("ARK_HOME".to_string(), "SEAGENT_HOME".to_string())]);
    }

    #[test]
    fn pre_rename_user_directories_move_once() {
        // Absolute fixture paths: `/h` on Unix, `C:\h` on Windows (where `/h` is not absolute).
        let fx = |s: &str| if cfg!(windows) { PathBuf::from(format!("C:{s}")) } else { PathBuf::from(s) };
        let home = fx("/h");
        let env = |k: &str| (k == "XDG_CACHE_HOME").then(|| fx("/xc").to_string_lossy().into_owned());
        let have = ["/h/.config/ark", "/h/.local/share/ark", "/h/.local/share/seagent", "/xc/ark"].map(fx);
        let exists = |p: &Path| have.iter().any(|h| h.as_path() == p);
        let m = user_dir_moves(&home, &env, &exists);
        assert_eq!(m, vec![(fx("/h/.config/ark"), fx("/h/.config/seagent")), (fx("/xc/ark"), fx("/xc/seagent"))], "data already moved stays put");
    }

    #[test]
    fn a_project_keeps_its_old_directory_until_it_has_a_new_one() {
        let ws = crate::tmp::scratch("legacy-proj");
        assert_eq!(project_dir(&ws), ws.join(".seagent"));
        std::fs::create_dir_all(ws.join(".ark")).unwrap();
        assert_eq!(project_dir(&ws), ws.join(".ark"));
        std::fs::create_dir_all(ws.join(".seagent")).unwrap();
        assert_eq!(project_dir(&ws), ws.join(".seagent"));
    }
}
