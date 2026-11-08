//! Singularity / Apptainer backend (Hermes
//! `tools/environments/singularity.py`): every command is one
//! `singularity exec … <image> bash -c <script>` process on this machine.
//!
//! The host workspace is bind-mounted at the same path (`--bind ws:ws`), so file
//! tools need no sync (`shares_host_fs()`), `map_path` is the identity, and a PTY
//! works (the container inherits the terminal). Sandbox policy is honoured:
//! `workspace_access = "ro"` bind-mounts read-only and `"none"` binds the
//! scope's private scratch workspace instead of the real one; `[exec.sandbox]
//! binds` and `[exec.singularity] binds` are validated as host mounts.

use super::local::{self, spawn_command};
use super::sandbox::{self, SandboxConfig};
use super::BackendCtx;
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest};
use serde::Deserialize;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `[exec.singularity]` (and `[exec.apptainer]` uses `singularity`, see config)
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SingularityConfig {
    /// `.sif` path, `docker://…` URI or an existing image URI. Required.
    pub image: String,
    /// CLI to use: `singularity`, `apptainer`, or an absolute path. Empty = first of
    /// `apptainer`, `singularity` found in PATH (Hermes `_find_singularity_executable`).
    pub binary: String,
    /// Extra `--bind host:container[:ro]` mounts.
    pub binds: Vec<String>,
    /// `--nv`: expose the host NVIDIA driver + GPUs.
    pub nv: bool,
    /// `--cleanenv`: do not inherit the host environment.
    pub cleanenv: bool,
    /// `--no-home` (default on): the container must not see the host home directory.
    pub no_home: bool,
    /// Raw arguments inserted before the image (`--fakeroot`, `--writable-tmpfs`, …).
    pub extra_args: Vec<String>,
}

impl Default for SingularityConfig {
    fn default() -> Self {
        SingularityConfig { image: String::new(), binary: String::new(), binds: vec![], nv: false, cleanenv: false, no_home: true, extra_args: vec![] }
    }
}

/// Where the workspace is mounted and whether it is writable.
fn mount(sb: &SandboxConfig, ctx: &BackendCtx) -> Result<(PathBuf, bool), String> {
    Ok(match (ctx.sandboxed, sb.workspace_access.as_str()) {
        (true, "none") => {
            let w = sb.scratch_workspace(&ctx.home, &ctx.scope_key);
            std::fs::create_dir_all(&w).map_err(|e| format!("create {}: {e}", w.display()))?;
            (w, true)
        }
        (true, "ro") => (ctx.workspace.clone(), false),
        _ => (ctx.workspace.clone(), true),
    })
}

pub struct SingularityBackend {
    cfg: SingularityConfig,
    exe: String,
    /// Bind-mounted workspace (real one, or the private scratch copy).
    workspace: PathBuf,
    writable: bool,
    binds: Vec<(PathBuf, String, bool)>,
    id: &'static str,
}

impl SingularityBackend {
    pub fn new(cfg: &SingularityConfig, name: &str, sb: &SandboxConfig, ctx: &BackendCtx) -> Result<SingularityBackend, String> {
        if cfg.image.trim().is_empty() {
            return Err("exec backend singularity: set `[exec.singularity] image` (a .sif file, `docker://…` URI, or an image path)".into());
        }
        let exe = resolve_exe(&cfg.binary)?;
        let mut binds = sb.binds.iter().map(|b| sandbox::parse_bind(b)).collect::<Result<Vec<_>, _>>()?;
        binds.extend(cfg.binds.iter().map(|b| sandbox::parse_bind(b)).collect::<Result<Vec<_>, _>>()?);
        let (workspace, writable) = mount(sb, ctx)?;
        Ok(SingularityBackend { cfg: cfg.clone(), exe, workspace, writable, binds, id: if name == "apptainer" { "apptainer" } else { "singularity" } })
    }

    /// `exec` argv (without the `bash -c` tail).
    pub fn args(&self) -> Vec<String> {
        let mut a: Vec<String> = vec!["exec".into()];
        if self.cfg.cleanenv {
            a.push("--cleanenv".into());
        }
        if self.cfg.no_home {
            a.push("--no-home".into());
        }
        if self.cfg.nv {
            a.push("--nv".into());
        }
        let ws = self.workspace.display().to_string();
        a.extend(["--bind".into(), format!("{ws}:{ws}{}", if self.writable { "" } else { ":ro" })]);
        for (src, dst, ro) in &self.binds {
            a.extend(["--bind".into(), format!("{}:{dst}{}", src.display(), if *ro { ":ro" } else { "" })]);
        }
        a.extend(self.cfg.extra_args.iter().cloned());
        a.push(self.cfg.image.clone());
        a
    }
}

fn resolve_exe(binary: &str) -> Result<String, String> {
    let exe = if !binary.trim().is_empty() {
        if local::which(binary).is_none() {
            return Err(format!("exec backend singularity: `{binary}` not found in PATH (install Apptainer/Singularity or fix [exec.singularity] binary)"));
        }
        binary.to_string()
    } else {
        ["apptainer", "singularity"].into_iter().find(|e| local::which(e).is_some()).ok_or_else(|| {
            "exec backend singularity: neither `apptainer` nor `singularity` was found in PATH — install Apptainer (https://apptainer.org/docs/admin/main/installation.html) \
or Singularity, or set [exec.singularity] binary to its absolute path"
                .to_string()
        })?
        .to_string()
    };
    // Hermes `_ensure_singularity_available`: the binary must actually run.
    let out = super::probe_output(Command::new(&exe).arg("version")).map_err(|e| format!("exec backend singularity: cannot run `{exe} version`: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().chars().take(200).collect::<String>();
        return Err(format!("exec backend singularity: `{exe} version` failed ({}): {err}", out.status.code().map(|c| format!("exit {c}")).unwrap_or_else(|| "killed".into())));
    }
    Ok(exe)
}

impl ExecBackend for SingularityBackend {
    fn id(&self) -> &str {
        self.id
    }
    fn describe(&self) -> String {
        format!(
            "{}: container {} runs `bash -c` with the workspace {} bound {} at {}",
            self.id,
            self.cfg.image,
            if self.writable { "read-write" } else { "read-only" },
            self.workspace.display(),
            self.workspace.display()
        )
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        let mut script = String::new();
        if let Some(c) = &req.cwd {
            script.push_str(&format!("mkdir -p {0} && cd {0} || exit 126\n", super::sh_quote(&self.map_path(c))));
        }
        script.push_str(&req.script);
        let mut cmd = Command::new(&self.exe);
        cmd.args(self.args());
        cmd.arg("bash").arg(if req.login { "-lc" } else { "-c" }).arg(script);
        // PTY and detach are handled by the local spawner: the container is a host process.
        spawn_command(cmd, req, None)
    }
    fn map_path(&self, host: &Path) -> String {
        // The workspace is bound at its host path; anything else is whatever the
        // image provides, so the host path is the best answer either way.
        host.display().to_string()
    }
    fn shares_host_fs(&self) -> bool {
        true
    }
    fn supports_pty(&self) -> bool {
        true
    }
    fn temp_dir(&self) -> String {
        "/tmp".into()
    }
}

#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code, unused_imports))]
mod tests {
    use super::*;
    use crate::exec::sync::common::fakecli;
    use crate::exec::{ExecConfig, ExecEnv};
    use crate::testutil::tmpdir;
    use serde_json::json;

    #[cfg(unix)]
    /// A stand-in `singularity`: `version` answers the preflight, `exec` records
    /// its argv and runs the trailing script locally (the workspace is bound at
    /// the same path, so local bash is a fair stand-in).
    fn fake_singularity(bin: &Path, log: &Path) -> PathBuf {
        let body = format!(
            r#"#!/bin/bash
printf '%s\n' "$*" >> {log}
if [ "$1" = "version" ]; then echo "apptainer version 1.3.6-fake"; exit 0; fi
last=""
for a in "$@"; do last="$a"; done
exec bash -c "$last"
"#,
            log = log.display()
        );
        fakecli::script(bin, "singularity", &body)
    }

    fn ctx(ws: &Path, home: &Path) -> BackendCtx {
        BackendCtx { workspace: ws.to_path_buf(), scope_key: "s-1".into(), secrets: std::sync::Arc::new(|s: &str| s.to_string()), home: home.to_path_buf(), sandboxed: true }
    }

    #[cfg(unix)]
    #[test]
    fn exec_argv_bind_pty_and_errors() {
        let base = tmpdir("sing");
        let (ws, home, bin) = (base.join("ws"), base.join("home"), base.join("bin"));
        for d in [&ws, &home] {
            std::fs::create_dir_all(d).unwrap();
        }
        let log = base.join("sing.log");
        let exe = fake_singularity(&bin, &log);
        let ws = ws.canonicalize().unwrap_or(ws);
        std::fs::write(ws.join("in.txt"), "data").unwrap();
        let read = || std::fs::read_to_string(&log).unwrap_or_default();

        // Through `[exec] backend = "singularity"` — the user-reachable path.
        let cfg = ExecConfig {
            backend: "singularity".into(),
            singularity: SingularityConfig {
                image: "img.sif".into(),
                binary: exe.display().to_string(),
                binds: vec![format!("{}:/data", ws.display())],
                nv: true,
                cleanenv: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let env = ExecEnv::new(cfg);
        let secrets: std::sync::Arc<dyn Fn(&str) -> String + Send + Sync> = std::sync::Arc::new(|s: &str| s.to_string());
        let b = env.backend("s1", &ws, &home, &secrets, false).unwrap();
        assert_eq!(b.id(), "singularity");
        assert!(b.shares_host_fs() && b.supports_pty(), "bind-mounted workspace, real tty");
        assert_eq!(b.map_path(&ws.join("a")), ws.join("a").display().to_string());

        let req = ExecRequest { script: "cat in.txt; echo hi; exit 3".into(), cwd: Some(ws.clone()), env: vec![("A".into(), "1".into())], ..Default::default() };
        let (st, out) = crate::exec::drain(b.spawn(&req).unwrap(), std::time::Duration::from_secs(20)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert_eq!(st.code, Some(3), "{s}");
        assert!(s.contains("data") && s.contains("hi"), "{s}");
        let argv = read();
        assert!(argv.contains("exec --cleanenv --no-home --nv"), "{argv}");
        assert!(argv.contains(&format!("--bind {}:{}", ws.display(), ws.display())), "workspace bound at its own path: {argv}");
        assert!(argv.contains(&format!("--bind {}:/data", ws.display())), "{argv}");
        assert!(argv.contains("img.sif bash -c"), "image then bash -c: {argv}");
        assert!(argv.contains(&format!("cd {} || exit 126", ws.display())), "cwd mapped into the container: {argv}");
        // A PTY works: the container is a local process, so spawn_command's pty is inherited.
        let (st, out) = crate::exec::drain(b.spawn(&ExecRequest { script: "tty".into(), pty: Some((24, 80)), ..Default::default() }).unwrap(), std::time::Duration::from_secs(20)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("/dev/pts"), "pty inside the container: {}", String::from_utf8_lossy(&out));

        // Sandboxed sessions (`[exec.sandbox]`) honour `workspace_access`.
        let sb = |access: &str| SandboxConfig { mode: "all".into(), backend: "singularity".into(), workspace_access: access.into(), ..Default::default() };
        let sing = || SingularityConfig { image: "img.sif".into(), binary: exe.display().to_string(), ..Default::default() };
        let ro = ExecConfig { backend: "local".into(), sandbox: sb("ro"), singularity: sing(), ..Default::default() };
        let b = ExecEnv::new(ro).backend("s2", &ws, &home, &secrets, false).unwrap();
        assert!(b.describe().contains("read-only"), "{}", b.describe());
        crate::exec::drain(b.spawn(&ExecRequest { script: "true".into(), ..Default::default() }).unwrap(), std::time::Duration::from_secs(20)).unwrap();
        assert!(read().contains(&format!("--bind {}:{}:ro", ws.display(), ws.display())), "ro workspace: {}", read());
        let none = ExecConfig { backend: "local".into(), sandbox: sb("none"), singularity: sing(), ..Default::default() };
        let scratch = ExecEnv::new(none).backend("s3", &ws, &home, &secrets, false).unwrap();
        assert_eq!(scratch.id(), "singularity");
        let private = home.join("sandboxes").join(format!("s-{}", crate::exec::sanitize("s3"))).join("workspace");
        assert!(scratch.describe().contains(&private.display().to_string()), "private scratch workspace: {}", scratch.describe());
        crate::exec::drain(scratch.spawn(&ExecRequest { script: "true".into(), ..Default::default() }).unwrap(), std::time::Duration::from_secs(20)).unwrap();
        assert!(read().contains(&format!("--bind {}:{}", private.display(), private.display())), "scratch bind: {}", read());

        // Errors: empty image, missing binary, broken binary.
        let d = tmpdir("singerr");
        let c = ctx(&ws, &d);
        let e = SingularityBackend::new(&SingularityConfig::default(), "singularity", &SandboxConfig::default(), &c).err().unwrap();
        assert!(e.contains("[exec.singularity] image"), "{e}");
        let e = SingularityBackend::new(&SingularityConfig { image: "i.sif".into(), binary: "/nonexistent/singularity-xyz".into(), ..Default::default() }, "singularity", &SandboxConfig::default(), &c).err().unwrap();
        assert!(e.contains("not found in PATH"), "{e}");
        let bad = fakecli::script(&bin, "bad-singularity", "#!/bin/bash\necho 'no kernel support' >&2\nexit 1\n");
        let e = SingularityBackend::new(&SingularityConfig { image: "i.sif".into(), binary: bad.display().to_string(), ..Default::default() }, "singularity", &SandboxConfig::default(), &c).err().unwrap();
        assert!(e.contains("version` failed") && e.contains("no kernel support"), "{e}");
        // Bind specs are validated like the sandbox's own (`/etc` is refused).
        let e = SingularityBackend::new(&SingularityConfig { image: "i.sif".into(), binary: exe.display().to_string(), binds: vec!["/etc:/etc".into()], ..Default::default() }, "singularity", &SandboxConfig::default(), &c).err().unwrap();
        assert!(e.contains("refusing"), "{e}");
        assert!(serde_json::from_value::<SingularityConfig>(json!({"image": "x.sif", "nv": true})).unwrap().no_home);
        assert!(serde_json::from_value::<SingularityConfig>(json!({"typo": 1})).is_err());
    }
}
