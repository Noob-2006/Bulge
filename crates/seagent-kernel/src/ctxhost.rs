//! Context features the host attaches to a kernel: native slash commands (`/context`, `/compact`
//! and its `/compress` alias, `/title`, `/btw`, `/personality`, `/role`) and the frozen system segments
//! that carry the persona (`SOUL.md` + personality), the coding posture and the local toolchain
//! probe, plus the background title generator. Called from `crates/seagent/src/wire.rs`.
//!
//! Everything here goes through `Kernel::run_slash`, so a channel chat, `seagent run`, the TUI and
//! the web UI answer the same way. Behaviour ports Hermes (`hermes_cli/commands.py`,
//! `agent/{title_generator,side_question,coding_context}.py`, `tools/env_probe.py`,
//! `hermes_cli/partial_compress.py`, SOUL.md seeding in `hermes_cli/config.py`) and matches the
//! `seagent` crate's own CLI commands where they already exist.

mod persona;
mod posture;
pub mod role;
mod slash;
mod title;

// The pieces a host needs to drive (or replace) the seams: a custom title generator, the persona
// selection, and reading the generated titles back. Re-exported so `seagent` can name them.
pub use persona::Persona;
pub use title::{Titles, Titler};

use crate::kernel::Kernel;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

/// Seams a host (or a test) may replace. The defaults do the real thing.
#[derive(Clone, Default)]
pub struct Options {
    /// Title generator: the titling input → the model's raw reply. `None` samples
    /// `[model.tasks] title_generation` (else the aux model) through `Kernel::sample`.
    pub titler: Option<Titler>,
    /// Directories searched for the toolchain probe instead of `$PATH`.
    pub probe_path: Option<PathBuf>,
    /// Do not warm the toolchain probe in the background at attach time.
    pub lazy_probe: bool,
}

/// Shared state for the context features: the kernel handle (weak — the kernel owns this object),
/// the persona selection and the title/toolchain caches.
pub struct Host {
    kernel: Weak<crate::kernel::Runtime>,
    persona: Persona,
    /// `/role` choice for this process (crate::roles).
    role: role::RoleChoice,
    titles: Arc<Titles>,
    probe: posture::Probe,
}

impl Host {
    pub fn kernel(&self) -> Option<Kernel> {
        self.kernel.upgrade()
    }
    fn kernel_weak(&self) -> Weak<crate::kernel::Runtime> {
        self.kernel.clone()
    }
    /// The config turns started now would use (`/debug set` overrides included).
    pub fn cfg(&self) -> Option<crate::config::Config> {
        self.kernel().map(|k| k.cfg_now())
    }
    pub fn titles(&self) -> &Titles {
        &self.titles
    }
    pub fn persona(&self) -> &Persona {
        &self.persona
    }
    /// Per-turn hook body for the auto-title lifecycle (`Lifecycle::turn_end` delegates here so
    /// tests can drive it without the kernel's turn runner).
    pub fn on_turn_end(&self, session: &str, user: &str, assistant: &str, ok: bool) {
        title::after_turn(self, session, user, assistant, ok);
    }
}

/// What `attach` registered, so a host (or a test) can drive the seams and read the state back.
pub struct Attached {
    pub host: Arc<Host>,
}

impl Attached {
    pub fn titles(&self) -> &Titles {
        self.host.titles()
    }
    pub fn persona(&self) -> &Persona {
        self.host.persona()
    }
    pub fn on_turn_end(&self, session: &str, user: &str, assistant: &str, ok: bool) {
        self.host.on_turn_end(session, user, assistant, ok);
    }
    /// The frozen system segment with `id` for a live session, if it has one.
    pub fn segment(&self, k: &Kernel, session: &str, id: &str) -> Option<seagent_core::SystemSegment> {
        let events = k.store.read(session).ok()?;
        crate::projection::project(&events).system.into_iter().find(|s| s.id == id)
    }
}

pub fn attach(k: &Kernel, ws: &Path) -> Arc<Attached> {
    attach_with(k, ws, Options::default())
}

/// Register the context slash commands and lifecycle observers. `ws` is the workspace the host
/// started in; the toolchain probe is warmed for it at attach time (it takes ~50 ms).
pub fn attach_with(k: &Kernel, ws: &Path, o: Options) -> Arc<Attached> {
    let host = Arc::new(Host {
        kernel: Arc::downgrade(k),
        persona: Persona::new(),
        role: role::RoleChoice::default(),
        titles: Arc::new(title::Titles::new(Arc::downgrade(k), o.titler)),
        probe: posture::Probe::new(o.probe_path),
    });
    k.add_slash(Arc::new(slash::CtxSlash(host.clone())));
    // Persona, coding posture, environment; the same id in a later build replaces the segment.
    k.add_lifecycle(Arc::new(persona::SoulSegment(host.clone())));
    k.add_lifecycle(Arc::new(persona::ToneSegment(host.clone())));
    k.add_lifecycle(Arc::new(posture::PostureSegment(host.clone())));
    k.add_lifecycle(Arc::new(posture::EnvSegment(host.clone())));
    k.add_lifecycle(Arc::new(title::AutoTitle(host.clone())));
    // Occupation: the `/role` choice for new sessions, and the role's run-time checks
    // (default permissions, reserved acts of regulated professions).
    k.add_lifecycle(Arc::new(role::RoleSegment(host.clone())));
    k.add_hooks(vec![Arc::new(crate::roles::hook::RoleHook::new(Arc::downgrade(k)))]);
    if !o.lazy_probe {
        host.probe.warm(ws);
    }
    Arc::new(Attached { host })
}

/// `<workspace>` for a session, or the current directory (then the data dir) when there is none.
pub(crate) fn workspace_of(k: &Kernel, session: Option<&str>) -> PathBuf {
    session
        .and_then(|s| k.store.read(s).ok())
        .map(|e| crate::projection::project(&e).workspace)
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .or_else(|| std::env::current_dir().ok().filter(|p| p.is_dir()))
        .unwrap_or_else(|| k.paths.data.clone())
}

#[cfg(test)]
#[cfg(unix)] // fake toolchains are `#!/bin/sh` scripts with the executable bit
mod tests;
