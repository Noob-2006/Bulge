//! Managed local inference (Hermes `hermes_cli/local_runtime/supervisor.py`, OpenClaw
//! `extensions/llama-cpp`): a provider with `model_path` gets its own llama.cpp server,
//! started on first use on a free loopback port, health-checked (`/health`), restarted
//! if it died, and stopped with ark.

use crate::auth::{Cred, CredSource};
use crate::ProviderConfig;
use ark_core::{ProviderError, ProviderErrorKind as K};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Managed {
    id: String,
    command: String,
    args: Vec<String>,
    inner: Arc<dyn CredSource>,
    startup: Duration,
    state: Mutex<Option<(Child, u16)>>,
}

impl Managed {
    pub fn new(cfg: &ProviderConfig, inner: Arc<dyn CredSource>) -> Result<Managed, String> {
        let path = cfg.model_path.clone().unwrap_or_default();
        let p = std::path::Path::new(&path);
        if !p.exists() {
            return Err(format!(
                "provider `{}`: model_path {path} does not exist",
                cfg.id
            ));
        }
        let mut args = vec![
            "--host".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            "{port}".to_string(),
        ];
        if p.is_dir() {
            // Router mode: every GGUF in the directory, loaded on demand.
            args.extend([
                "--models-dir".into(),
                path.clone(),
                "--models-autoload".into(),
            ]);
        } else {
            args.extend(["-m".into(), path.clone()]);
        }
        args.extend(cfg.args.iter().cloned());
        Ok(Managed {
            id: cfg.id.clone(),
            command: cfg.command.clone().unwrap_or_else(|| "llama-server".into()),
            args,
            inner,
            startup: Duration::from_secs(cfg.idle_timeout_secs.unwrap_or(180).max(5)),
            state: Mutex::new(None),
        })
    }

    fn healthy(port: u16) -> bool {
        let url = format!("http://127.0.0.1:{port}/health");
        let a: ureq::Agent = ark_net::http::builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(3)))
            .proxy(None)
            .build()
            .into();
        a.get(&url).call().is_ok_and(|r| r.status().as_u16() == 200)
    }

    /// Port of a running, healthy server (starting one if needed).
    pub fn ensure(&self) -> Result<u16, String> {
        let mut st = self.state.lock().unwrap();
        if let Some((c, port)) = st.as_mut() {
            if c.try_wait().ok().flatten().is_none() {
                return Ok(*port);
            }
            eprintln!("ark: {}: local server exited; restarting", self.id);
        }
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .map_err(|e| e.to_string())?;
        let args: Vec<String> = self
            .args
            .iter()
            .map(|a| a.replace("{port}", &port.to_string()))
            .collect();
        let mut child = Command::new(&self.command)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                format!(
                    "cannot start `{}`: {e} (install llama.cpp or set `command`)",
                    self.command
                )
            })?;
        let start = Instant::now();
        loop {
            if let Ok(Some(s)) = child.try_wait() {
                return Err(format!("`{}` exited during startup ({s})", self.command));
            }
            if Self::healthy(port) {
                break;
            }
            if start.elapsed() > self.startup {
                let _ = child.kill();
                return Err(format!(
                    "`{}` not healthy after {}s",
                    self.command,
                    self.startup.as_secs()
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        *st = Some((child, port));
        Ok(port)
    }
}

impl CredSource for Managed {
    fn get(&self) -> Result<Cred, ProviderError> {
        let port = self
            .ensure()
            .map_err(|e| ProviderError::new(K::Network, format!("{}: {e}", self.id)))?;
        let mut c = self.inner.get()?;
        c.base = Some(format!("http://127.0.0.1:{port}/v1"));
        Ok(c)
    }
    fn invalidate(&self) -> bool {
        self.inner.invalidate()
    }
    fn describe(&self) -> String {
        format!("managed `{}`", self.command)
    }
}

impl Drop for Managed {
    fn drop(&mut self) {
        if let Some((mut c, _)) = self.state.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_health_checks_and_restarts() {
        let d = ark_core::tmp::scratch_path(format!("ark-llama-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let model = d.join("m.gguf");
        std::fs::write(&model, b"GGUF").unwrap();
        let fake = d.join("fake_server.py");
        std::fs::write(&fake, "import sys, http.server\nport=int(sys.argv[sys.argv.index('--port')+1])\nclass H(http.server.BaseHTTPRequestHandler):\n    def log_message(self,*a): pass\n    def do_GET(self):\n        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')\nhttp.server.HTTPServer(('127.0.0.1',port),H).serve_forever()\n").unwrap();
        let cfg = ProviderConfig {
            id: "llama-local".into(),
            model_path: Some(model.to_string_lossy().into()),
            command: Some("python3".into()),
            args: vec![],
            ..Default::default()
        };
        let mut m = Managed::new(&cfg, Arc::new(crate::auth::Static::new(None))).unwrap();
        m.args.insert(0, fake.to_string_lossy().into());
        m.args.insert(0, "-I".into());
        let c = m.get().unwrap();
        let base = c.base.unwrap();
        assert!(base.starts_with("http://127.0.0.1:") && base.ends_with("/v1"));
        let p1 = m.ensure().unwrap();
        assert_eq!(base, format!("http://127.0.0.1:{p1}/v1"), "reused");
        m.state.lock().unwrap().as_mut().unwrap().0.kill().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(m.ensure().is_ok(), "restarted after exit");
        let bad = ProviderConfig {
            model_path: Some("/nonexistent.gguf".into()),
            ..cfg
        };
        assert!(Managed::new(&bad, Arc::new(crate::auth::Static::new(None))).is_err());
    }
}
