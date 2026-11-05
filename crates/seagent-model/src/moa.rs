//! Mixture of agents (Hermes `agent/moa_loop.py`): before each model step the reference
//! models answer the same conversation in parallel (no tools), then the aggregator —
//! which keeps the tools and owns the turn — answers with their drafts as guidance.
//! Configure `[providers.moa] format = "moa"`, `references = ["p/m", …]`, `aggregator = "p/m"`.

use crate::ProviderConfig;
use seagent_core::*;
use std::sync::Arc;

pub type Resolve<'a> = &'a dyn Fn(&str) -> Result<Arc<dyn Provider>, String>;

pub struct Moa {
    id: String,
    refs: Vec<(String, Arc<dyn Provider>, String)>,
    agg: (Arc<dyn Provider>, String),
}

const REFERENCE_SYSTEM: &str = "You are a reference model in a mixture-of-agents ensemble. Another model (the aggregator) holds the tools and will answer the user; give your best analysis and draft answer to the latest request. You cannot run tools: never claim to have executed anything, and do not emit tool-call syntax.";

fn split(m: &str) -> Result<(&str, &str), String> {
    m.split_once('/')
        .ok_or_else(|| format!("mixture-of-agents model `{m}` must be provider/model"))
}

impl Moa {
    pub fn new(cfg: &ProviderConfig, resolve: Resolve) -> Result<Moa, String> {
        if cfg.references.is_empty() {
            return Err(format!(
                "provider `{}`: set `references = [\"provider/model\", …]` for mixture-of-agents",
                cfg.id
            ));
        }
        let agg = cfg.aggregator.clone().ok_or_else(|| {
            format!(
                "provider `{}`: set `aggregator = \"provider/model\"`",
                cfg.id
            )
        })?;
        let mut refs = Vec::new();
        for r in &cfg.references {
            let (p, m) = split(r)?;
            if p == cfg.id {
                return Err(format!(
                    "provider `{}`: a reference cannot be the mixture itself",
                    cfg.id
                ));
            }
            refs.push((r.clone(), resolve(p)?, m.to_string()));
        }
        let (p, m) = split(&agg)?;
        if p == cfg.id {
            return Err(format!(
                "provider `{}`: the aggregator cannot be the mixture itself",
                cfg.id
            ));
        }
        Ok(Moa {
            id: cfg.id.clone(),
            refs,
            agg: (resolve(p)?, m.to_string()),
        })
    }
}

impl Provider for Moa {
    fn id(&self) -> &str {
        &self.id
    }
    fn caps(&self, _model: &str) -> ModelCaps {
        self.agg.0.caps(&self.agg.1)
    }
    fn complete(
        &self,
        req: &ModelRequest,
        on_event: &mut dyn FnMut(StreamEvent),
        cancel: &Cancel,
    ) -> Result<ModelResponse, ProviderError> {
        let mut rreq = req.clone();
        rreq.tools.clear();
        rreq.system.insert(
            0,
            SystemSegment {
                id: "moa-reference".into(),
                text: REFERENCE_SYSTEM.into(),
                cache: false,
            },
        );
        // Tool calls in history become plain text for tool-less reference models.
        for m in &mut rreq.messages {
            m.content = m
                .content
                .drain(..)
                .map(|b| match b {
                    Block::ToolUse { name, input, .. } => {
                        Block::text(format!("[called {name} {input}]"))
                    }
                    Block::ToolResult { content, .. } => {
                        Block::text(format!("[tool result] {content}"))
                    }
                    Block::Thinking { .. } => Block::text(""),
                    o => o,
                })
                .collect();
        }
        let results: Vec<(String, Result<ModelResponse, ProviderError>)> =
            std::thread::scope(|s| {
                let hs: Vec<_> = self
                    .refs
                    .iter()
                    .map(|(label, p, m)| {
                        let mut r = rreq.clone();
                        r.model = m.clone();
                        let c = cancel.clone();
                        let p = p.clone();
                        let label = label.clone();
                        s.spawn(move || (label, p.complete(&r, &mut |_| {}, &c)))
                    })
                    .collect();
                hs.into_iter()
                    .map(|h| {
                        h.join().unwrap_or_else(|_| {
                            (
                                "?".into(),
                                Err(ProviderError::new(
                                    ProviderErrorKind::Server,
                                    "reference panicked",
                                )),
                            )
                        })
                    })
                    .collect()
            });
        if cancel.is_cancelled() {
            return Err(ProviderError::new(
                ProviderErrorKind::Cancelled,
                "cancelled",
            ));
        }
        let mut usage = Usage::default();
        let mut guide = String::new();
        let mut ok = 0;
        for (label, r) in &results {
            match r {
                Ok(resp) => {
                    ok += 1;
                    usage.add(&resp.usage);
                    guide.push_str(&format!(
                        "<reference model=\"{label}\">\n{}\n</reference>\n",
                        resp.message.text()
                    ));
                }
                Err(e) => guide.push_str(&format!(
                    "<reference model=\"{label}\" failed=\"{}\"/>\n",
                    e.message.replace('"', "'")
                )),
            }
        }
        let mut areq = req.clone();
        areq.model = self.agg.1.clone();
        if ok > 0 {
            areq.system.push(SystemSegment { id: "moa-guidance".into(), text: format!("Reference models drafted these answers to the latest request. Use them as guidance — verify, combine the best parts, and correct mistakes; you alone can call tools.\n{guide}"), cache: false });
        }
        let mut r = self.agg.0.complete(&areq, on_event, cancel)?;
        r.usage.add(&usage);
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Echo {
        name: String,
        seen: Mutex<Vec<ModelRequest>>,
    }
    impl Provider for Echo {
        fn id(&self) -> &str {
            &self.name
        }
        fn caps(&self, m: &str) -> ModelCaps {
            crate::caps_for(m)
        }
        fn complete(
            &self,
            req: &ModelRequest,
            _: &mut dyn FnMut(StreamEvent),
            _: &Cancel,
        ) -> Result<ModelResponse, ProviderError> {
            self.seen.lock().unwrap().push(req.clone());
            if self.name == "bad" {
                return Err(ProviderError::new(ProviderErrorKind::Server, "down"));
            }
            Ok(ModelResponse {
                message: Message::assistant(format!("{} says hi", self.name)),
                stop: StopReason::EndTurn,
                usage: Usage {
                    input_tokens: 1,
                    output_tokens: 1,
                    ..Default::default()
                },
                model: req.model.clone(),
            })
        }
    }

    #[test]
    fn references_fan_out_aggregator_answers_with_guidance() {
        let a = Arc::new(Echo {
            name: "a".into(),
            seen: Mutex::default(),
        });
        let b = Arc::new(Echo {
            name: "bad".into(),
            seen: Mutex::default(),
        });
        let g = Arc::new(Echo {
            name: "agg".into(),
            seen: Mutex::default(),
        });
        let (a2, b2, g2) = (a.clone(), b.clone(), g.clone());
        let resolve = move |p: &str| -> Result<Arc<dyn Provider>, String> {
            Ok(match p {
                "pa" => a2.clone(),
                "pb" => b2.clone(),
                _ => g2.clone(),
            })
        };
        let cfg = ProviderConfig {
            id: "moa".into(),
            format: crate::WireFormat::Moa,
            references: vec!["pa/m1".into(), "pb/m2".into()],
            aggregator: Some("pg/big".into()),
            ..Default::default()
        };
        let m = Moa::new(&cfg, &resolve).unwrap();
        let req = ModelRequest {
            model: "x".into(),
            messages: vec![Message::user("q")],
            tools: vec![ToolSchema {
                name: "read".into(),
                description: "".into(),
                input_schema: serde_json::json!({}),
            }],
            max_tokens: 10,
            ..Default::default()
        };
        let r = m.complete(&req, &mut |_| {}, &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "agg says hi");
        assert_eq!(r.usage.input_tokens, 2, "reference usage is accounted");
        assert!(a.seen.lock().unwrap()[0].tools.is_empty());
        let agg_req = &g.seen.lock().unwrap()[0];
        assert_eq!(agg_req.model, "big");
        assert_eq!(agg_req.tools.len(), 1);
        let guide = &agg_req.system.last().unwrap().text;
        assert!(guide.contains("a says hi") && guide.contains("failed=\"down\""));
        let bad = ProviderConfig {
            references: vec!["moa/x".into()],
            ..cfg.clone()
        };
        assert!(Moa::new(&bad, &resolve).is_err());
        assert!(Moa::new(
            &ProviderConfig {
                references: vec![],
                ..cfg
            },
            &resolve
        )
        .is_err());
    }
}
