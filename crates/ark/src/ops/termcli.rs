//! Terminal look-and-feel commands (Hermes `hermes skin`, `hermes pets`, `/skin`, `/pet`,
//! `/hatch`, `/battery`, `/indicator`): CLI subcommands and the slash rows merged into
//! `slash::defs()` through `ops::SLASH`. State lives in `<config>/ui.json` and
//! `<data>/pets`; the logic is in `ark_app::tui::{skin, pets, battery, indicator, tips}`.

use crate::args::Args;
use crate::slash::{Action, Ctx, Def, Reply};
use crate::R;
use ark_app::tui::{battery, indicator, pets, prefs, skin};
use ark_kernel::config::Paths;
use serde_json::json;
use std::io::Write;

pub const COMMANDS: &[&str] = &["skin", "pets"];
pub const VALUE_FLAGS: &[&str] = &["skin", "state", "render-mode", "scale", "style"];
pub const BOOL_FLAGS: &[&str] = &["installed", "select", "cycle", "once"];

fn text(t: impl Into<String>) -> Result<Reply, String> {
    Ok(Reply { text: Some(t.into()), ..Default::default() })
}

fn local(name: &str, arg: &str, t: String) -> Result<Reply, String> {
    Ok(Reply { text: Some(t), prompt: None, action: Some(Action::Local(name.into(), arg.into())) })
}

pub const SLASH: &[Def] = &[
    Def { name: "skin", aliases: &[], args: "[name]", help: "Show or change the display skin/theme", category: "Display", admin: false, local: true, run: slash_skin },
    Def { name: "battery", aliases: &[], args: "[on|off|status]", help: "Toggle a colour-coded battery indicator in the status bar", category: "Display", admin: false, local: true, run: slash_battery },
    Def { name: "indicator", aliases: &[], args: "[ascii|emoji|kaomoji|unicode]", help: "Pick the TUI busy-indicator style", category: "Display", admin: false, local: true, run: slash_indicator },
    Def { name: "tips", aliases: &[], args: "[on|off]", help: "Show a random tip, or switch startup tips on/off", category: "Display", admin: false, local: true, run: slash_tips },
    Def { name: "bell", aliases: &[], args: "[on|off] | prompt [on|off]", help: "Desktop notification (BEL + OSC 9/777) when a turn ends or the agent needs you", category: "Display", admin: false, local: true, run: slash_bell },
    Def { name: "pet", aliases: &[], args: "[toggle|list|scale <n>|off|<slug>]", help: "Toggle or adopt a petdex mascot", category: "Tools", admin: false, local: true, run: slash_pet },
    Def { name: "hatch", aliases: &["generate-pet"], args: "<description>", help: "Generate a new petdex pet from a description", category: "Tools", admin: false, local: true, run: slash_hatch },
];

fn paths_of<'a>(c: &Ctx<'a>) -> &'a Paths {
    &c.k.paths
}

fn slash_skin(c: &Ctx, a: &str) -> Result<Reply, String> {
    let p = paths_of(c);
    let name = a.trim().to_lowercase();
    if name.is_empty() {
        return text(skin::listing(p));
    }
    let s = skin::set_active(p, &name)?;
    local("skin", &s.name, format!("skin → {} (saved; the TUI repaints now, `ark chat` on next start)", s.name))
}

fn slash_battery(c: &Ctx, a: &str) -> Result<Reply, String> {
    let p = paths_of(c);
    let cur = prefs::get_bool(&prefs::load(p), "battery", false);
    let reading = battery::read(false);
    let detail = if reading.available { format!(" — {}", battery::format(&reading)) } else { " — no battery detected".into() };
    let arg = a.trim().to_lowercase();
    if arg == "status" || arg == "show" {
        return text(format!("battery indicator: {}{detail}", if cur { "on" } else { "off" }));
    }
    let on = prefs::parse_toggle(&arg, cur).ok_or("usage: /battery [on|off|status]")?;
    prefs::set(p, "battery", json!(on))?;
    local("battery", if on { "on" } else { "off" }, if on { format!("battery indicator on{}", if reading.available { detail } else { " — no battery detected, nothing will be shown".into() }) } else { "battery indicator off".into() })
}

fn slash_indicator(c: &Ctx, a: &str) -> Result<Reply, String> {
    let p = paths_of(c);
    if a.trim().is_empty() {
        return text(format!("busy indicator: {} (options: {})", prefs::get_str(&prefs::load(p), "indicator", indicator::DEFAULT), indicator::STYLES.join("|")));
    }
    let s = indicator::normalize(a).ok_or_else(|| format!("usage: /indicator [{}]", indicator::STYLES.join("|")))?;
    prefs::set(p, "indicator", json!(s))?;
    local("indicator", s, format!("busy indicator → {s}"))
}

fn slash_tips(c: &Ctx, a: &str) -> Result<Reply, String> {
    let p = paths_of(c);
    if a.trim().is_empty() {
        return text(format!("✦ tip: {}", ark_app::tui::tips::random_tip()));
    }
    let on = prefs::parse_toggle(a, true).ok_or("usage: /tips [on|off]")?;
    prefs::set(p, "tips", json!(on))?;
    text(format!("startup tips {}", if on { "on" } else { "off" }))
}

fn slash_bell(c: &Ctx, a: &str) -> Result<Reply, String> {
    let p = paths_of(c);
    let v = prefs::load(p);
    let mut w = a.split_whitespace();
    let (key, arg) = match w.next() {
        Some("prompt") => ("bell_on_prompt", w.next().unwrap_or("")),
        Some(x) => ("bell_on_complete", x),
        None => {
            return text(format!("bell on turn end: {} · on prompts (approvals/questions): {}", if prefs::get_bool(&v, "bell_on_complete", false) { "on" } else { "off" }, if prefs::get_bool(&v, "bell_on_prompt", false) { "on" } else { "off" }));
        }
    };
    let on = prefs::parse_toggle(arg, prefs::get_bool(&v, key, false)).ok_or("usage: /bell [on|off] | /bell prompt [on|off]")?;
    prefs::set(p, key, json!(on))?;
    text(format!("{} → {}", if key == "bell_on_prompt" { "bell on prompts" } else { "bell on turn end" }, if on { "on" } else { "off" }))
}

/// Install (if needed) and adopt a pet.
pub fn adopt(paths: &Paths, dex: &pets::Petdex, slug: &str) -> Result<String, String> {
    let pet = match pets::load(paths, slug).filter(|p| p.exists()) {
        Some(p) => p,
        None => pets::install(paths, dex, slug, false)?,
    };
    pets::set_active(paths, &pet.slug)?;
    let note = if pet.png_sheet().is_none() { " (WebP sheet: install dwebp/ImageMagick/ffmpeg to see it in the terminal)" } else { "" };
    Ok(format!("(^o^)/ {} is now your pet{note}", pet.display_name))
}

fn slash_pet(c: &Ctx, a: &str) -> Result<Reply, String> {
    let p = paths_of(c);
    let dex = pets::Petdex::default();
    let mut w = a.split_whitespace();
    match w.next().unwrap_or("toggle") {
        "toggle" => {
            let (on, name, err) = pets::toggle(p);
            if let Some(e) = err {
                return text(e);
            }
            local("pet", if on { "on" } else { "off" }, format!("pet {} {}", name.unwrap_or_default(), if on { "on" } else { "off" }))
        }
        "off" => {
            pets::set_enabled(p, false)?;
            local("pet", "off", "pet display off".into())
        }
        "list" => text(match pets::gallery_text(p, &dex, w.next().unwrap_or(""), 20) {
            Ok(t) => t,
            Err(e) => format!("(._.) couldn't reach the petdex gallery: {e}"),
        }),
        "scale" => {
            let s = pets::set_scale(p, w.next().ok_or("usage: /pet scale <0.1–3.0>")?)?;
            local("pet", "scale", format!("pet scale → {s}"))
        }
        slug => {
            let t = adopt(p, &dex, slug)?;
            local("pet", "on", t)
        }
    }
}

fn slash_hatch(c: &Ctx, a: &str) -> Result<Reply, String> {
    let concept = a.trim().to_string();
    if concept.is_empty() {
        return text("usage: /hatch <description>, e.g. /hatch a sleepy space otter");
    }
    let gen = crate::ops::hatchgen::from_kernel(c.k)?;
    let paths = c.k.paths.clone();
    match c.notify.clone() {
        // Long (~a minute of image calls): run in the background and report through notify.
        Some(n) => {
            let note = format!("🥚 hatching “{concept}” — this takes about a minute…");
            std::thread::spawn(move || {
                let n2 = n.clone();
                let r = pets::hatch(&paths, gen.as_ref(), &concept, "auto", &move |m| n2(format!("  🥚 {m}")));
                n(match r {
                    Ok(h) => format!("🐣 {} hatched ({} animations) and is now your pet", h.pet.display_name, h.states.len()),
                    Err(e) => format!("✗ hatch failed: {e}"),
                });
            });
            text(note)
        }
        None => {
            let h = pets::hatch(&paths, gen.as_ref(), &concept, "auto", &|m| eprintln!("  🥚 {m}"))?;
            local("pet", "on", format!("🐣 {} hatched ({} animations) and is now your pet", h.pet.display_name, h.states.len()))
        }
    }
}

/// `ark chat` start: the random startup tip (unless `/tips off`).
pub fn chat_started(paths: &Paths) {
    if let Some(t) = ark_app::tui::tips::startup_line(&prefs::load(paths)) {
        eprintln!("{t}");
    }
}

/// `ark chat` turn end: BEL + OSC 9 / Warp OSC 777 when `/bell on`.
pub fn chat_turn_done(k: &ark_kernel::kernel::Kernel, session: &str) {
    if prefs::get_bool(&prefs::load(&k.paths), "bell_on_complete", false) {
        let cwd = std::env::current_dir().map(|d| d.display().to_string()).unwrap_or_default();
        ark_app::tui::notify::write_tty(&ark_app::tui::notify::sequence(&ark_app::tui::notify::env_map(), "turn complete", false, session, "", &cwd));
    }
}

// ───────────── CLI ─────────────

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    let paths = Paths::from_env();
    Some(match cmd {
        "skin" => cli_skin(&paths, a),
        _ => cli_pets(&paths, &pets::Petdex::default(), a),
    })
}

pub fn cli_skin(paths: &Paths, a: &Args) -> R {
    match a.pos(0).unwrap_or("list") {
        "list" => {
            let cur = skin::active_name(paths);
            for (n, d, src) in skin::list(paths) {
                println!("{} {n:<16} {src:<8} {d}", if n == cur { "*" } else { " " });
            }
        }
        "use" => {
            let s = skin::set_active(paths, a.need(1, "name")?)?;
            println!("✓ active skin → {} (live in `ark tui` within ~2s)", s.name);
        }
        "set" => {
            let (t, file) = skin::set_color(paths, a.need(1, "key")?, a.need(2, "#rrggbb")?, a.val("skin"))?;
            println!("✓ {} = {} in {} (active skin: {t})", a.need(1, "key")?, a.need(2, "value")?, file.display());
        }
        other => return Err(format!("unknown `ark skin {other}` (list | use <name> | set <key> <#rrggbb> [--skin NAME])").into()),
    }
    Ok(0)
}

pub fn cli_pets(paths: &Paths, dex: &pets::Petdex, a: &Args) -> R {
    match a.pos(0).unwrap_or("help") {
        "list" => {
            if a.flag("installed") {
                let ps = pets::installed(paths);
                if ps.is_empty() {
                    println!("No pets installed. Try: ark pets install boba");
                }
                for p in ps {
                    println!("  {:<24} {}", p.slug, p.display_name);
                }
                return Ok(0);
            }
            let limit = a.num::<usize>("limit")?.unwrap_or(40);
            println!("{}", pets::gallery_text(paths, dex, a.pos(1).unwrap_or(""), limit)?);
        }
        "install" => {
            let slug = a.need(1, "slug")?;
            let p = pets::install(paths, dex, slug, a.flag("force")).map_err(|e| format!("install failed: {e}"))?;
            println!("✓ installed {} → {}", p.display_name, p.dir.display());
            let active = pets::enabled(&pets::config(paths)) && pets::config(paths)["slug"].as_str().is_some_and(|s| !s.is_empty());
            if a.flag("select") || !active {
                pets::set_active(paths, &p.slug)?;
                println!("✓ {} is now the active pet (pet.slug={}, enabled)", p.display_name, p.slug);
            } else {
                println!("  Make it active with: ark pets select {}", p.slug);
            }
        }
        "select" => {
            let slug = match a.pos(1) {
                Some(s) => s.to_string(),
                None => pick(paths)?,
            };
            let p = pets::load(paths, &slug).filter(|p| p.exists()).ok_or_else(|| format!("'{slug}' is not installed — run: ark pets install {slug}"))?;
            pets::set_active(paths, &p.slug)?;
            println!("✓ active pet set to {} (pet.slug={}, enabled)", p.display_name, p.slug);
        }
        "off" => {
            pets::set_enabled(paths, false)?;
            println!("✓ pet disabled (pet.enabled=false)");
        }
        "scale" => println!("✓ pet scale set to {} (pet.scale)", pets::set_scale(paths, a.need(1, "factor")?)?),
        "remove" => {
            let slug = a.need(1, "slug")?;
            if !pets::remove(paths, slug) {
                return Err(format!("'{slug}' is not installed").into());
            }
            pets::clear_active_if(paths, slug);
            println!("✓ removed {slug}");
        }
        "doctor" => println!("{}", pets::doctor(paths)),
        "show" => return show(paths, a),
        "hatch" => {
            let concept = a.rest(1);
            let gen = crate::ops::hatchgen::from_paths(paths)?;
            let h = pets::hatch(paths, gen.as_ref(), &concept, a.val("style").unwrap_or("auto"), &|m| eprintln!("  🥚 {m}"))?;
            println!("🐣 {} hatched ({}) → {}", h.pet.display_name, h.states.join(", "), h.pet.dir.display());
        }
        _ => {
            println!("ark pets — petdex animated pets (https://petdex.dev)\n  list [query] [--installed] [--limit N]\n  install <slug> [--force] [--select]\n  select [slug]\n  show [slug] [--state idle|run|review|failed|wave|jump|waiting] [--cycle] [--once] [--render-mode kitty|iterm|unicode|auto] [--scale X]\n  off · scale <factor> · remove <slug> · doctor\n  hatch <description>   generate a new pet with your image provider");
        }
    }
    Ok(0)
}

fn pick(paths: &Paths) -> Result<String, String> {
    let ps = pets::installed(paths);
    if ps.is_empty() {
        return Err("no pets installed — run: ark pets install boba".into());
    }
    eprintln!("Installed pets:");
    for (i, p) in ps.iter().enumerate() {
        eprintln!("  {}. {:<24} {}", i + 1, p.slug, p.display_name);
    }
    eprint!("Select a pet [1]: ");
    let _ = std::io::stderr().flush();
    let mut l = String::new();
    std::io::stdin().read_line(&mut l).map_err(|e| e.to_string())?;
    let i = l.trim().parse::<usize>().unwrap_or(1).saturating_sub(1);
    ps.get(i).map(|p| p.slug.clone()).ok_or_else(|| "invalid selection".into())
}

fn show(paths: &Paths, a: &Args) -> R {
    let cfg = pets::config(paths);
    let slug = a.pos(1).map(str::to_string).unwrap_or_else(|| cfg["slug"].as_str().unwrap_or("").to_string());
    let pet = pets::resolve_active(paths, &slug).ok_or("no pet to show — run: ark pets install boba")?;
    let sheet_path = pet.png_sheet().ok_or("this pet's WebP sheet needs dwebp, ImageMagick, ffmpeg or vips to render")?;
    let sheet = pets::Sheet::load(&sheet_path)?;
    let env = ark_app::tui::notify::env_map();
    let mode = pets::resolve_mode(a.val("render-mode").or(cfg["render_mode"].as_str()).unwrap_or("auto"), &env);
    let scale = a.num::<f64>("scale")?.filter(|s| *s > 0.0).or(cfg["scale"].as_f64()).unwrap_or(pets::DEFAULT_SCALE);
    let cols = pets::resolve_cols(scale, cfg["unicode_cols"].as_u64().unwrap_or(0) as usize);
    let states: Vec<String> = match a.val("state") {
        Some(s) => vec![s.to_lowercase()],
        None if a.flag("cycle") => pets::STATES.iter().map(|s| s.to_string()).collect(),
        None => vec!["idle".into()],
    };
    let mut out = std::io::stdout();
    println!("{} — mode={mode}  (Ctrl+C to stop)", pet.display_name);
    let _ = write!(out, "\x1b[?25l");
    let mut prev = 0usize;
    let mut loops = 0;
    loop {
        for st in &states {
            let n = sheet.frame_count(st);
            let delay = std::time::Duration::from_millis((pets::LOOP_MS / n.max(1) as u64).max(50));
            for i in 0..n {
                let f = sheet.frame(st, i);
                if mode == "unicode" {
                    let lines = pets::render_unicode(&f, cols);
                    if prev > 0 {
                        let _ = write!(out, "\x1b[{prev}F");
                    }
                    let _ = writeln!(out, "{}\x1b[0m", lines.join("\n"));
                    prev = lines.len();
                } else {
                    let _ = write!(out, "\x1b[2J\x1b[3J\x1b[H{} [{st}]\n{}\n", pet.display_name, if mode == "kitty" { pets::render_kitty(&f, cols) } else { pets::render_iterm(&f, cols) });
                }
                let _ = out.flush();
                std::thread::sleep(delay);
            }
        }
        loops += 1;
        if a.flag("once") && loops >= 1 {
            break;
        }
    }
    let _ = writeln!(out, "\x1b[?25h\x1b[0m");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slash;

    #[test]
    fn skin_battery_indicator_bell_tips_slashes() {
        let kit = crate::testkit::kit();
        let c = slash::Ctx { k: &kit.k, ext: None, session: None, workspace: kit.ws.clone(), surface: slash::Surface::Tui, sender: None, notify: None };
        assert!(slash::run(&c, "/skin").unwrap().text.unwrap().contains("current skin: default"));
        let r = slash::run(&c, "/skin poseidon").unwrap();
        assert_eq!(r.action, Some(Action::Local("skin".into(), "poseidon".into())));
        assert_eq!(skin::active_name(&kit.paths), "poseidon");
        assert!(slash::run(&c, "/skin nope").unwrap().text.unwrap().contains("unknown skin"));
        slash::run(&c, "/battery on").unwrap();
        assert!(prefs::get_bool(&prefs::load(&kit.paths), "battery", false));
        assert!(slash::run(&c, "/battery status").unwrap().text.unwrap().starts_with("battery indicator: on"));
        slash::run(&c, "/battery").unwrap();
        assert!(!prefs::get_bool(&prefs::load(&kit.paths), "battery", true));
        assert_eq!(slash::run(&c, "/indicator emoji").unwrap().action, Some(Action::Local("indicator".into(), "emoji".into())));
        assert!(slash::run(&c, "/indicator").unwrap().text.unwrap().contains("busy indicator: emoji"));
        assert!(slash::run(&c, "/indicator wild").unwrap().text.unwrap().contains("usage"));
        slash::run(&c, "/bell on").unwrap();
        slash::run(&c, "/bell prompt on").unwrap();
        let v = prefs::load(&kit.paths);
        assert!(prefs::get_bool(&v, "bell_on_complete", false) && prefs::get_bool(&v, "bell_on_prompt", false));
        assert!(slash::run(&c, "/tips").unwrap().text.unwrap().starts_with("✦ tip:"));
        slash::run(&c, "/tips off").unwrap();
        assert!(!prefs::get_bool(&prefs::load(&kit.paths), "tips", true));
        // Display commands are terminal-local: refused in channel chats.
        let ch = slash::Ctx { surface: slash::Surface::Channel, sender: Some(slash::Sender::default()), ..c };
        assert!(slash::run(&ch, "/skin ares").unwrap().text.unwrap().contains("works in the terminal"));
        assert_eq!(skin::active_name(&kit.paths), "poseidon");
    }

    #[test]
    fn pet_slash_and_cli_against_a_fake_gallery() {
        let kit = crate::testkit::kit();
        let p = kit.paths.clone();
        let (base, _h) = ark_app::tui::pets::tests_support::fake_petdex(&["boba", "mochi"]);
        let dex = pets::Petdex { manifest_url: format!("{base}/api/manifest"), host: "127.0.0.1".into(), timeout: std::time::Duration::from_secs(5) };
        let c = slash::Ctx { k: &kit.k, ext: None, session: None, workspace: kit.ws.clone(), surface: slash::Surface::Tui, sender: None, notify: None };
        assert!(slash::run(&c, "/pet").unwrap().text.unwrap().contains("no pets installed"));
        assert!(adopt(&p, &dex, "boba").unwrap().contains("is now your pet"));
        assert_eq!(pets::config(&p)["slug"], "boba");
        assert_eq!(slash::run(&c, "/pet off").unwrap().action, Some(Action::Local("pet".into(), "off".into())));
        assert!(!pets::enabled(&pets::config(&p)));
        assert!(slash::run(&c, "/pet").unwrap().text.unwrap().contains("on"));
        assert!(slash::run(&c, "/pet scale 0.5").unwrap().text.unwrap().contains("0.5"));
        let args = |v: &[&str]| Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        assert_eq!(cli_pets(&p, &dex, &args(&["list", "--installed"])).ok(), Some(0));
        assert_eq!(cli_pets(&p, &dex, &args(&["show", "--once", "--render-mode", "unicode", "--state", "wave"])).ok(), Some(0));
        // The rest of the documented subcommands are wired to the store.
        assert_eq!(cli_pets(&p, &dex, &args(&["select", "boba"])).ok(), Some(0));
        assert_eq!(pets::config(&p)["slug"], "boba");
        assert!(cli_pets(&p, &dex, &args(&["select", "nope"])).is_err());
        assert_eq!(cli_pets(&p, &dex, &args(&["scale", "0.5"])).ok(), Some(0));
        assert_eq!(pets::config(&p)["scale"], json!(0.5));
        assert_eq!(cli_pets(&p, &dex, &args(&["doctor"])).ok(), Some(0));
        assert!(pets::doctor(&p).contains("active (resolved):   boba"));
        assert_eq!(cli_pets(&p, &dex, &args(&["install", "mochi", "--select"])).ok(), Some(0));
        assert_eq!(pets::config(&p)["slug"], "mochi");
        assert_eq!(cli_pets(&p, &dex, &args(&["remove", "boba"])).ok(), Some(0));
        assert!(cli_pets(&p, &dex, &args(&["remove", "boba"])).is_err());
        // `ark skin list` / `use` / `set` (forking the active skin).
        assert_eq!(cli_skin(&p, &args(&["list"])).ok(), Some(0));
        assert!(cli_skin(&p, &args(&["use", "nope"])).is_err());
        assert_eq!(cli_skin(&p, &args(&["use", "poseidon"])).ok(), Some(0));
        assert_eq!(skin::active_name(&p), "poseidon");
        assert_eq!(cli_skin(&p, &args(&["set", "ui_accent", "#00ff00"])).ok(), Some(0));
        assert_eq!(skin::active_name(&p), "poseidon-custom");
        assert_eq!(skin::load(&p, "poseidon-custom").color("ui_accent"), Some((0x00, 0xff, 0x00)));
        assert!(cli_skin(&p, &args(&["bogus"])).is_err());
        assert!(slash::run(&c, "/hatch").unwrap().text.unwrap().starts_with("usage"));
    }
}
