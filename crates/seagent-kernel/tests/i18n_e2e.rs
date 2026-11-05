//! End-to-end i18n: the same chain `seagent` runs at startup — a `config.toml` with `[display]
//! language`, `Config::load`, `i18n::set_config_language` — really changes the strings the CLI
//! prints (`approval.*`, `status.*`, `help.category.*` are exactly what `term::approval_prompt`,
//! `/status` and `/help` render). The `SEAGENT_LANGUAGE` override and the `$SEAGENT_HOME/locales` overlay
//! are exercised through the real home resolution too.
//!
//! One test, its own process: `SEAGENT_HOME` / `SEAGENT_LANGUAGE` are process globals.

use seagent_kernel::config::Config;
use seagent_kernel::i18n;
use std::path::PathBuf;

fn tmp(prefix: &str) -> PathBuf {
    let d = seagent_core::tmp::scratch_path(format!("seagent-i18n-e2e-{prefix}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_config_or_env_language_changes_the_strings_the_cli_prints() {
    let home = tmp("home");
    std::env::set_var("SEAGENT_HOME", &home);
    std::env::remove_var("SEAGENT_LANGUAGE");
    i18n::set_thread_language(None);
    i18n::set_config_language("");

    // 1. Default: English, the wording seagent has always printed.
    assert_eq!(i18n::t("status.no_session"), "no session yet");
    assert!(i18n::t_fmt("approval.heading", &[("gate", "privilege"), ("reason", "recursive delete")]).starts_with("⚑ privilege gate"));

    // 2. `display.language` in config.toml (what `seagent --set display.language=…` writes).
    let cfg_path = home.join("config.toml");
    std::fs::write(&cfg_path, "[display]\nlanguage = \"zh-TW\"\n").unwrap();
    let cfg = Config::load(Some(&cfg_path), None, &[]).unwrap();
    i18n::set_config_language(&cfg.display.language); // ← the one call `main::load_config` makes
    assert_eq!(i18n::t("status.no_session"), "尚無工作階段", "the /status heading is translated");
    assert_eq!(i18n::t("help.category.session"), "工作階段", "the /help heading is translated");
    assert!(i18n::t("approval.choices").starts_with("允許？"), "the approval prompt is translated");
    assert_eq!(i18n::active_language(), "zh-hant", "`zh-TW` resolves through the alias table");

    // 3. `SEAGENT_LANGUAGE` wins over the config, and is alias-resolved as well.
    std::env::set_var("SEAGENT_LANGUAGE", "chinese");
    assert_eq!(i18n::t("status.no_session"), "还没有会话");
    std::env::remove_var("SEAGENT_LANGUAGE");

    // 4. The user overlay under the real `$SEAGENT_HOME/locales` beats the bundled catalog, and a
    //    reload picks up an edited file.
    std::fs::create_dir_all(home.join("locales")).unwrap();
    let overlay = home.join("locales").join("zh-hant.json");
    std::fs::write(&overlay, r#"{"status": {"no_session": "本地覆寫"}}"#).unwrap();
    i18n::reset_cache();
    assert_eq!(i18n::t("status.no_session"), "本地覆寫");
    assert_eq!(i18n::t("help.category.session"), "工作階段", "a partial overlay keeps the bundled keys");
    std::fs::write(&overlay, "{}\n").unwrap();
    assert_eq!(i18n::t("status.no_session"), "本地覆寫", "cached until invalidated");
    i18n::reset_cache();
    assert_eq!(i18n::t("status.no_session"), "尚無工作階段");

    // 5. Clearing the key returns to English.
    i18n::set_config_language("");
    assert_eq!(i18n::t("status.no_session"), "no session yet");
}
