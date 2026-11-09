use super::boundary::{boundaries, detect};
use super::hook::{check_tool, scan_targets_of, target_allowed, Checks};
use super::*;
use serde_json::json;

fn cat() -> Arc<Catalog> {
    Catalog::for_config(&Config::default())
}

fn acts(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn roles_tree_loads_every_pack_with_string_isco() {
    let c = cat();
    assert!(c.errors.is_empty(), "{:?}", c.errors);
    assert_eq!(c.by_layer(Layer::L0).count(), 1);
    assert_eq!(c.by_layer(Layer::L1).count(), 10);
    assert!(c.by_layer(Layer::L2).count() >= 537, "{}", c.by_layer(Layer::L2).count());
    for p in c.packs.values() {
        match p.layer {
            Layer::L0 => assert_eq!(p.isco, "all"),
            Layer::L1 => assert!(p.isco.len() == 1 && p.isco.chars().all(|c| c.is_ascii_digit()), "{}", p.slug),
            Layer::L2 => assert!(p.isco.len() == 4 && p.isco.chars().all(|c| c.is_ascii_digit()), "{} {}", p.slug, p.isco),
        }
        if p.layer != Layer::L0 {
            let chain = c.chain(&p.slug).unwrap();
            assert_eq!(chain[0].slug, CORE_SLUG, "{} reaches L0", p.slug);
            if p.layer == Layer::L2 {
                assert_eq!(chain[1].isco, p.isco[..1], "{}: L1 parent matches the major group", p.slug);
            }
        }
        if p.regulated {
            assert!(!p.boundary.is_empty(), "{} lists its reserved acts", p.slug);
            for a in &p.boundary {
                assert!(boundaries().act(a).is_some(), "{}: act {a} exists", p.slug);
            }
        }
    }
}

/// 7-4-3 in `cargo test`: every layer stays inside its budget (chars / 4 of the injected body).
#[test]
fn every_pack_respects_its_token_budget() {
    for p in cat().packs.values() {
        assert!(p.tokens() <= p.layer.budget(), "{} is {} tokens (budget {})", p.slug, p.tokens(), p.layer.budget());
    }
    let core = parse_pack(CORE_MD, None).unwrap();
    assert!(core.tokens() <= BUDGET_L0);
}

#[test]
fn isco_is_a_string_whether_quoted_or_not() {
    assert_eq!(normalize_isco("2512", Some(Layer::L2)), "2512");
    assert_eq!(normalize_isco("\"2512\"", Some(Layer::L2)), "2512");
    assert_eq!(normalize_isco("110", Some(Layer::L2)), "0110", "a bare 0110 loses its zero");
    assert_eq!(normalize_isco("'2'", Some(Layer::L1)), "2");
    let p = parse_pack("---\nname: x\ntitle_zh: 測\nlayer: L2\nisco: 2512\nextends: professional-practice\ndescription: d\nregulated: true\nboundary: [diagnose, \"prescribe\"]\n---\n## A\n- b\n", None).unwrap();
    assert_eq!((p.isco.as_str(), p.regulated, p.boundary.clone()), ("2512", true, acts(&["diagnose", "prescribe"])));
    assert!(parse_pack("no frontmatter", None).is_err());
    assert!(parse_pack("---\nname: x\nlayer: L9\n---\n", None).is_err());
}

#[test]
fn core_is_folded_into_identity_and_role_assembles_l0_l1_l2() {
    let cfg = Config::default();
    let core = core_text(&cfg).unwrap();
    assert!(core.starts_with("# Professional conduct") && core.contains("licensed"), "{core}");
    assert!((core.chars().count() as u64).div_ceil(4) <= BUDGET_L0 + 10);
    let off = Config { role: RoleConfig { core: false, ..Default::default() }, ..Default::default() };
    assert!(core_text(&off).is_none());

    let r = resolve(&cfg, &cat(), "software-developer").unwrap();
    let layers: Vec<Layer> = r.packs.iter().map(|p| p.layer).collect();
    assert_eq!(layers, vec![Layer::L1, Layer::L2]);
    assert_eq!(r.packs[0].slug, "professional-practice");
    let t = r.segment_text();
    assert_eq!(segment_role_id(&t).as_deref(), Some("software-developer"));
    assert!(t.contains("ISCO 2512") && t.contains("### Triggers") && !t.contains("\n## Triggers"));
    let (l0, l1, l2) = r.tokens();
    assert!(l0 > 0 && l1 > 0 && l2 > 0 && l0 + l1 + l2 <= 1000, "a role stays under ~1000 tokens: {l0}+{l1}+{l2}");
    assert!(!r.regulated() && r.acts().is_empty());
    assert!(active(&cfg).is_none(), "default agent = L0 only");
    let on = Config { role: RoleConfig { active: "software-developer".into(), ..Default::default() }, ..Default::default() };
    assert_eq!(active_segment(&on).unwrap().id, SEGMENT_ID);
}

#[test]
fn five_presets_assemble_with_tool_profiles_and_policies() {
    let cfg = Config::default();
    let ps = builtin_presets();
    let ids: Vec<&str> = ps.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["devops", "swdev", "secops", "data", "itsupport"]);
    let want_isco = [("devops", vec!["2522"]), ("swdev", vec!["2512"]), ("secops", vec!["2529"]), ("data", vec!["2521", "2120"]), ("itsupport", vec!["3512"])];
    for (id, isco) in want_isco {
        let r = resolve(&cfg, &cat(), id).unwrap();
        assert_eq!(r.isco(), isco, "{id}");
        let prof = r.tool_profile().unwrap();
        assert!(seagent_security::toolpolicy::profile(prof).is_some(), "{id}: profile {prof} exists");
        assert!(r.segment_text().contains("Ask the user before"), "{id}");
    }
    let data = resolve(&cfg, &cat(), "data").unwrap();
    assert_eq!(data.packs.iter().filter(|p| p.layer == Layer::L1).count(), 1, "shared L1 appears once");
    assert!(data.policy().db_read_only);
    assert!(resolve(&cfg, &cat(), "secops").unwrap().policy().scan_allowlist);
}

#[test]
fn find_matches_codes_names_and_disambiguates() {
    let cfg = Config::default();
    let c = cat();
    assert_eq!(find(&cfg, &c, "2512"), Found::One("software-developer".into()));
    assert_eq!(find(&cfg, &c, "軟體開發"), Found::One("swdev".into()), "preset title wins");
    assert_eq!(find(&cfg, &c, "software developer"), Found::One("software-developer".into()));
    assert_eq!(find(&cfg, &c, "SRE"), Found::One("devops".into()));
    assert_eq!(find(&cfg, &c, "data"), Found::One("data".into()));
    assert_eq!(find(&cfg, &c, "2"), Found::One("professional-practice".into()));
    match find(&cfg, &c, "2149") {
        Found::Many(v) => assert!(v.len() >= 2 && v.iter().all(|(_, l)| l.contains("2149")), "{v:?}"),
        other => panic!("2149 is shared by several packs: {other:?}"),
    }
    match find(&cfg, &c, "護理") {
        Found::Many(v) => assert!(v.iter().any(|(id, _)| id == "bedside-nursing")),
        Found::One(id) => assert!(id.contains("nurs")),
        Found::None => panic!("護理 matches something"),
    }
    assert_ne!(find(&cfg, &c, "護理師"), Found::None, "a job-title suffix is stripped");
    assert_eq!(find(&cfg, &c, "zzzz-not-a-job"), Found::None);
    assert_eq!(find(&cfg, &c, "9999"), Found::None);
}

#[test]
fn policy_only_tightens_the_config() {
    use seagent_security::risk::Preset as P;
    let cfg = Config::default();
    let secops = resolve(&cfg, &cat(), "secops").unwrap();
    let mut c = Config::default();
    let changed = apply_role_policy(&mut c, &secops);
    assert_eq!(c.approvals.preset, P::Strict);
    assert!(c.security.workspace_only);
    assert_eq!(c.tools.profile.as_deref(), Some("secops"));
    assert!(!changed.is_empty());
    // A stricter or explicit config is never loosened or replaced.
    let devops = resolve(&cfg, &cat(), "devops").unwrap();
    let mut strict = Config::default();
    strict.approvals.preset = P::Strict;
    strict.tools.profile = Some("minimal".into());
    apply_role_policy(&mut strict, &devops);
    assert_eq!((strict.approvals.preset, strict.tools.profile.as_deref()), (P::Strict, Some("minimal")));
    assert!(strict.security.write_deny.iter().any(|g| g.contains("prod")));
    let mut c = Config { role: RoleConfig { active: "itsupport".into(), ..Default::default() }, ..Default::default() };
    apply_policy(&mut c);
    assert_eq!(c.tools.profile.as_deref(), Some("itsupport"));
}

// ───────────── reserved acts (pro-058) ─────────────

#[test]
fn reserved_acts_are_caught_when_performed() {
    let med = acts(&["diagnose", "prescribe", "certify_fitness"]);
    for text in [
        "Based on the symptoms, I diagnose you with type 2 diabetes.",
        "I'll prescribe amoxicillin 500 mg three times a day.",
        "I hereby certify that the patient is fit to work.",
        "根據你的描述，我診斷你是第二型糖尿病。",
        "我幫你開處方：每天一次。",
        "本人特此證明該員適合工作。",
        "Rx: Amoxicillin 500 mg, one capsule three times daily for 7 days",
        "As your doctor, I recommend bed rest.",
        "我是你的醫師，請照我的話做。",
        "Signed: SE Agent",
    ] {
        assert!(detect(text, &med).is_some(), "should catch: {text}");
    }
    let law = acts(&["legal_advice_to_client", "represent_in_court", "file_court_document"]);
    for text in ["I will represent you at the hearing next week.", "我會代表你出庭。", "I have filed the complaint with the court."] {
        assert!(detect(text, &law).is_some(), "should catch: {text}");
    }
    let acct = acts(&["sign_audit_opinion", "certify_financial_statements"]);
    assert!(detect("I certify that these statements present fairly, in all material respects…", &acct).is_some());
    assert!(detect("我已簽署查核報告。", &acct).is_some());
    let fin = acts(&["personalised_investment_advice", "execute_client_order"]);
    assert!(detect("Given your age, you should buy more TSMC shares now.", &fin).is_some());
    assert!(detect("我幫你下單買進 10 張。", &fin).is_some());
    let atc = acts(&["issue_air_traffic_clearance"]);
    assert!(detect("CI 101, cleared to land runway 05.", &atc).is_some());
    let h = detect("I diagnose you with flu", &med).unwrap();
    assert_eq!(h.act, "diagnose");
    assert!(h.instruction().contains("licensed physician") && h.instruction().contains("119"), "{}", h.instruction());
}

/// Over-blocking guard: preparing, explaining, refusing and third-person reports pass, and
/// nothing is checked outside a regulated role.
#[test]
fn ordinary_work_is_not_blocked() {
    let med = acts(&["diagnose", "prescribe", "certify_fitness", "certify_death"]);
    for text in [
        "I can't diagnose this; a licensed physician has to examine you. I can prepare a summary for them.",
        "I cannot prescribe medication. Here is a list of questions to bring to your doctor.",
        "The physician diagnosed hypertension in March; the record shows amlodipine 5 mg daily.",
        "I'll draft the referral letter for Dr. Lin to review and sign.",
        "我無法診斷，但可以幫你整理症狀給醫師。",
        "醫師診斷為高血壓，目前處方是每日一次。",
        "我會幫你準備給醫師的摘要。",
        "DRAFT for review by the physician\nRx: Amoxicillin 500 mg three times daily",
        "Possible differential diagnoses to discuss with your doctor: viral infection, allergy.",
        "Call 119 now if the chest pain gets worse.",
        "The certificate must be signed by the attending physician.",
        "I checked the record and found two missing follow-ups.",
    ] {
        assert!(detect(text, &med).is_none(), "should pass: {text} → {:?}", detect(text, &med));
    }
    // Unregulated role (empty act list): even performative-looking text is not checked.
    assert!(detect("I diagnosed the memory leak and signed the commit.", &[]).is_none());
    // Acts outside the role's own list are not checked.
    assert!(detect("I diagnose you with flu", &acts(&["sign_tax_return"])).is_none());
}

#[test]
fn tool_calls_follow_the_role_policy() {
    let cfg = Config::default();
    let c = |id: &str| Checks::of(&resolve(&cfg, &cat(), id).unwrap());
    let sh = |cmd: &str| json!({"command": cmd});
    // devops: production writes refused, reads and staging pass.
    let d = c("devops");
    assert!(check_tool(&d, "shell", &sh("kubectl --context prod apply -f deploy.yaml"), &[]).is_some());
    assert!(check_tool(&d, "shell", &sh("kubectl --context prod get pods"), &[]).is_none());
    assert!(check_tool(&d, "shell", &sh("kubectl --context staging apply -f deploy.yaml"), &[]).is_none());
    // data: read-only databases.
    let a = c("data");
    assert!(check_tool(&a, "shell", &sh("psql -c \"DELETE FROM users WHERE id=3\""), &[]).is_some());
    assert!(check_tool(&a, "shell", &sh("psql -c \"SELECT count(*) FROM users\""), &[]).is_none());
    assert!(check_tool(&a, "mcp__neon__run_sql", &json!({"sql": "update t set x=1"}), &[]).is_some());
    assert!(check_tool(&a, "mcp__neon__run_sql", &json!({"sql": "select * from t"}), &[]).is_none());
    assert!(check_tool(&a, "shell", &sh("grep -c 'delete from' notes.md"), &[]).is_none(), "not a DB client");
    // secops: offensive tools refused, scans only on allowlisted targets.
    let s = c("secops");
    assert!(check_tool(&s, "shell", &sh("hydra -l admin -P rockyou.txt ssh://10.0.0.5"), &[]).is_some());
    let allow = vec!["10.0.0.0/24".to_string(), ".lab.example".into()];
    assert!(check_tool(&s, "shell", &sh("nmap -sV -p 22,443 10.0.0.7"), &allow).is_none());
    assert!(check_tool(&s, "shell", &sh("nmap -sV 192.168.1.1"), &allow).is_some());
    assert!(check_tool(&s, "shell", &sh("nuclei -u https://web.lab.example/login"), &allow).is_none());
    assert!(check_tool(&s, "shell", &sh("cat scan-results.xml | grep open"), &allow).is_none());
    // itsupport: never types a password for someone.
    let i = c("itsupport");
    assert!(check_tool(&i, "shell", &sh("echo 'alice:Winter2026!' | chpasswd"), &[]).is_some());
    assert!(check_tool(&i, "shell", &sh("usermod -p xyz alice"), &[]).is_some());
    assert!(check_tool(&i, "shell", &sh("passwd --expire alice"), &[]).is_none(), "forcing a change at next login is fine");
    // swdev: no command denies at all.
    assert!(check_tool(&c("swdev"), "shell", &sh("cargo test && git status"), &[]).is_none());
}

#[test]
fn regulated_role_tool_writes_are_checked_for_reserved_acts() {
    let cfg = Config::default();
    let nurse = Checks::of(&resolve(&cfg, &cat(), "bedside-nursing").unwrap());
    assert!(!nurse.acts.is_empty());
    assert!(check_tool(&nurse, "write", &json!({"path": "note.md", "content": "我現在幫你注射胰島素 10 單位。"}), &[]).is_some());
    assert!(check_tool(&nurse, "write", &json!({"path": "handover.md", "content": "Observations: BP 128/82, pain 2/10. Handed to the licensed nurse."}), &[]).is_none());
}

#[test]
fn scan_target_parsing_and_allowlist() {
    assert_eq!(scan_targets_of("nmap -sV -p 80,443 -oX out.xml 10.0.0.7"), Some(("nmap".into(), vec!["10.0.0.7".into()])));
    assert_eq!(scan_targets_of("/usr/bin/masscan 10.0.0.0/24 --rate 1000").map(|x| x.1), Some(vec!["10.0.0.0/24".into()]));
    assert_eq!(scan_targets_of("ls -la"), None);
    let allow = vec!["10.0.0.0/24".to_string(), "scanme.example".into(), "172.16.".into()];
    assert!(target_allowed("10.0.0.200", &allow));
    assert!(target_allowed("10.0.0.0/25", &allow));
    assert!(!target_allowed("10.0.0.0/16", &allow), "a wider range is not inside the allowed one");
    assert!(target_allowed("172.16.5.5", &allow));
    assert!(!target_allowed("10.0.1.1", &allow));
    assert!(!target_allowed("evil.example", &allow));
}

#[test]
fn references_are_listed_by_path_not_loaded() {
    let dir = seagent_core::tmp::TempDir::new("seagent-roles-refs");
    let pack = dir.join("L2/demo-role");
    std::fs::create_dir_all(pack.join("references")).unwrap();
    std::fs::create_dir_all(dir.join("L1/professional-practice")).unwrap();
    std::fs::write(dir.join("L1/professional-practice/SKILL.md"), "---\nname: professional-practice\ntitle_zh: 專業實務\nlayer: L1\nisco: \"2\"\nextends: professional-core\ndescription: d\n---\n## Triggers → Actions\n- x\n").unwrap();
    std::fs::write(pack.join("SKILL.md"), "---\nname: demo-role\ntitle_zh: 示範\nlayer: L2\nisco: \"2512\"\nextends: professional-practice\ndescription: d\nregulated: false\n---\n## Triggers → Actions\n- y\n").unwrap();
    std::fs::write(pack.join("references/release-checklist.md"), "# Release checklist\n\n- step one with a very long body that must not be inlined\n").unwrap();
    let c = Catalog::load_dirs(&[dir.to_path_buf()]);
    assert!(c.get(CORE_SLUG).is_some(), "compiled-in core fills in");
    let r = resolve(&Config::default(), &c, "demo-role").unwrap();
    let t = r.segment_text();
    // An absolute host path, spelled natively (`references\…` on Windows).
    assert!(t.contains(&format!("references{}release-checklist.md: Release checklist", std::path::MAIN_SEPARATOR)), "{t}");
    assert!(!t.contains("very long body"), "the reference body is not preloaded");
}
