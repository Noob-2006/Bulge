//! Reserved acts of regulated professions, enforced at run time (pro-058, BATCH-next §7-5).
//!
//! `boundaries.toml` names the acts the law keeps for a licensed person (diagnose,
//! prescribe, sign an audit opinion, seal drawings, decide a case…). A regulated pack lists
//! the ones its profession touches in `boundary: [...]`. While a session runs such a role,
//! [`detect`] looks at what the model is about to *do* — its final reply and the input of
//! every tool call — and reports a hit only when the text performs one of those acts:
//!
//! - a first-person performative (`I diagnose…`, `I hereby certify…`, `我幫你開處方`,
//!   `本人特此證明`), where only fixed modal/adverb words may sit between the subject and the
//!   verb — so `I can't diagnose`, `the physician diagnosed`, `我無法診斷`, `醫師診斷為…` and
//!   `I'll prepare the summary for your physician` never match;
//! - the act's document form produced as final (a prescription block with a dose, a signature
//!   line signed by the assistant), unless the text is marked as a draft for the
//!   professional;
//! - presenting itself as the licensed professional (`as your doctor`, `我是你的律師`).
//!
//! Precision over recall, on purpose: drafting, checking, explaining and preparing are what
//! the packs ask the model to do, so nothing else is touched, acts outside the role's own
//! boundary list are not checked, and unregulated roles are never checked at all. What a
//! hit triggers (refuse the tool call, ask the model to rewrite as prepared material and
//! hand over to the professional) lives in [`super::hook`].

use regex::Regex;
use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Deserialize)]
pub struct Act {
    pub id: String,
    pub zh: String,
    pub en: String,
    pub area: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Area {
    pub id: String,
    pub name_zh: String,
    pub acts: Vec<String>,
    #[serde(default)]
    pub may_do: Vec<String>,
    pub hand_to: String,
    pub escalation: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Boundaries {
    pub acts: Vec<Act>,
    pub areas: Vec<Area>,
}

impl Boundaries {
    pub fn act(&self, id: &str) -> Option<&Act> {
        self.acts.iter().find(|a| a.id == id)
    }
    pub fn area_of(&self, act: &str) -> Option<&Area> {
        let a = self.act(act)?;
        self.areas.iter().find(|x| x.id == a.area)
    }
}

/// The compiled-in `boundaries.toml`.
pub fn boundaries() -> &'static Boundaries {
    static B: OnceLock<Boundaries> = OnceLock::new();
    B.get_or_init(|| toml::from_str(super::BOUNDARIES_TOML).expect("share/roles/boundaries.toml parses"))
}

/// One detected reserved act.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    /// Act id (`diagnose`), or `present_as_licensed`.
    pub act: String,
    pub act_zh: String,
    pub act_en: String,
    /// The text that matched (trimmed to ~80 chars).
    pub matched: String,
    pub hand_to: String,
    pub escalation: String,
}

impl Hit {
    /// The instruction a refusal / revision gives the model.
    pub fn instruction(&self) -> String {
        format!(
            "Reserved act for a licensed professional: {} ({}) — matched \"{}\". Do not perform it or present yourself as licensed. Keep what you prepared, clearly marked as a draft for {}, and tell the user plainly: {}",
            self.act_zh, self.act_en, self.matched, self.hand_to, self.escalation
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Family {
    Diagnose,
    Assess,
    Prescribe,
    Dispense,
    Treat,
    Certify,
    Legal,
    Invest,
    Trade,
    Insure,
    Decide,
    Police,
    Command,
    Energise,
}

fn family(act: &str) -> Family {
    use Family::*;
    match act {
        "diagnose" | "diagnose_animal" | "diagnose_communication_disorder" => Diagnose,
        "nursing_assessment" | "prenatal_assessment" | "psychological_assessment" => Assess,
        "prescribe" | "prescribe_therapeutic_diet" => Prescribe,
        "dispense" => Dispense,
        "perform_surgery" | "perform_dental_treatment" | "psychotherapy" | "perform_physiotherapy" | "provide_speech_therapy" | "perform_nursing_care" | "administer_medication" | "attend_birth" | "perform_refraction" | "fit_contact_lens" | "fit_hearing_aid"
        | "perform_medical_imaging" | "provide_advanced_life_support" | "perform_animal_surgery" | "fabricate_dental_prosthesis" | "apply_restricted_pesticide" => Treat,
        "legal_advice_to_client" | "represent_in_court" | "file_court_document" | "represent_client_before_tax_authority" | "prosecute" => Legal,
        "personalised_investment_advice" | "manage_client_portfolio" => Invest,
        "execute_client_order" => Trade,
        "sell_insurance_policy" | "bind_insurance_cover" | "broker_property_transaction" => Insure,
        "make_statutory_welfare_decision" | "decide_case" | "determine_statutory_entitlement" | "assess_tax_liability" | "release_goods_from_customs" | "issue_enforcement_order" | "issue_licence" | "order_evacuation" | "declare_goods_to_customs"
        | "prepare_land_registration" => Decide,
        "exercise_police_powers" | "detain_person" | "search_person" => Police,
        "act_as_pilot_in_command" | "issue_air_traffic_clearance" | "take_charge_of_navigational_watch" | "take_charge_of_engineering_watch" | "command_vessel" => Command,
        "energise_installation" => Energise,
        // certify_*, sign_*, seal_*, notarise, issue_*_report, issue_property_disclosure…
        _ => Certify,
    }
}

/// English first-person subject and the only words allowed between it and the verb (no
/// negation, no hypothetical: `can't`, `cannot`, `would`, `could` break the match).
const EN_SUBJ: &str = r"(?:\b(?:i|we)\b(?:\s*(?:'ll|'m|'ve|will|shall|am|are|have|hereby|now|officially|formally|herewith|also|therefore|can|going to|about to|ready to|here to))*|\blet me|\blet us|\blet's)\s+";
/// Chinese first-person subject and the allowed modal / adverb / beneficiary words.
const ZH_SUBJ: &str = r"(?:我們|我|本人|在下|讓我)(?:在此|特此|茲|已經|已|現在|現|直接|正式|會|將|就|先|來|可以|要|馬上|立即|立刻|這就|為你|為您|幫你|幫您|替你|替您|給你|給您|向你|向您|跟你|跟您)*";

fn family_patterns(f: Family) -> Vec<String> {
    use Family::*;
    let en = |verbs: &str| format!(r"(?i){EN_SUBJ}(?:{verbs})\b");
    let zh = |verbs: &str| format!(r"{ZH_SUBJ}(?:{verbs})");
    match f {
        Diagnose => vec![en(r"diagnos(?:e|es|ed|ing)"), r"(?i)\bmy (?:clinical |formal |final )?diagnosis (?:is|for you)\b".into(), zh(r"診斷|確診"), r"我的診斷(?:是|為)".into()],
        Assess => vec![
            en(r"assess(?:ed|ing)? (?:you|your|him|her|them|the patient|the client|the mother|the child)"),
            r"(?i)\bmy (?:clinical |psychological |nursing |formal )?assessment (?:is|of you|concludes|shows)\b".into(),
            zh(r"評估(?:你|您|病人|患者|個案|產婦|孩子)|做(?:心理|護理|產前)評估"),
            r"我的評估(?:結果)?(?:是|為)".into(),
        ],
        Prescribe => vec![en(r"prescrib(?:e|es|ed|ing)"), r"(?i)\bmy prescription (?:is|for you)\b".into(), zh(r"開(?:立)?(?:處方|藥方|藥)|處方|開給")],
        Dispense => vec![en(r"dispens(?:e|es|ed|ing)|(?:fill|filled|prepare|prepared) your prescription"), zh(r"調劑|配藥|發藥")],
        Treat => vec![
            en(r"operat(?:e|ing) on (?:you|him|her)|perform(?:ed|ing)? (?:the |your |a )?(?:surgery|operation|procedure|treatment|therapy|refraction|scan|x-ray|imaging|fitting|delivery)|administer(?:ed|ing)?|inject(?:ed|ing)? you|give you (?:the |an |a |your )?(?:injection|dose|medication|shot|treatment)|treat(?:ing)? you|start (?:your|the|our) (?:therapy|psychotherapy|counsel+ing|treatment) session|deliver (?:the|your) baby|fit (?:your|the|you with) (?:hearing aid|contact lens)"),
            r"(?i)\b(?:this is|welcome to) (?:your|our) (?:therapy|psychotherapy|counsel+ing) session\b".into(),
            zh(r"動手術|開刀|施打|注射|給藥|打針|治療你|治療您|進行(?:心理)?治療|諮商|驗光|配鏡|接生|執行(?:手術|治療|照射)"),
        ],
        Certify => vec![
            en(r"certif(?:y|ied|ying)|attest(?:ed)?|countersign(?:ed)?|notari[sz]e[ds]?|sign(?:ed)? off|sign(?:ed)? (?:this|the|your|it)|seal(?:ed)? (?:this|the|your|it)|stamp(?:ed)? (?:this|the|your|it)|issue[ds]? (?:this|the|your|a|an) (?:certificate|report|opinion|licen[cs]e|clearance|disclosure|statement)"),
            zh(r"證明|簽署|簽證|簽發|簽核|核章|用印|蓋章|核發|出具|公證|認證"),
        ],
        Legal => vec![
            en(r"represent(?:ed|ing)? you|act as your (?:lawyer|attorney|counsel|representative)|file[ds]? (?:the|your|this) (?:claim|complaint|motion|petition|appeal|lawsuit|brief|pleading|suit)|prosecut(?:e|ing)"),
            r"(?i)\bmy legal advice (?:is|to you)\b".into(),
            zh(r"代表你|代表您|代理你|代理您|擔任你的(?:律師|代理人)|遞狀|提告|起訴"),
            r"我的法律(?:意見|建議)(?:是|為)".into(),
        ],
        Invest => vec![
            r"(?i)\b(?:you should|i recommend(?: that)? you|i'd recommend you|my advice is to) (?:buy|sell|short|invest in|move your|put your|allocate)\b".into(),
            en(r"(?:manage|rebalance) your portfolio"),
            r"(?:建議|推薦)(?:你|您)(?:買進|賣出|買入|加碼|減碼|投資|放空|持有)".into(),
            r"(?:你|您)應該(?:買進|賣出|買入|加碼|減碼|投資|放空)".into(),
        ],
        Trade => vec![en(r"(?:buy|bought|sell|sold|place[ds]?|execute[ds]?|submit(?:ted)?) (?:the|your|this|an?) (?:order|trade)"), zh(r"下單|買進|賣出|成交")],
        Insure => vec![
            en(r"(?:bind|bound|issue[ds]?|sell|sold) (?:you )?(?:your|the|this|a) (?:cover|coverage|policy)"),
            r"(?i)\byour (?:coverage|cover|policy) is (?:now )?(?:bound|in force|active|effective)\b".into(),
            zh(r"投保|承保|核保|出單"),
            r"(?:你|您)的保單(?:已經?)?(?:生效|成立)".into(),
        ],
        Decide => vec![
            en(r"(?:approve[ds]?|grant(?:ed)?|den(?:y|ied)|reject(?:ed)?|decide[ds]?|rule[ds]? on|order(?:ed)?|determine[ds]?|declare[ds]?|release[ds]?|assess(?:ed)?|file[ds]?) (?:your|the|this) (?:application|claim|appeal|case|request|entitlement|benefit|licen[cs]e|permit|goods|shipment|tax|liability|declaration|registration)|order(?:ing)? (?:an |the )?evacuation"),
            r"(?i)\byour (?:application|claim|appeal|request|licen[cs]e|permit|benefit) (?:is|has been) (?:approved|granted|denied|rejected|refused)\b".into(),
            zh(r"核准|准予|駁回|裁定|判決|核定|不予|撤銷|放行|下令|報關|辦理(?:土地)?登記"),
            r"(?:你|您)的(?:申請|請領|案件|上訴|執照|許可|補助)(?:已經?)?(?:被)?(?:核准|通過|駁回|拒絕|不予)".into(),
        ],
        Police => vec![r"(?i)\byou are (?:now )?(?:under arrest|detained|being detained)\b".into(), en(r"(?:arrest|detain|search) you"), r"(?:你|您)(?:已經?)?被(?:逮捕|拘留|扣留|拘提)".into(), zh(r"(?:逮捕|拘留|搜索|搜身)(?:你|您)")],
        Command => vec![
            r"(?i)\bcleared (?:to|for) (?:land|landing|take-?off|approach|departure)\b".into(),
            en(r"(?:take|taking|assume|assuming|have) (?:the )?(?:command|controls|con|watch)"),
            r"許可(?:起飛|降落|進場)".into(),
            zh(r"(?:接手|負責)(?:操控|駕駛|值班|指揮|當值)"),
        ],
        Energise => vec![en(r"energi[sz]e[ds]?|switch(?:ed)? on the (?:main|supply|installation)|close[ds]? the (?:main )?breaker"), zh(r"送電|通電|復電|合閘")],
    }
}

/// Presenting itself as the licensed professional (any regulated role).
const IMPERSONATION: &[&str] = &[
    r"(?i)\b(?:i am|i'm)\s+(?:a|an|your)\s+(?:licensed\s+|registered\s+|certified\s+|board-certified\s+|practising\s+|practicing\s+)?(?:doctor|physician|surgeon|nurse|midwife|pharmacist|dentist|psychologist|psychotherapist|therapist|veterinarian|vet|lawyer|attorney|solicitor|barrister|notary|accountant|cpa|auditor|structural engineer|architect|surveyor|pilot|air traffic controller|electrician|financial advis[eo]r|judge|social worker|physiotherapist|optometrist|radiographer|paramedic)\b",
    r"(?i)\bas your (?:doctor|physician|nurse|midwife|pharmacist|dentist|lawyer|attorney|counsel|accountant|auditor|therapist|psychologist|vet|veterinarian|architect|financial advis[eo]r)\b",
    r"(?:我是|作為|身為)(?:你的|您的)(?:執業|合格|持照|註冊)?(?:醫師|醫生|護理師|護士|助產師|藥師|牙醫師?|心理師|治療師|獸醫師?|律師|地政士|公證人|會計師|審計師|技師|建築師|測量師|機長|管制員|理財顧問|投資顧問|法官|檢察官|社工師|驗光師|物理治療師|放射師)",
    r"我是(?:執業|合格|持照|註冊)(?:醫師|醫生|護理師|藥師|牙醫師|心理師|獸醫師|律師|地政士|會計師|技師|建築師|社工師|驗光師|物理治療師|放射師)",
];

/// A signature line signed by the assistant itself.
const SELF_SIGN: &[&str] = &[
    r"(?i)\b(?:signed|signature|sign-off|seal|stamp)\s*(?:by)?\s*[:：]?\s*(?:ark|claude|the assistant|ai assistant)\b",
    r"(?:簽名|簽章|簽署|簽核|核章|用印|蓋章|簽證人)\s*[:：]?\s*(?:ark|Ark|ARK|AI|本助理|助理)",
];

/// The prescription document form: an `Rx:` line plus a dose.
const RX_LINE: &str = r"(?im)^\s*(?:rx|℞)\s*[:：.]";
const DOSE: &str = r"(?i)\d+(?:\.\d+)?\s*(?:mg|mcg|µg|ml|iu|units?|tabs?|tablets?|caps?|capsules?|錠|顆|毫克|毫升|粒)";
/// Marks prepared material: a document form under these words is a draft, not the act.
const DRAFT: &str = r"(?i)\bdraft\b|\bfor (?:review|signature) by\b|\bpending (?:review|signature)\b|\bto be signed by\b|草稿|草案|待簽|待.{0,6}(?:審閱|簽核|簽署|確認)|供.{0,8}(?:審閱|簽核|簽署|確認|參考)";

struct Compiled {
    by_family: Vec<(Family, Vec<Regex>)>,
    impersonation: Vec<Regex>,
    self_sign: Vec<Regex>,
    rx: Regex,
    dose: Regex,
    draft: Regex,
}

fn compiled() -> &'static Compiled {
    static C: OnceLock<Compiled> = OnceLock::new();
    C.get_or_init(|| {
        use Family::*;
        let re = |s: &str| Regex::new(s).unwrap_or_else(|e| panic!("boundary pattern {s}: {e}"));
        Compiled {
            by_family: [Diagnose, Assess, Prescribe, Dispense, Treat, Certify, Legal, Invest, Trade, Insure, Decide, Police, Command, Energise].into_iter().map(|f| (f, family_patterns(f).iter().map(|s| re(s)).collect())).collect(),
            impersonation: IMPERSONATION.iter().map(|s| re(s)).collect(),
            self_sign: SELF_SIGN.iter().map(|s| re(s)).collect(),
            rx: re(RX_LINE),
            dose: re(DOSE),
            draft: re(DRAFT),
        }
    })
}

fn excerpt(text: &str, start: usize, end: usize) -> String {
    let s = text[..start].char_indices().rev().nth(20).map(|(i, _)| i).unwrap_or(0);
    let e = text[end..].char_indices().nth(30).map(|(i, _)| end + i).unwrap_or(text.len());
    text[s..e].split_whitespace().collect::<Vec<_>>().join(" ")
}

fn hit(act: &str, matched: String) -> Hit {
    let b = boundaries();
    let (zh, en) = b.act(act).map(|a| (a.zh.clone(), a.en.clone())).unwrap_or_else(|| ("以持照專業人員身分執業".into(), "present yourself as the licensed professional".into()));
    let area = b.area_of(act);
    Hit {
        act: act.into(),
        act_zh: zh,
        act_en: en,
        matched,
        hand_to: area.map(|a| a.hand_to.clone()).unwrap_or_else(|| "the licensed professional of record".into()),
        escalation: area.map(|a| a.escalation.clone()).unwrap_or_else(|| "This needs the licensed professional; I can prepare the material for them.".into()),
    }
}

/// The first reserved act among `acts` that `text` performs. Empty `acts` = not a regulated
/// role: nothing is checked.
pub fn detect(text: &str, acts: &[String]) -> Option<Hit> {
    if acts.is_empty() || text.trim().is_empty() {
        return None;
    }
    let c = compiled();
    let fallback = acts[0].as_str();
    for r in &c.impersonation {
        if let Some(m) = r.find(text) {
            let mut h = hit(fallback, excerpt(text, m.start(), m.end()));
            h.act = "present_as_licensed".into();
            h.act_zh = "以持照專業人員身分自居".into();
            h.act_en = "present yourself as the licensed professional".into();
            return Some(h);
        }
    }
    for r in &c.self_sign {
        if let Some(m) = r.find(text) {
            let act = acts.iter().find(|a| family(a) == Family::Certify).map(String::as_str).unwrap_or(fallback);
            return Some(hit(act, excerpt(text, m.start(), m.end())));
        }
    }
    let draft = c.draft.is_match(text);
    for act in acts {
        let f = family(act);
        if f == Family::Prescribe && !draft {
            if let Some(m) = c.rx.find(text) {
                if c.dose.is_match(&text[m.start()..]) {
                    return Some(hit(act, excerpt(text, m.start(), m.end())));
                }
            }
        }
        if let Some((_, pats)) = c.by_family.iter().find(|(x, _)| *x == f) {
            for r in pats {
                if let Some(m) = r.find(text) {
                    return Some(hit(act, excerpt(text, m.start(), m.end())));
                }
            }
        }
    }
    None
}

/// Every string inside a tool input (commands, file contents, message bodies), joined.
pub fn tool_text(input: &serde_json::Value) -> String {
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            serde_json::Value::Object(m) => m.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut v = Vec::new();
    walk(input, &mut v);
    v.join("\n")
}
