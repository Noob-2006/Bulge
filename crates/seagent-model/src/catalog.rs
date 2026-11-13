//! Built-in provider presets: every chat-model provider of Hermes
//! (`plugins/model-providers/*`, `hermes_cli/providers.py`) and OpenClaw (`extensions/*`
//! with a `providers` contract), with their aliases, endpoints, key variables and auth.
//! Any of them can be overridden or extended by `[providers.<id>]`.

use crate::reasoning::{self, Family, Hints, Shape};
use crate::{ProviderConfig, WireFormat};

#[derive(Debug, Clone)]
pub struct Preset {
    pub cfg: ProviderConfig,
    pub aliases: Vec<&'static str>,
    pub name: &'static str,
    pub signup: &'static str,
    /// Where the prompts are processed / data policy notes shown by pickers.
    pub notes: &'static str,
}

struct B(Preset);

impl B {
    fn alias(mut self, a: &[&'static str]) -> B {
        self.0.aliases.extend_from_slice(a);
        self
    }
    fn auth(mut self, a: &str) -> B {
        self.0.cfg.auth = a.into();
        self
    }
    fn oauth(mut self, flow: &str) -> B {
        self.0.cfg.oauth = Some(flow.into());
        if self.0.cfg.auth.is_empty() {
            self.0.cfg.auth = "oauth".into();
        }
        self
    }
    fn quirk(mut self, q: &str) -> B {
        self.0.cfg.quirks.push(q.into());
        self
    }
    fn header(mut self, k: &str, v: &str) -> B {
        self.0.cfg.headers.insert(k.into(), v.into());
        self
    }
    fn models(mut self, m: &[&str]) -> B {
        self.0.cfg.models = m.iter().map(|s| s.to_string()).collect();
        self
    }
    fn efforts(mut self, e: &[&str]) -> B {
        self.0.cfg.reasoning_efforts = Some(e.iter().map(|s| s.to_string()).collect());
        self
    }
    fn cmd(mut self, c: &str, args: &[&str], dialect: &str) -> B {
        self.0.cfg.command = Some(c.into());
        self.0.cfg.args = args.iter().map(|s| s.to_string()).collect();
        self.0.cfg.dialect = Some(dialect.into());
        self
    }
    fn signup(mut self, s: &'static str) -> B {
        self.0.signup = s;
        self
    }
    fn notes(mut self, s: &'static str) -> B {
        self.0.notes = s;
        self
    }
}

fn p(id: &str, name: &'static str, format: WireFormat, base: &str, envs: &[&str]) -> B {
    let cfg = ProviderConfig {
        id: id.into(),
        format,
        base_url: base.into(),
        api_key_env: envs.first().map(|s| s.to_string()),
        key_envs: envs.iter().skip(1).map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    B(Preset {
        cfg,
        aliases: vec![],
        name,
        signup: "",
        notes: "",
    })
}

fn local(id: &str, name: &'static str, base: &str, env: Option<&str>) -> B {
    // Local servers: a key is optional (sent when the variable is set).
    let mut b = p(id, name, WireFormat::OpenAiChat, base, &[]);
    if let Some(e) = env {
        b.0.cfg.key_envs = vec![e.to_string()];
        b = b.quirk("optional_key");
    }
    b
}

/// Every preset with its metadata.
pub fn catalog() -> Vec<Preset> {
    use WireFormat::*;
    let v: Vec<B> = vec![
        // ── first-party APIs ──
        p("openai", "OpenAI (Responses)", OpenAiResponses, "https://api.openai.com/v1", &["OPENAI_API_KEY"]).alias(&["openai-api", "openai-responses"]).signup("https://platform.openai.com/api-keys"),
        p("openai-chat", "OpenAI (Chat Completions)", OpenAiChat, "https://api.openai.com/v1", &["OPENAI_API_KEY"]),
        p("openai-codex", "ChatGPT subscription (Codex)", OpenAiResponses, "https://chatgpt.com/backend-api/codex", &[]).oauth("openai-codex").quirk("codex").alias(&["codex", "chatgpt"]).models(&["gpt-5.5-codex", "gpt-5.5", "gpt-5.4-mini", "gpt-5.3-codex"]).efforts(&["low", "medium", "high", "xhigh"]).notes("uses your ChatGPT plan limits; `seagent login openai-codex`"),
        p("anthropic", "Anthropic", Anthropic, "https://api.anthropic.com/v1", &["ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"]).alias(&["claude", "claude-oauth", "claude-code"]).signup("https://console.anthropic.com/settings/keys").notes("API key, or Claude subscription via `seagent login anthropic` / `seagent login anthropic-setup-token`"),
        p("gemini", "Google AI Studio (Gemini)", Gemini, "https://generativelanguage.googleapis.com/v1beta", &["GEMINI_API_KEY", "GOOGLE_API_KEY"]).alias(&["google", "google-gemini", "google-ai-studio"]).signup("https://aistudio.google.com/apikey"),
        p("xai", "xAI (Grok)", OpenAiChat, "https://api.x.ai/v1", &["XAI_API_KEY"]).alias(&["grok", "x-ai", "x.ai"]).efforts(&["low", "medium", "high"]).signup("https://console.x.ai"),
        p("xai-responses", "xAI (Responses)", OpenAiResponses, "https://api.x.ai/v1", &["XAI_API_KEY"]).efforts(&["low", "medium", "high"]),
        p("xai-oauth", "xAI account (OAuth)", OpenAiChat, "https://api.x.ai/v1", &[]).oauth("xai").efforts(&["low", "medium", "high"]),
        p("mistral", "Mistral", OpenAiChat, "https://api.mistral.ai/v1", &["MISTRAL_API_KEY"]).signup("https://console.mistral.ai"),
        p("deepseek", "DeepSeek", OpenAiChat, "https://api.deepseek.com", &["DEEPSEEK_API_KEY"]).alias(&["deep-seek"]).efforts(&["low", "medium", "high", "max"]).notes("PRC provider"),
        p("deepseek-messages", "DeepSeek (Messages API)", Anthropic, "https://api.deepseek.com/anthropic/v1", &["DEEPSEEK_API_KEY"]).alias(&["deepseek-anthropic", "deepseek-native"]).quirk("deepseek_messages").efforts(&["off", "low", "high", "max"]).models(&["deepseek-flash", "deepseek-v4-pro"]).notes("Anthropic-compatible Messages route; `deepseek` stays the default OpenAI-chat preset"),
        p("cohere", "Cohere (compatibility API)", OpenAiChat, "https://api.cohere.ai/compatibility/v1", &["COHERE_API_KEY"]),
        p("perplexity", "Perplexity", OpenAiChat, "https://api.perplexity.ai", &["PERPLEXITY_API_KEY", "PPLX_API_KEY"]).alias(&["pplx"]).models(&["sonar", "sonar-pro", "sonar-reasoning-pro"]),
        p("meta-ai", "Meta Model API", OpenAiResponses, "https://api.meta.ai/v1", &["MODEL_API_KEY", "META_API_KEY", "META_MODEL_API_KEY"]).alias(&["meta", "muse", "llama-api"]).efforts(&["minimal", "low", "medium", "high", "xhigh"]).notes("`-contributor` models train on your prompts"),
        // ── aggregators / gateways ──
        p("openrouter", "OpenRouter", OpenAiChat, "https://openrouter.ai/api/v1", &["OPENROUTER_API_KEY"]).alias(&["or"]).header("HTTP-Referer", "https://github.com/Noob-2006/System-Engineering-Agent").header("X-Title", "seagent").signup("https://openrouter.ai/keys"),
        p("ai-gateway", "Vercel AI Gateway", OpenAiChat, "https://ai-gateway.vercel.sh/v1", &["AI_GATEWAY_API_KEY"]).alias(&["vercel", "vercel-ai-gateway"]),
        p("cloudflare-ai-gateway", "Cloudflare AI Gateway", OpenAiChat, "https://gateway.ai.cloudflare.com/v1/{env:CLOUDFLARE_ACCOUNT_ID}/{env:CLOUDFLARE_GATEWAY_ID}/compat", &["CLOUDFLARE_AI_GATEWAY_API_KEY"]),
        local("litellm", "LiteLLM proxy", "http://127.0.0.1:4000/v1", Some("LITELLM_API_KEY")).alias(&["litellm-proxy"]),
        p("kilocode", "Kilo Code gateway", OpenAiChat, "https://api.kilo.ai/api/gateway", &["KILOCODE_API_KEY"]).alias(&["kilo", "kilo-code"]),
        p("opencode-zen", "OpenCode Zen", OpenAiChat, "https://opencode.ai/zen/v1", &["OPENCODE_ZEN_API_KEY", "OPENCODE_API_KEY"]).alias(&["opencode", "zen"]),
        p("opencode-go", "OpenCode Go", OpenAiChat, "https://opencode.ai/zen/go/v1", &["OPENCODE_GO_API_KEY", "OPENCODE_API_KEY"]).alias(&["go"]),
        p("router", "Ramp Router (router.com)", OpenAiResponses, "https://api.router.com/v1", &["RAMP_ROUTER_API_KEY", "ROUTER_API_KEY"]).alias(&["ramp", "router.com"]),
        p("clawrouter", "ClawRouter", OpenAiChat, "https://clawrouter.openclaw.ai/v1", &["CLAWROUTER_API_KEY"]),
        p("huggingface", "Hugging Face Inference", OpenAiChat, "https://router.huggingface.co/v1", &["HF_TOKEN", "HUGGINGFACE_HUB_TOKEN"]).alias(&["hf"]),
        p("commandcode", "CommandCode", OpenAiChat, "https://api.commandcode.ai/provider/v1", &["COMMANDCODE_API_KEY"]),
        p("commandcode-anthropic", "CommandCode (Anthropic)", Anthropic, "https://api.commandcode.ai/provider/v1", &["COMMANDCODE_API_KEY"]).auth("bearer"),
        p("actual", "Actual Computer", OpenAiChat, "https://api.actual.inc/v1", &["ACTUAL_API_KEY"]).alias(&["actual-computer"]),
        // ── inference clouds ──
        p("groq", "Groq", OpenAiChat, "https://api.groq.com/openai/v1", &["GROQ_API_KEY"]),
        p("together", "Together AI", OpenAiChat, "https://api.together.xyz/v1", &["TOGETHER_API_KEY"]),
        p("fireworks", "Fireworks AI", OpenAiChat, "https://api.fireworks.ai/inference/v1", &["FIREWORKS_API_KEY"]).alias(&["fireworks-ai", "fw"]),
        p("cerebras", "Cerebras", OpenAiChat, "https://api.cerebras.ai/v1", &["CEREBRAS_API_KEY"]),
        p("deepinfra", "DeepInfra", OpenAiChat, "https://api.deepinfra.com/v1/openai", &["DEEPINFRA_API_KEY"]),
        p("novita", "NovitaAI", OpenAiChat, "https://api.novita.ai/openai/v1", &["NOVITA_API_KEY"]).alias(&["novita-ai"]),
        p("nvidia", "NVIDIA NIM", OpenAiChat, "https://integrate.api.nvidia.com/v1", &["NVIDIA_API_KEY"]).alias(&["nim", "nvidia-nim"]),
        p("nebius", "Nebius Token Factory", OpenAiChat, "https://api.tokenfactory.nebius.com/v1", &["NEBIUS_API_KEY", "NEBIUS_TOKEN_FACTORY_API_KEY"]).alias(&["nebius-token-factory"]).efforts(&["low", "medium", "high"]),
        p("gmi", "GMI Cloud", OpenAiChat, "https://api.gmi-serving.com/v1", &["GMI_API_KEY"]).alias(&["gmi-cloud"]),
        p("baseten", "Baseten", OpenAiChat, "https://inference.baseten.co/v1", &["BASETEN_API_KEY"]),
        p("chutes", "Chutes", OpenAiChat, "https://llm.chutes.ai/v1", &["CHUTES_API_KEY", "CHUTES_OAUTH_TOKEN"]),
        p("featherless", "Featherless", OpenAiChat, "https://api.featherless.ai/v1", &["FEATHERLESS_API_KEY"]),
        p("venice", "Venice", OpenAiChat, "https://api.venice.ai/api/v1", &["VENICE_API_KEY"]),
        p("synthetic", "Synthetic", Anthropic, "https://api.synthetic.new/anthropic/v1", &["SYNTHETIC_API_KEY"]).auth("bearer"),
        p("arcee", "Arcee AI", OpenAiChat, "https://api.arcee.ai/api/v1", &["ARCEEAI_API_KEY"]).alias(&["arcee-ai"]),
        p("upstage", "Upstage Solar", OpenAiChat, "https://api.upstage.ai/v1", &["UPSTAGE_API_KEY"]).alias(&["solar"]).efforts(&["low", "medium", "high"]),
        p("typesafe", "Typesafe", OpenAiChat, "https://api.typesafe.ai/v1", &["TYPESAFE_API_KEY"]),
        p("levanto", "Levanto", OpenAiChat, "https://sage.levanto.ai/v1", &["LEVANTO_API_KEY"]),
        p("longcat", "LongCat", OpenAiChat, "https://api.longcat.chat/openai/v1", &["LONGCAT_API_KEY"]),
        p("radius", "Radius gateway", Anthropic, "https://radius.pi.dev/v1", &["RADIUS_API_KEY"]).auth("bearer"),
        p("ollama-cloud", "Ollama Cloud", OpenAiChat, "https://ollama.com/v1", &["OLLAMA_API_KEY"]).efforts(&["off", "low", "medium", "high", "max"]),
        p("nous", "Nous Portal", OpenAiChat, "https://inference-api.nousresearch.com/v1", &["NOUS_API_KEY"]).oauth("nous").alias(&["nous-portal", "nousresearch"]),
        // ── hyperscalers ──
        p("bedrock", "AWS Bedrock (Converse)", Bedrock, "https://bedrock-runtime.{region}.amazonaws.com", &[]).auth("aws").alias(&["aws", "aws-bedrock", "amazon-bedrock", "amazon"]).notes("SigV4 from AWS env/profile, or $AWS_BEARER_TOKEN_BEDROCK"),
        p("bedrock-mantle", "AWS Bedrock (OpenAI-compatible Mantle)", OpenAiChat, "https://bedrock-mantle.{region}.api.aws/v1", &["AWS_BEARER_TOKEN_BEDROCK"]).alias(&["amazon-bedrock-mantle"]),
        p("vertex", "Vertex AI (OpenAI-compatible)", OpenAiChat, "https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}/endpoints/openapi", &[]).auth("google").alias(&["vertex-ai", "gcp-vertex"]).notes("models as `google/gemini-…`; credentials from ADC"),
        p("google-vertex", "Vertex AI (Gemini native)", Gemini, "https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}/publishers/google", &[]).auth("google").quirk("vertex"),
        p("anthropic-vertex", "Claude on Vertex AI", Anthropic, "https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}", &[]).auth("google").quirk("vertex"),
        p("azure-openai", "Azure OpenAI", OpenAiChat, "https://{env:AZURE_OPENAI_RESOURCE}.openai.azure.com/openai/v1", &["AZURE_OPENAI_API_KEY"]).auth("api-key").alias(&["azure"]),
        p("azure-openai-entra", "Azure OpenAI (Entra ID)", OpenAiChat, "https://{env:AZURE_OPENAI_RESOURCE}.openai.azure.com/openai/v1", &[]).auth("azure-ad"),
        p("azure-foundry", "Azure AI Foundry", OpenAiChat, "{env:AZURE_FOUNDRY_BASE_URL}", &["AZURE_FOUNDRY_API_KEY"]).auth("api-key").alias(&["azure-ai-foundry"]),
        p("microsoft-foundry", "Microsoft Foundry", OpenAiChat, "https://{env:AZURE_FOUNDRY_RESOURCE}.services.ai.azure.com/openai/v1", &["AZURE_OPENAI_API_KEY"]).auth("api-key"),
        p("microsoft-foundry-anthropic", "Claude on Microsoft Foundry", Anthropic, "https://{env:AZURE_FOUNDRY_RESOURCE}.services.ai.azure.com/anthropic/v1", &["AZURE_OPENAI_API_KEY"]),
        p("github-copilot", "GitHub Copilot", OpenAiChat, "https://api.githubcopilot.com", &["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]).auth("copilot").oauth("github-copilot").quirk("copilot").alias(&["copilot", "github-models"]).models(&["gpt-5.5", "claude-sonnet-4.5", "gemini-2.5-pro", "gpt-4.1"]),
        p("copilot-proxy", "Copilot proxy (local)", OpenAiChat, "http://localhost:3000/v1", &[]),
        // ── China ──
        p("dashscope", "Alibaba DashScope / Qwen (intl)", OpenAiChat, "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", &["DASHSCOPE_API_KEY", "QWEN_API_KEY"]).alias(&["alibaba", "qwen-dashscope", "modelstudio", "qwencloud"]).notes("PRC provider"),
        p("dashscope-cn", "Alibaba DashScope (China)", OpenAiChat, "https://dashscope.aliyuncs.com/compatible-mode/v1", &["DASHSCOPE_API_KEY"]).alias(&["alibaba-cn"]),
        p("alibaba-coding-plan", "Alibaba Coding Plan", OpenAiChat, "https://coding-intl.dashscope.aliyuncs.com/v1", &["ALIBABA_CODING_PLAN_API_KEY", "DASHSCOPE_API_KEY"]).alias(&["dashscope-coding"]),
        p("alibaba-coding-plan-cn", "Alibaba Coding Plan (China)", OpenAiChat, "https://coding.dashscope.aliyuncs.com/v1", &["ALIBABA_CODING_PLAN_CN_API_KEY", "ALIBABA_CODING_PLAN_API_KEY", "DASHSCOPE_API_KEY"]),
        p("alibaba-token-plan", "Alibaba Token Plan", OpenAiChat, "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1", &["ALIBABA_TOKEN_PLAN_API_KEY", "QWEN_TOKEN_PLAN_API_KEY"]).alias(&["qwen-token-plan", "bailian-token-plan"]),
        p("alibaba-token-plan-cn", "Alibaba Token Plan (China)", OpenAiChat, "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1", &["ALIBABA_TOKEN_PLAN_CN_API_KEY", "ALIBABA_TOKEN_PLAN_API_KEY"]),
        p("qwen", "Qwen portal (OAuth)", OpenAiChat, "https://portal.qwen.ai/v1", &["QWEN_OAUTH_TOKEN"]).oauth("qwen").alias(&["qwen-oauth", "qwen-portal", "qwen-cli"]).models(&["qwen3-coder-plus", "qwen3-max", "coder-model"]),
        p("moonshot", "Moonshot / Kimi (intl)", OpenAiChat, "https://api.moonshot.ai/v1", &["MOONSHOT_API_KEY", "KIMI_API_KEY"]).alias(&["kimi"]).notes("PRC provider"),
        p("moonshot-cn", "Moonshot / Kimi (China)", OpenAiChat, "https://api.moonshot.cn/v1", &["MOONSHOT_CN_API_KEY", "KIMI_CN_API_KEY"]).alias(&["kimi-cn", "kimi-coding-cn"]),
        p("kimi-coding", "Kimi for Coding", Anthropic, "https://api.kimi.com/coding/v1", &["KIMI_API_KEY", "KIMICODE_API_KEY", "KIMI_CODING_API_KEY"]).auth("bearer").header("User-Agent", "KimiCLI/1.0 (seagent)").alias(&["kimi-for-coding", "kimi-code"]),
        p("zhipu", "Zhipu GLM (bigmodel.cn)", OpenAiChat, "https://open.bigmodel.cn/api/paas/v4", &["ZHIPU_API_KEY"]).alias(&["bigmodel"]),
        p("zai", "Z.AI GLM (intl)", OpenAiChat, "https://api.z.ai/api/paas/v4", &["ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY"]).alias(&["z-ai", "z.ai", "glm"]),
        p("zai-coding", "Z.AI GLM Coding Plan", OpenAiChat, "https://api.z.ai/api/coding/paas/v4", &["ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY"]),
        p("minimax", "MiniMax (intl)", OpenAiChat, "https://api.minimax.io/v1", &["MINIMAX_API_KEY"]).alias(&["mini-max"]),
        p("minimax-anthropic", "MiniMax (Anthropic API)", Anthropic, "https://api.minimax.io/anthropic/v1", &["MINIMAX_API_KEY", "MINIMAX_CODING_API_KEY"]).auth("bearer"),
        p("minimax-cn", "MiniMax (China)", Anthropic, "https://api.minimaxi.com/anthropic/v1", &["MINIMAX_CN_API_KEY"]).auth("bearer").alias(&["minimax-china"]),
        p("minimax-oauth", "MiniMax portal (OAuth)", Anthropic, "https://api.minimax.io/anthropic/v1", &[]).oauth("minimax").alias(&["minimax-portal"]),
        p("minimax-oauth-cn", "MiniMax portal (OAuth, China)", Anthropic, "https://api.minimaxi.com/anthropic/v1", &[]).oauth("minimax-cn"),
        p("siliconflow", "SiliconFlow", OpenAiChat, "https://api.siliconflow.cn/v1", &["SILICONFLOW_API_KEY"]),
        p("stepfun", "StepFun", OpenAiChat, "https://api.stepfun.ai/v1", &["STEPFUN_API_KEY"]).alias(&["step"]),
        p("stepfun-plan", "StepFun Step Plan", OpenAiChat, "https://api.stepfun.ai/step_plan/v1", &["STEPFUN_API_KEY"]).alias(&["stepfun-coding-plan"]),
        p("xiaomi", "Xiaomi MiMo", OpenAiChat, "https://api.xiaomimimo.com/v1", &["XIAOMI_API_KEY"]).alias(&["mimo"]),
        p("xiaomi-token-plan", "Xiaomi MiMo Token Plan", OpenAiChat, "https://token-plan-sgp.xiaomimimo.com/v1", &["XIAOMI_TOKEN_PLAN_API_KEY"]),
        p("tencent-tokenhub", "Tencent TokenHub", OpenAiChat, "https://tokenhub.tencentmaas.com/v1", &["TOKENHUB_API_KEY"]).efforts(&["low", "medium", "high"]),
        p("tencent-tokenplan", "Tencent TokenPlan", Anthropic, "https://api.lkeap.cloud.tencent.com/plan/anthropic/v1", &["TOKENPLAN_API_KEY"]).auth("bearer"),
        p("qianfan", "Baidu Qianfan", OpenAiChat, "https://qianfan.baidubce.com/v2", &["QIANFAN_API_KEY"]),
        p("volcengine", "Volcengine SE Agent (Doubao)", OpenAiChat, "https://seagent.cn-beijing.volces.com/api/v3", &["VOLCANO_ENGINE_API_KEY", "SEAGENT_API_KEY"]).alias(&["doubao"]),
        p("volcengine-plan", "Volcengine Coding Plan", OpenAiChat, "https://seagent.cn-beijing.volces.com/api/coding/v3", &["VOLCANO_ENGINE_API_KEY", "SEAGENT_API_KEY"]),
        p("byteplus", "BytePlus ModelSeagent", OpenAiChat, "https://seagent.ap-southeast.bytepluses.com/api/v3", &["BYTEPLUS_API_KEY"]),
        p("byteplus-plan", "BytePlus Coding Plan", OpenAiChat, "https://seagent.ap-southeast.bytepluses.com/api/coding/v3", &["BYTEPLUS_API_KEY"]),
        // ── local servers ──
        local("ollama", "Ollama (local)", "http://127.0.0.1:11434/v1", Some("OLLAMA_API_KEY")),
        local("lmstudio", "LM Studio", "http://127.0.0.1:1234/v1", Some("LM_API_KEY")).alias(&["lm-studio"]),
        local("vllm", "vLLM", "http://127.0.0.1:8000/v1", Some("VLLM_API_KEY")),
        local("sglang", "SGLang", "http://127.0.0.1:30000/v1", Some("SGLANG_API_KEY")),
        local("llama-cpp", "llama.cpp server", "http://127.0.0.1:8080/v1", Some("LLAMA_SERVER_API_KEY")).alias(&["llamacpp", "llama.cpp"]),
        local("omlx", "oMLX", "http://127.0.0.1:8000/v1", Some("OMLX_API_KEY")),
        // ── agent CLIs / runtimes ──
        p("claude-cli", "Claude Code CLI (subscription)", Cli, "", &[]).cmd("claude", &["-p", "--output-format", "stream-json", "--verbose", "--model", "{model}"], "claude-stream-json").models(&["sonnet", "opus", "haiku"]),
        p("gemini-cli", "Gemini CLI (Google login)", Cli, "", &[]).cmd("gemini", &["--skip-trust", "--approval-mode", "auto_edit", "--output-format", "stream-json", "--model", "{model}", "--prompt", "{prompt}"], "gemini-stream-json").alias(&["google-gemini-cli"]).models(&["gemini-3.1-pro-preview", "gemini-3-flash-preview"]),
        p("codex-cli", "Codex CLI (exec)", Cli, "", &[]).cmd("codex", &["exec", "--json", "--skip-git-repo-check", "--model", "{model}", "-"], "codex-jsonl").models(&["gpt-5.5-codex", "gpt-5.5"]),
        p("copilot-cli", "GitHub Copilot CLI", Cli, "", &[]).cmd("copilot", &["-p", "{prompt}", "--allow-all-tools", "--silent", "--model", "{model}"], "text").models(&["claude-sonnet-4.5", "gpt-5.5"]),
        p("copilot-acp", "GitHub Copilot CLI (ACP runtime)", Acp, "", &[]).cmd("copilot", &["--acp", "--stdio"], "acp").alias(&["copilot-acp-runtime"]).models(&["claude-sonnet-4.5", "gpt-5.5"]).notes("one ACP session per request; `copilot --acp` from @github/copilot"),
        p("codex-app-server", "Codex app-server runtime", CodexAppServer, "", &[]).cmd("codex", &["app-server"], "jsonrpc").alias(&["codex-runtime"]).models(&["gpt-5.5-codex", "gpt-5.5"]),
        p("moa", "Mixture of agents", Moa, "", &[]).alias(&["mixture-of-agents"]),
        p("openai-agents", "OpenAI Agents API (hosted sessions)", AgentsApi, "https://api.openai.com/v1", &["OPENAI_API_KEY"]).alias(&["agents-api", "agentsapi"]).models(&["gpt-5.5", "gpt-5.4-mini"]).notes("runs tools in an OpenAI-hosted session"),
        p("muse-code", "Meta Muse Code CLI (muse serve)", Muse, "", &[]).cmd("muse", &["serve"], "msp").models(&["muse-spark-1.3", "muse-spark-1.3-contributor"]).notes("needs `muse login` on this host"),
    ];
    let mut out: Vec<Preset> = v.into_iter().map(|b| b.0).collect();
    for x in &mut out {
        if matches!(
            x.cfg.format,
            Cli | CodexAppServer | Acp | Muse | Moa
        ) {
            x.cfg.auth = "none".into();
        }
    }
    out
}

/// The preset provider configs (what `[providers.*]` overrides).
pub fn presets() -> Vec<ProviderConfig> {
    catalog().into_iter().map(|p| p.cfg).collect()
}

/// Canonical preset id for an alias (or the id itself).
pub fn resolve_alias(id: &str) -> Option<String> {
    let id = id.trim().to_lowercase();
    let c = catalog();
    c.iter()
        .find(|p| p.cfg.id == id)
        .or_else(|| c.iter().find(|p| p.aliases.contains(&id.as_str())))
        .map(|p| p.cfg.id.clone())
}

/// The model family a preset serves, when it serves exactly one (a new model of that family
/// then needs no preset edit). Cloud resellers (`bedrock`, `vertex`, `openrouter`…) and
/// gateways serve several families and return `None`, so the model id decides.
pub fn preset_family(id: &str) -> Option<Family> {
    reasoning::family_from_provider(&resolve_alias(id)?)
}

/// The reasoning wire a preset speaks, from its configured format: `None` when the endpoint
/// does not imply one — Anthropic (budget vs adaptive is model-dependent, see
/// [`reasoning::detect_with`]), cloud resellers, CLI backends and local servers (they ignore
/// unknown fields inconsistently, so nothing is assumed).
pub fn preset_shape(id: &str) -> Option<Shape> {
    let want = resolve_alias(id)?;
    let p = catalog().into_iter().find(|p| p.cfg.id == want)?;
    Some(match p.cfg.format {
        WireFormat::Gemini => Shape::ThinkingConfig,
        WireFormat::OpenAiResponses | WireFormat::AgentsApi => Shape::ResponsesEffort,
        WireFormat::OpenAiChat if !local_endpoint(&p.cfg.base_url) => Shape::Effort,
        _ => return None,
    })
}

fn local_endpoint(base: &str) -> bool {
    let b = base.trim().to_lowercase();
    b.starts_with("http://127.0.0.1")
        || b.starts_with("http://localhost")
        || b.starts_with("http://[::1]")
        || b.starts_with("http://0.0.0.0")
}

/// Reasoning hints for a `provider`/`model` pair: the preset's family and dialect, overridden
/// by models.dev when the registry is already loaded (this never fetches and never reads the
/// disk — an unloaded registry simply falls through to id-based detection).
///
/// ```ignore
/// let h = catalog::reasoning_hints(Some("anthropic"), "claude-opus-6-7");
/// let support = reasoning::detect_with("claude-opus-6-7", Some(&h));
/// ```
pub fn reasoning_hints(provider: Option<&str>, model: &str) -> Hints {
    let mut h = Hints {
        family: provider.and_then(preset_family),
        shape: provider.and_then(preset_shape),
        reasoning: None,
    };
    if let Some(info) = crate::modelsdb::registry_entry(provider, model) {
        h.family = reasoning::family_from_provider(&info.provider).or(h.family);
        // models.dev `reasoning` is authoritative for this model id.
        h.reasoning = Some(info.reasoning);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_are_unique_and_do_not_shadow_ids() {
        let c = catalog();
        let ids: std::collections::HashSet<&str> = c.iter().map(|p| p.cfg.id.as_str()).collect();
        let mut seen = std::collections::HashSet::new();
        for p in &c {
            for a in &p.aliases {
                assert!(
                    !ids.contains(a),
                    "alias {a} of {} shadows a preset id",
                    p.cfg.id
                );
                assert!(seen.insert(*a), "alias {a} used twice");
            }
        }
        assert_eq!(resolve_alias("grok").as_deref(), Some("xai"));
        assert_eq!(resolve_alias("AWS").as_deref(), Some("bedrock"));
        assert_eq!(
            resolve_alias("google-gemini-cli").as_deref(),
            Some("gemini-cli")
        );
        assert_eq!(resolve_alias("openrouter").as_deref(), Some("openrouter"));
        assert!(resolve_alias("nonesuch").is_none());
    }

    #[test]
    fn reasoning_preset_dialects_come_from_metadata() {
        assert_eq!(preset_shape("gemini"), Some(Shape::ThinkingConfig));
        assert_eq!(preset_shape("openai"), Some(Shape::ResponsesEffort));
        assert_eq!(preset_shape("openai-chat"), Some(Shape::Effort));
        assert_eq!(preset_shape("xai"), Some(Shape::Effort));
        assert_eq!(
            preset_shape("anthropic"),
            None,
            "budget vs adaptive is decided by the model, not the preset"
        );
        assert_eq!(
            preset_shape("ollama"),
            None,
            "local servers: assume nothing"
        );
        assert_eq!(
            preset_shape("claude-cli"),
            None,
            "CLI backends have no wire field"
        );
        assert_eq!(preset_shape("nonesuch"), None);

        assert_eq!(preset_family("anthropic"), Some(Family::Anthropic));
        assert_eq!(preset_family("claude-cli"), Some(Family::Anthropic));
        assert_eq!(preset_family("xai"), Some(Family::Xai));
        assert_eq!(preset_family("gemini-cli"), Some(Family::Gemini));
        assert_eq!(preset_family("deepseek"), Some(Family::DeepSeek));
        assert_eq!(preset_family("azure-openai"), Some(Family::OpenAi));
        assert_eq!(
            preset_family("openrouter"),
            None,
            "gateways serve several families"
        );
        assert_eq!(preset_family("bedrock"), None);
    }

    #[test]
    fn reasoning_hints_place_unlisted_models() {
        // Preset + an id nobody listed yet: family derivation still answers.
        let m = "claude-opus-6-7";
        let h = reasoning_hints(Some("anthropic"), m);
        let s = reasoning::detect_with(m, Some(&h));
        assert_eq!(s.shape, Shape::Adaptive);
        assert!(s.verified());

        let m = "gemini-9.9-pro-preview";
        let h = reasoning_hints(Some("gemini"), m);
        assert_eq!(
            reasoning::detect_with(m, Some(&h)).shape,
            Shape::ThinkingConfig
        );

        // No preset, no metadata: no optional parameter, flagged unverified.
        let m = "acme-neo-9000";
        let h = reasoning_hints(None, m);
        let s = reasoning::detect_with(m, Some(&h));
        assert!(!s.sends_reasoning());
        assert!(s.unverified());
    }

    #[test]
    fn deepseek_messages_is_an_opt_in_route() {
        let p = catalog().into_iter().find(|p| p.cfg.id == "deepseek-messages").expect("DeepSeek Messages preset");
        assert_eq!(p.cfg.format, WireFormat::Anthropic);
        assert_eq!(p.cfg.base_url, "https://api.deepseek.com/anthropic/v1");
        assert_eq!(p.cfg.auth, "");
        assert_eq!(p.cfg.api_key_env.as_deref(), Some("DEEPSEEK_API_KEY"));
        assert!(p.cfg.has_quirk("deepseek_messages"));
        assert_eq!(p.cfg.reasoning_efforts.as_deref(), Some(&["off".to_string(), "low".into(), "high".into(), "max".into()][..]));
        assert_eq!(resolve_alias("deepseek").as_deref(), Some("deepseek"), "the OpenAI-chat preset stays the default");
        assert_eq!(resolve_alias("deepseek-native").as_deref(), Some("deepseek-messages"));
    }

    #[test]
    fn covers_both_upstreams() {
        let ids: Vec<String> = presets().into_iter().map(|p| p.id).collect();
        for want in [
            "openrouter",
            "bedrock",
            "vertex",
            "google-vertex",
            "anthropic-vertex",
            "github-copilot",
            "azure-openai",
            "groq",
            "together",
            "fireworks",
            "xai",
            "minimax",
            "dashscope",
            "moonshot",
            "zhipu",
            "zai",
            "nous",
            "cerebras",
            "perplexity",
            "ollama",
            "lmstudio",
            "vllm",
            "sglang",
            "openai-codex",
            "qwen",
            "kimi-coding",
            "deepinfra",
            "huggingface",
            "kilocode",
            "nvidia",
            "novita",
            "nebius",
            "gmi",
            "arcee",
            "upstage",
            "stepfun",
            "xiaomi",
            "tencent-tokenhub",
            "venice",
            "baseten",
            "chutes",
            "cohere",
            "featherless",
            "qianfan",
            "volcengine",
            "byteplus",
            "synthetic",
            "litellm",
            "cloudflare-ai-gateway",
            "ai-gateway",
            "opencode-zen",
            "opencode-go",
            "meta-ai",
            "router",
            "actual",
            "commandcode",
            "claude-cli",
            "gemini-cli",
            "codex-app-server",
        ] {
            assert!(ids.iter().any(|i| i == want), "missing preset {want}");
        }
    }
}
