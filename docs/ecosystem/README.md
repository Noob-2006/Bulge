# 生態相容文件索引

一覽（相容哪些生態、參考了哪些上游、怎麼做出來的）在根目錄 [README.md](../../README.md) 的「相容的生態」與「參考的上游專案」兩節；逐項落差報告在 [../parity-agent/](../parity-agent/)。

| 文件 | 內容 |
|---|---|
| [langchain-internals.md](langchain-internals.md) | F1：LangChain v1 / LangGraph / deepagents / LangSmith SDK 的解剖（agent 迴圈、Pregel 與 checkpoint、interrupt／HITL、工具與記憶抽象、追蹤格式），每一項都有上游 `path:line` 出處，最後是 SE Agent 的 18 項缺口與借鏡決定 |
| [graph-flows.md](graph-flows.md) | F2：`graph-flow` 工具（LangGraph 式持久化流程）的規格、與 LangGraph 的逐項對照、與 `lobster` 的分工、§0 兩個問題的答覆 |
| [langsmith.md](langsmith.md) | F3：LangSmith 的 OTLP 匯入規格（URL／header／span 屬性）、SE Agent 的相容層、驗證到什麼程度（誠實分級）與還缺什麼 |
| [langchain-integration.md](langchain-integration.md) | F4：從 LangChain／LangGraph 接入 SE Agent 的三條路（OpenAI 相容 API、MCP、A2A）＋實測輸出 |
| [openclaw-compat.md](openclaw-compat.md) | F5：OpenClaw 技能／設定／外掛／ClawHub／node 裝置在 SE Agent 上「直接用、經轉換、不可用」的清單與轉換規則 |
| [hermes-compat.md](hermes-compat.md) | F6：Hermes 技能／設定／`plugin.yaml` 外掛／optional-mcps 的實測結果，含真的把 `disk-cleanup` 外掛跑起來的過程與界線 |
| [other-ecosystems.md](other-ecosystems.md) | F7：MCP（client／server）、ACP、Claude Code（skills／hooks／settings／marketplace）、A2A 的對照與驗證指令 |

相關（非本目錄）：`docs/compliance-tw.md` §7（本輪新設計的合規影響）、`docs/plugins.md`（SE Agent 外掛協議）、
`crates/seagent-app/src/surfaces/{lobster,graph}.rs`、`crates/seagent-plugin/src/compat/`、
`crates/seagent-skills/src/compat/`。
