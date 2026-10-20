# M20 — harness 樹解析 / 驗證 / 物化

**目標**：`crates/bulge-harness/src/tree.rs` 的 `skills`、`validate`、`materialize`（可加私有函式；公開型別不可變）。
**來源**：`~/harness2/harness2/core/tree.py`（`validate` L336-390、`autotrigger` L192、always-on 串接概念）、`~/harness2/harness2/substrate/opencode.py` L42-88（surface：always-on、24k 上限、skill frontmatter `name` 必須等於目錄名、skill 名要在 always-on 文字出現）。只取設計,用 Rust 重寫,不含 py_compile / plugin / subagent。

## 規則
- frontmatter：SKILL.md 以第一行 `---` 開始、下一個 `---` 結束,中間每行 `key: value`(至少 `name`、`description`);之後是 body。手寫解析,不加 YAML 依賴;鍵值去頭尾空白。
- `skills`：掃描 `tree` 中鍵符合 `<skill_dir><name>/SKILL.md` 的項目,解析出 `Skill { name(=目錄名), description, body }`,依 name 排序。frontmatter 缺 name/description、或無法解析 → 回傳 `Err(Problem{path, message})`(第一個錯誤)。
- `validate`：收集**所有**問題(不是第一個):
  1. always-on 檔案(存在者)內容總位元組 > `always_on_max` → 一個 problem(path 用第一個 always-on 檔)。
  2. 每個 skill:frontmatter 的 `name` 必須等於其目錄名,否則 problem;description 空 → problem。
  3. 每個 skill 的 name 必須出現在某個 always-on 檔的文字中(觸發語),否則 problem(dead weight)。
  - skills 解析失敗也納入回傳(轉成 problem)。
- `materialize`：把 always-on 檔(存在者,依 spec 順序)以 `\n\n` 串接,末尾附一段:
  ```
  <available_skills>
  name: description
  ...(每個 skill 一行,依 name 排序)
  </available_skills>
  ```
  無 skill 則不附該區塊。缺的 always-on 檔略過。
- 只用 std、serde(若需要)。不新增依賴。

## 驗收測試
- 正常樹:skills 解析正確;validate 空;materialize 含 always-on 內容 + 每個 skill 一行。
- always-on 超過上限 → 一個 problem。
- skill 目錄名與 frontmatter name 不符 → problem。
- skill 的 name 沒在 always-on 出現 → dead-weight problem。
- frontmatter 缺 description → problem。
- 多個問題同時回報。
- `cargo test -p bulge-harness`、`cargo clippy -p bulge-harness --all-targets -- -D warnings` 通過。
