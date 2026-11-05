# ark 企業導入文件

給資安、法遵、IT 架構與採購人員看的一組文件。**每一句都對應程式裡已經做出來的功能**；做不到的、要客戶自己負責的、目前沒有的，都明寫在「限制」或「客戶責任」欄，不用行銷語氣掩蓋。

| 文件 | 給誰 | 內容 |
|---|---|---|
| [security-whitepaper.md](security-whitepaper.md) | 資安長、架構審查 | 對外版安全白皮書：威脅模型、七道防線、資料流、稽核、供應鏈、已知限制 |
| [deployment-architecture.md](deployment-architecture.md) | IT 架構、維運 | 四種部署參考架構（單機、容器／Kubernetes、離線隔離網路、集中稽核）、連接埠與信任邊界、資料外流清單 |
| [install.md](install.md) | 維運 | deb／rpm／簽章套件庫／離線包／容器映像／Helm／Ansible／Terraform／cloud-init 的安裝與驗證 |
| [poc-guide.md](poc-guide.md) | PoC 負責人 | 兩週 PoC 計畫、驗收條件、逐步指令、退出與清除 |
| [security-questionnaire.md](security-questionnaire.md) | 供應商風險管理 | CAIQ／SIG Lite 風格的預填問卷（約 90 題），每題附證據位置 |
| [compliance-mapping.md](compliance-mapping.md) | 稽核、法遵 | SOC 2 信任服務準則與 ISO/IEC 27001:2022 附錄 A 的控制項對照：ark 提供什麼、證據在哪、客戶要補什麼 |

## 先讀這三件事

1. **ark 是自行部署的軟體，不是 SaaS。** 沒有供應商端的雲端服務在處理你的資料；資料留在你的主機（`/var/lib/ark`）。唯一的外送是你自己設定的模型供應商、聊天平台與你自己指定的 SIEM／OTLP 端點。遙測預設關閉。
2. **ark 本身沒有取得 SOC 2 報告或 ISO 27001 驗證。** `compliance-mapping.md` 是「ark 能幫你的組織滿足哪些控制項」的對照，不是認證主張。
3. **白皮書與問卷會隨程式更新。** 文件裡的指令與設定鍵，都能在對應版本的 `ark help`、`docs/MANUAL.md` 找到；對不上就是文件的錯，請回報。

## 相關既有文件

- [../SECURITY.md](../SECURITY.md)：操作者版，講每一道防線的實作細節與界線。
- [../risk-assessment.md](../risk-assessment.md)：數發部《人工智慧風險分類框架》自評、威脅模型、OWASP Agentic Top 10 對照。
- [../compliance-tw.md](../compliance-tw.md)：台灣法規對照（人工智慧基本法、個資法、資通安全管理法）。
- [../../packaging/release/README.md](../../packaging/release/README.md)：發佈簽章、SBOM、可重現建置的步驟。
