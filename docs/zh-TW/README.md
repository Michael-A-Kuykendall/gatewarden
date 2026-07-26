<p align="center">
    <img src="https://raw.githubusercontent.com/Michael-A-Kuykendall/gatewarden/master/assets/gatewarden-logo.png" alt="Gatewarden" width="350"/>
</p>

<p align="center">
    <a href="https://crates.io/crates/gatewarden"><img src="https://img.shields.io/crates/v/gatewarden.svg" alt="Crates.io"></a>
    <a href="https://docs.rs/gatewarden"><img src="https://docs.rs/gatewarden/badge.svg" alt="Docs.rs"></a>
    <a href="https://github.com/Michael-A-Kuykendall/gatewarden/actions"><img src="https://github.com/Michael-A-Kuykendall/gatewarden/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/Michael-A-Kuykendall/gatewarden/blob/master/LICENSE"><img src="https://img.shields.io/crates/l/gatewarden.svg" alt="License"></a>
</p>

<p align="center"><em>是的，這個 logo 對於一個許可證校驗函式庫來說有點誇張。我們知道。</em></p>

<p align="center"><strong>語言：</strong> <a href="docs/zh-CN/README.md">简体中文</a> · <a href="docs/zh-TW/README.md">繁體中文</a></p>

<h2 align="center">面向 Rust 的加固版 <a href="https://keygen.sh">Keygen.sh</a> 許可證校驗。</h2>

**Gatewarden 面向使用 Keygen.sh 的開發者，提供密碼學層面的保障——而不僅是 HTTP 呼叫成功——來確保許可證校驗回應是真實可信的。**

*加固（Hardened）* 意味著 Gatewarden 把許可證校驗視為一種對抗性的協定，而不是一次受信任的 API 呼叫。它將 Keygen 的客戶端校驗從「信任 API」提升為「密碼學信任」。

### 💝 支援 Gatewarden

🚀 **如果 Gatewarden 對你有幫助，歡迎 [贊助](https://github.com/sponsors/Michael-A-Kuykendall)——所有支援都將用於讓它永久免費。**

- **$5/月**：咖啡英雄 ☕——永久感謝 + 名字登上 [SPONSORS.md](SPONSORS.md)
- **$25/月**：開發者支援者 🐛——優先處理缺陷 + 影響路線圖
- **$100/月**：企業支援者 🏢——README 中展示 Logo + 發布說明致謝
- **$500/月**：企業合作夥伴 🚀——顯著 Logo + 月度辦公時間 + 路線圖輸入

[**🎯 成為贊助者**](https://github.com/sponsors/Michael-A-Kuykendall) | 看看我們出色的 [贊助者](SPONSORS.md) 🙏

---

## 為什麼選擇 Gatewarden？

大多數 Keygen 整合只是在 JSON 回應中檢查 `meta.valid == true`。這在有人把你的應用指向一個對每個請求都回傳 `{"meta":{"valid":true}}` 的代理之前都沒問題。

Gatewarden 會校驗 Keygen 為每次回應附加的 **Ed25519 簽章**，從而確保：

| 威脅 | 保護 |
|--------|------------|
| **中間人 / 代理偽造** | 回應必須由 Keygen 的私鑰簽章 |
| **重放攻擊** | 超過 5 分鐘的回應將被拒絕 |
| **回應體篡改** | 校驗 SHA-256 摘要（如果存在） |
| **快取篡改** | 快取記錄每次載入時重新校驗 |
| **缺少簽章** | 失敗即關閉（fail-closed）：無簽章 = 拒絕 |

## 非目標

Gatewarden **不**嘗試：

- 取代 Keygen.sh（它是 Keygen 的客戶端，而非替代品）
- 阻止二進位修補或執行時記憶體篡改
- 提供 DRM 或反逆向工程

如果攻擊者完全控制了機器，他們就能繞過任何客戶端檢查。Gatewarden 把門檻從「攔截 HTTP」提高到「逆向工程二進位」。

## 快速開始

```rust
use gatewarden::{GatewardenConfig, LicenseManager};
use std::time::Duration;

fn main() -> Result<(), gatewarden::GatewardenError> {
    let config = GatewardenConfig {
        app_name: "myapp".to_string(),
        feature_name: "pro".to_string(),
        account_id: "your-keygen-account-id".to_string(),
        public_key_hex: "your-keygen-ed25519-verify-key".to_string(),
        required_entitlements: vec!["PRO_FEATURE".to_string()],
        user_agent_product: "myapp".to_string(),
        cache_namespace: "myapp".to_string(),
        offline_grace: Duration::from_secs(24 * 60 * 60), // 24 小時
    };

    let manager = LicenseManager::new(config)?;

    // validate_key：始終存取 Keygen，校驗簽章，並更新快取
    let result = manager.validate_key("LICENSE-KEY")?;

    if result.valid {
        println!("許可證有效（來自快取：{}）", result.from_cache);
    }
    Ok(())
}
```

## API 概覽

| 方法 | 行為 |
|--------|----------|
| `validate_key(key)` | 線上校驗 → 簽章驗證 → 快取 |
| `check_access(key)` | 優先使用快取（在離線寬限期内）→ 回退到線上校驗 |

兩種方法都會校驗簽章和權限。當你需要全新校驗時使用 `validate_key`；當可以接受離線寬限期、用於常規執行時檢查時使用 `check_access`。

## 錯誤處理

Gatewarden 使用類型化錯誤以便精確處理：

```rust
use gatewarden::GatewardenError;

match manager.validate_key(&license_key) {
    Ok(result) if result.valid => { /* 繼續 */ }
    Ok(_) => { /* 許可證無效 */ }

    // 許可證問題（用戶可處理）
    Err(GatewardenError::InvalidLicense) => { /* 已過期或已撤銷 */ }
    Err(GatewardenError::EntitlementMissing { code }) => { /* 層級不對 */ }

    // 安全事件（記錄並調查）
    Err(GatewardenError::SignatureInvalid) => { /* 可能被篡改 */ }
    Err(GatewardenError::SignatureMissing) => { /* 回應未簽章 */ }
    Err(GatewardenError::DigestMismatch) => { /* 回應體被修改 */ }
    Err(GatewardenError::ResponseTooOld { .. }) => { /* 重放嘗試 */ }

    // 網路問題（可使用離線快取）
    Err(GatewardenError::KeygenTransport(_)) => { /* 嘗試 check_access() */ }

    Err(e) => { /* 其他錯誤 */ }
}
```

## 配置

| 欄位 | 說明 |
|-------|-------------|
| `account_id` | 你的 Keygen 帳戶 UUID |
| `public_key_hex` | Keygen 的 Ed25519 驗證金鑰（64 個十六進位字元） |
| `required_entitlements` | 許可證必須具備的權限代碼 |
| `offline_grace` | 線上校驗失敗時，快取校驗保持有效的時長 |
| `cache_namespace` | 快取檔案的目錄名（位於使用者資料目錄下，例如 `dirs::data_dir()/<namespace>/`） |

從 Keygen 控制面板 → 設定 → 公鑰 獲取你的公鑰。

## 離線寬限期

當線上校驗因網路問題失敗時，Gatewarden 會回退到經過認證的快取：

1. 快取記錄包含原始的 Keygen 簽章
2. 記錄每次載入都會重新校驗（防篡改）
3. 記錄在 `offline_grace` 時長後過期
4. 永遠不會儲存許可證金鑰——快取條目以 SHA-256 雜湊作為鍵

## 預設失敗即關閉（Fail-Closed）

大多數許可證函式庫會失敗*開放（fail-open）*。Gatewarden 則失敗*關閉（fail-closed）*：

- 缺少簽章 → **拒絕**
- 簽章無效 → **拒絕**
- 過期回應（>5 分鐘）→ **拒絕**
- 偵測到快取篡改 → **拒絕**

透過類型化錯誤，可以將安全失敗與網路失敗區分開來，從而進行恰當處理。

## 安全模型

**Gatewarden 保護的內容：**

- 遠端攻擊者無法偽造有效的許可證回應
- 網路層面的攻擊者無法重放舊回應
- 本地攻擊者無法修改快取的校驗記錄

**設計哲學：** 許可不是業務規則——它是對抗性的介面。Gatewarden 據此對待它。

## 離線用量計量（feature `meter`）

Gatewarden 可以**在本地且離線**地強制實施用量上限——這是 Keygen 服務端 `maxUses` 在無網路連線時無法保證的。這是一項關鍵差異化能力。啟用 `meter` cargo 特性，然後：

```rust
// 記錄一次本地使用；超出上限時回傳 UsageLimitExceeded。
manager.record_use("LICENSE-KEY")?;

// 每次校驗都會自動查詢本地計量：
let result = manager.check_access("LICENSE-KEY")?;
// result.caps 包含 max_uses / current_uses / remaining
```

- 計量是**按許可證金鑰**進行的（以許可證金鑰雜湊為鍵）。
- `LicenseManager::record_use(key)` 會遞增、持久化並重新檢查上限。
- 本地月度計數會被傳入 `check_access_with_usage`，因此即使離線，每次校驗也會遵守本地上限。
- `Selector::UsageRemaining` 會報告實際剩餘的可用次數。
- 透過橋接服務，`POST /v1/record-use` 記錄一次使用，並在超出上限時回傳 `429`（`USAGE_LIMIT_EXCEEDED`）；校驗回應會展示用量上限（`usage`：`maxUses`、`currentUses`、`remaining`）。

未啟用 `meter` 時，行為保持不變——該 API 是增量且非破壞性的。詳見 [docs/QUICKSTART.md](docs/QUICKSTART.md) 與 [CHANGELOG.md](CHANGELOG.md) 中的 `[0.4.2]` 條目。

## 範例

完整的帶錯誤處理的範例見 [`examples/basic_validation.rs`](examples/basic_validation.rs)。

## 本地測試

針對真實 Keygen API 的整合測試見 [LOCAL_TESTING.md](LOCAL_TESTING.md)。

## 橋接 API（連接器介面）

對於非 Rust 執行時（TypeScript、JavaScript、Python），Gatewarden 可以透過本地旁路橋接服務暴露。

- 協定概覽：[docs/bridge-protocol.md](docs/bridge-protocol.md)
- OpenAPI 契約：[spec/gatewarden-bridge.openapi.yaml](spec/gatewarden-bridge.openapi.yaml)

這樣 Gatewarden 作為唯一的密碼學可信源，同時支援生成客戶端和標準 API 發現。

## 貢獻

見 [CONTRIBUTING.md](CONTRIBUTING.md)。

**開源，但不接受主動貢獻：** 本專案不接受主動發起的 Pull Request。請先開 Issue 討論擬議的變更。

## 專利聲明與許可

**帶 FSE 專利限制的 MIT 許可證**

Gatewarden 基於 MIT 許可證發布（見 [LICENSE](LICENSE)）。但 `src/policy/fse/` 中的融合語意執行（FSE）實作受到額外的專利許可限制。

**FSE 專利狀態：** 由 Michael A. Kuykendall 申請的專利 pending（待審）。保留所有權利。

### 這意味著什麼

✅ **你可以：**

- 將 Gatewarden 用於 Keygen.sh 許可證校驗（其預期用途）
- 修改、分發以及建立 Gatewarden 的衍生作品
- 出於教育目的研究 FSE 程式碼

❌ **你不可以：**

- 提取 FSE 並用於其他專案
- 為其他用例重新實作 FSE 演算法
- 使用 FSE 建立競爭產品

**FSE 許可諮詢：** 見 [FSE_PATENT_LICENSE.md](FSE_PATENT_LICENSE.md) 或聯絡 michaelallenkuykendall@gmail.com

## 許可證

MIT——見 [LICENSE](LICENSE)。
FSE 專利限制——見 [FSE_PATENT_LICENSE.md](FSE_PATENT_LICENSE.md)。
