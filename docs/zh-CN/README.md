<p align="center">
    <img src="https://raw.githubusercontent.com/Michael-A-Kuykendall/gatewarden/master/assets/gatewarden-logo.png" alt="Gatewarden" width="350"/>
</p>

<p align="center">
    <a href="https://crates.io/crates/gatewarden"><img src="https://img.shields.io/crates/v/gatewarden.svg" alt="Crates.io"></a>
    <a href="https://docs.rs/gatewarden"><img src="https://docs.rs/gatewarden/badge.svg" alt="Docs.rs"></a>
    <a href="https://github.com/Michael-A-Kuykendall/gatewarden/actions"><img src="https://github.com/Michael-A-Kuykendall/gatewarden/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/Michael-A-Kuykendall/gatewarden/blob/master/LICENSE"><img src="https://img.shields.io/crates/l/gatewarden.svg" alt="License"></a>
</p>

<p align="center"><em>是的，这个 logo 对于一个许可证校验库来说有点夸张。我们知道。</em></p>

<p align="center"><strong>语言：</strong> <a href="docs/zh-CN/README.md">简体中文</a> · <a href="docs/zh-TW/README.md">繁體中文</a></p>

<h2 align="center">面向 Rust 的加固版 <a href="https://keygen.sh">Keygen.sh</a> 许可证校验。</h2>

**Gatewarden 面向使用 Keygen.sh 的开发者，提供密码学层面的保障——而不仅仅是 HTTP 调用成功——来确保许可证校验响应是真实可信的。**

*加固（Hardened）* 意味着 Gatewarden 把许可证校验视为一种对抗性的协议，而不是一次受信任的 API 调用。它将 Keygen 的客户端校验从“信任 API”提升为“密码学信任”。

### 💝 支持 Gatewarden

🚀 **如果 Gatewarden 对你有帮助，欢迎 [赞助](https://github.com/sponsors/Michael-A-Kuykendall)——所有支持都将用于让它永久免费。**

- **$5/月**：咖啡英雄 ☕——永久感谢 + 名字登上 [SPONSORS.md](SPONSORS.md)
- **$25/月**：开发者支持者 🐛——优先处理缺陷 + 影响路线图
- **$100/月**：企业支持者 🏢——README 中展示 Logo + 发布说明致谢
- **$500/月**：企业合作伙伴 🚀——显著 Logo + 月度办公时间 + 路线图输入

[**🎯 成为赞助者**](https://github.com/sponsors/Michael-A-Kuykendall) | 看看我们出色的 [赞助者](SPONSORS.md) 🙏

---

## 为什么选择 Gatewarden？

大多数 Keygen 集成只是在 JSON 响应中检查 `meta.valid == true`。这在有人把你的应用指向一个对每个请求都返回 `{"meta":{"valid":true}}` 的代理之前都没问题。

Gatewarden 会校验 Keygen 为每次响应附加的 **Ed25519 签名**，从而确保：

| 威胁 | 保护 |
|--------|------------|
| **中间人 / 代理伪造** | 响应必须由 Keygen 的私钥签名 |
| **重放攻击** | 超过 5 分钟的响应将被拒绝 |
| **响应体篡改** | 校验 SHA-256 摘要（如果存在） |
| **缓存篡改** | 缓存记录每次加载时重新校验 |
| **缺少签名** | 失败即关闭（fail-closed）：无签名 = 拒绝 |

## 非目标

Gatewarden **不**尝试：

- 取代 Keygen.sh（它是 Keygen 的客户端，而非替代品）
- 阻止二进制修补或运行时内存篡改
- 提供 DRM 或反逆向工程

如果攻击者完全控制了机器，他们就能绕过任何客户端检查。Gatewarden 把门槛从“拦截 HTTP”提高到“逆向工程二进制”。

## 快速开始

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
        offline_grace: Duration::from_secs(24 * 60 * 60), // 24 小时
    };

    let manager = LicenseManager::new(config)?;

    // validate_key：始终访问 Keygen，校验签名，并更新缓存
    let result = manager.validate_key("LICENSE-KEY")?;

    if result.valid {
        println!("许可证有效（来自缓存：{}）", result.from_cache);
    }
    Ok(())
}
```

## API 概览

| 方法 | 行为 |
|--------|----------|
| `validate_key(key)` | 在线校验 → 签名验证 → 缓存 |
| `check_access(key)` | 优先使用缓存（在离线宽限期内）→ 回退到在线校验 |

两种方法都会校验签名和权限。当你需要全新校验时使用 `validate_key`；当可以接受离线宽限期、用于常规运行时检查时使用 `check_access`。

## 错误处理

Gatewarden 使用类型化错误以便精确处理：

```rust
use gatewarden::GatewardenError;

match manager.validate_key(&license_key) {
    Ok(result) if result.valid => { /* 继续 */ }
    Ok(_) => { /* 许可证无效 */ }

    // 许可证问题（用户可处理）
    Err(GatewardenError::InvalidLicense) => { /* 已过期或已撤销 */ }
    Err(GatewardenError::EntitlementMissing { code }) => { /* 层级不对 */ }

    // 安全事件（记录并调查）
    Err(GatewardenError::SignatureInvalid) => { /* 可能被篡改 */ }
    Err(GatewardenError::SignatureMissing) => { /* 响应未签名 */ }
    Err(GatewardenError::DigestMismatch) => { /* 响应体被修改 */ }
    Err(GatewardenError::ResponseTooOld { .. }) => { /* 重放尝试 */ }

    // 网络问题（可使用离线缓存）
    Err(GatewardenError::KeygenTransport(_)) => { /* 尝试 check_access() */ }

    Err(e) => { /* 其他错误 */ }
}
```

## 配置

| 字段 | 说明 |
|-------|-------------|
| `account_id` | 你的 Keygen 账户 UUID |
| `public_key_hex` | Keygen 的 Ed25519 验证密钥（64 个十六进制字符） |
| `required_entitlements` | 许可证必须具备的权限代码 |
| `offline_grace` | 在线校验失败时，缓存校验保持有效的时长 |
| `cache_namespace` | 缓存文件的目录名（位于用户数据目录下，例如 `dirs::data_dir()/<namespace>/`） |

从 Keygen 控制面板 → 设置 → 公钥 获取你的公钥。

## 离线宽限期

当在线校验因网络问题失败时，Gatewarden 会回退到经过认证的缓存：

1. 缓存记录包含原始的 Keygen 签名
2. 记录每次加载都会重新校验（防篡改）
3. 记录在 `offline_grace` 时长后过期
4. 永远不会存储许可证密钥——缓存条目以 SHA-256 哈希作为键

## 默认失败即关闭（Fail-Closed）

大多数许可证库会失败*开放（fail-open）*。Gatewarden 则失败*关闭（fail-closed）*：

- 缺少签名 → **拒绝**
- 签名无效 → **拒绝**
- 过期响应（>5 分钟）→ **拒绝**
- 检测到缓存篡改 → **拒绝**

通过类型化错误，可以将安全失败与网络失败区分开来，从而进行恰当处理。

## 安全模型

**Gatewarden 保护的内容：**

- 远程攻击者无法伪造有效的许可证响应
- 网络层面的攻击者无法重放旧响应
- 本地攻击者无法修改缓存的校验记录

**设计哲学：** 许可不是业务规则——它是对抗性的接口。Gatewarden 据此对待它。

## 离线用量计量（feature `meter`）

Gatewarden 可以**在本地且离线**地强制实施用量上限——这是 Keygen 服务端 `maxUses` 在无网络连接时无法保证的。这是一项关键差异化能力。启用 `meter` cargo 特性，然后：

```rust
// 记录一次本地使用；超出上限时返回 UsageLimitExceeded。
manager.record_use("LICENSE-KEY")?;

// 每次校验都会自动查询本地计量：
let result = manager.check_access("LICENSE-KEY")?;
// result.caps 包含 max_uses / current_uses / remaining
```

- 计量是**按许可证密钥**进行的（以许可证密钥哈希为键）。
- `LicenseManager::record_use(key)` 会递增、持久化并重新检查上限。
- 本地月度计数会被传入 `check_access_with_usage`，因此即使离线，每次校验也会遵守本地上限。
- `Selector::UsageRemaining` 会报告实际剩余的可用次数。
- 通过桥接服务，`POST /v1/record-use` 记录一次使用，并在超出上限时返回 `429`（`USAGE_LIMIT_EXCEEDED`）；校验响应会展示用量上限（`usage`：`maxUses`、`currentUses`、`remaining`）。

未启用 `meter` 时，行为保持不变——该 API 是增量且非破坏性的。详见 [docs/QUICKSTART.md](docs/QUICKSTART.md) 与 [CHANGELOG.md](CHANGELOG.md) 中的 `[0.4.2]` 条目。

## 示例

完整的带错误处理的示例见 [`examples/basic_validation.rs`](examples/basic_validation.rs)。

## 本地测试

针对真实 Keygen API 的集成测试见 [LOCAL_TESTING.md](LOCAL_TESTING.md)。

## 桥接 API（连接器接口）

对于非 Rust 运行时（TypeScript、JavaScript、Python），Gatewarden 可以通过本地旁路桥接服务暴露。

- 协议概览：[docs/bridge-protocol.md](docs/bridge-protocol.md)
- OpenAPI 契约：[spec/gatewarden-bridge.openapi.yaml](spec/gatewarden-bridge.openapi.yaml)

这样 Gatewarden 作为唯一的密码学可信源，同时支持生成客户端和标准 API 发现。

## 贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)。

**开源，但不接受主动贡献：** 本项目不接受主动发起的 Pull Request。请先开 Issue 讨论拟议的变更。

## 专利声明与许可

**带 FSE 专利限制的 MIT 许可证**

Gatewarden 基于 MIT 许可证发布（见 [LICENSE](LICENSE)）。但 `src/policy/fse/` 中的融合语义执行（FSE）实现受到额外的专利许可限制。

**FSE 专利状态：** 由 Michael A. Kuykendall 申请的专利 pending（待审）。保留所有权利。

### 这意味着什么

✅ **你可以：**

- 将 Gatewarden 用于 Keygen.sh 许可证校验（其预期用途）
- 修改、分发以及创建 Gatewarden 的衍生作品
- 出于教育目的研究 FSE 代码

❌ **你不可以：**

- 提取 FSE 并用于其他项目
- 为其他用例重新实现 FSE 算法
- 使用 FSE 创建竞争产品

**FSE 许可咨询：** 见 [FSE_PATENT_LICENSE.md](FSE_PATENT_LICENSE.md) 或联系 michaelallenkuykendall@gmail.com

## 许可证

MIT——见 [LICENSE](LICENSE)。
FSE 专利限制——见 [FSE_PATENT_LICENSE.md](FSE_PATENT_LICENSE.md)。
