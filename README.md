# coldchain-gateway — 冷链网关密钥轮换与验签服务

冷链网关换钥时，各实例的阶段分歧会误拒新报文或放过旧钥。本服务以 PostgreSQL 为唯一权威，
集中管理每个租户的 Ed25519 公钥生命周期（当前 / 候选 / 退役中 / 已退休），并对网关报文
验签、开具回执。所有实例读取同一份角色快照，阶段分歧随之消除。

## 架构

- `api` / `api2`：Python 3.12 + FastAPI，无状态，可水平扩展；验收时启动两个共享同一数据库的实例，
  覆盖跨实例时钟、挑战与竞争。
- `db`：PostgreSQL 16，保存租户密钥、租户策略/代次、持钥挑战与证明、验签回执；时钟偏移也落库。
- `verify`：一次性验收服务，以 pytest 黑盒验收两个 `api` 实例；不占用宿主机端口，退出码即验收结果。

## 密钥状态机

每个租户同一时刻：**当前钥恰一把；候选、退役中各至多一把；已退休不限**。

```
                登记首个公钥          登记第二公钥          promote                retire
∅ ─────────────────────▶ current ──────────────────▶ current ───────────────▶ current(新) ─────────▶ current
                                                      + candidate            + retiring(旧)          (+ retired)
```

- **登记（register）**：租户无钥 → 新钥为当前；仅有当前钥 → 新钥为候选；其余情形 → 409。
- **提升（promote）**：需存在候选且无退役中钥；同一事务内候选 → 当前、旧当前 → 退役中。
- **退休（retire）**：需存在退役中钥；退役中 → 已退休（不可逆）。
- 非法迁移返回 **409**，响应体携带权威角色视图 `roles`，调用方可据此对齐本地状态。

### 并发正确性

- 所有状态迁移在事务内先取 `pg_advisory_xact_lock(hashtext('tenant_keys'), hashtext(tenant))`，
  按租户串行化，迁移在提交前对其他事务不可见。
- 三个部分唯一索引（每租户每在用角色至多一行）作为兜底：任何残余竞态都会退化为
  唯一约束冲突并返回 409。
- 验签以**单次角色读取为排序点**：快照早于退休提交则可验签成功，晚于退休提交则返回
  `KEY_RETIRED`。两种结果都正确，取决于排序点落在哪一侧。
- 持钥证明的应答与消费同样在租户咨询锁内进行：每个挑战至多一条证明（`challenge_id` 唯一索引
  兜底），提升以单条 `UPDATE ... WHERE consumed_at IS NULL ... RETURNING` 原子挑走一条仍有效、
  绑定（租户，候选 keyId，当前代次）的证明。并发提升恰好一次成功，其余返回 409 与权威角色视图。
- 可控时钟是数据库里的单个偏移量（`clock_timestamp() + offset`，只能前移），因此任意数量的
  API 实例共享同一时间；该接口仅在 `ENABLE_CLOCK_CONTROL=1` 时挂载。

## API

认证：`Authorization: Bearer <token>`。令牌缺失或无效 → **401**；令牌有效但越权 → **403**。

| 令牌 | 环境变量 | 权限（scope） |
|---|---|---|
| 管理令牌 | `ADMIN_TOKEN` | `keys:manage` + `verify` |
| 网关令牌 | `GATEWAY_TOKEN` | `verify` |

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| POST | `/v1/tenants/{tenantId}/keys` | `keys:manage` | 登记公钥（201） |
| POST | `/v1/tenants/{tenantId}/keys/promote` | `keys:manage` | 提升候选（200） |
| POST | `/v1/tenants/{tenantId}/keys/retire` | `keys:manage` | 退休退役中钥（200） |
| GET | `/v1/tenants/{tenantId}/keys` | `keys:manage` | 权威角色视图（含已退休列表、当前钥代次） |
| GET | `/v1/tenants/{tenantId}/receipts` | `keys:manage` | 回执列表 |
| GET/PUT | `/v1/tenants/{tenantId}/policy` | `keys:manage` | 读取/设置租户可选策略 |
| POST | `/v1/tenants/{tenantId}/proof/challenge` | `keys:manage` | 为当前候选钥申请一次性持钥挑战（201） |
| POST | `/v1/tenants/{tenantId}/proof/challenge/{challengeId}/answer` | `verify` | 网关用候选私钥签回挑战，登记限时证明（201） |
| POST | `/v1/verify` | `verify` | 验签并开具回执（202） |
| GET | `/healthz` | — | 健康检查 |

## 提升前持钥证明（租户级可选，默认关闭）

启用后，候选钥提升前必须证明设备确实持有对应私钥，避免误录公钥被切成当前钥而中断报文接收。
**默认关闭**：无策略行的租户与旧版本行为完全一致（登记 / 提升 / 验签不变）。

1. 管理员开启策略：`PUT /v1/tenants/{tenantId}/policy`，体 `{"requirePromotionProof": true}`。
   切换策略本身不改变任何密钥角色。
2. 管理员申请挑战：`POST /v1/tenants/{tenantId}/proof/challenge` →
   `{challengeId, candidateKeyId, currentGeneration, challenge(32B base64url), expiresAt, ttlSeconds}`。
   挑战一次性、随机 32 字节，绑定 **租户 + 候选 keyId + 当时的当前钥代次**，限时 `CHALLENGE_TTL_SECONDS`。
3. 网关用**候选私钥**对规范消息做 Ed25519 签名，提交到 `.../answer`（体 `{"signature": "<64B base64url>"}`）。
   服务按登记的候选公钥验签，成功则登记限时、单次有效的证明。
4. 提升在**同一租户事务**内检查证明：租户一致、候选 keyId 一致、当前钥代次未变、未过期、未消费；
   成功后立即 `consumed_at` 消费，随后才迁移角色并把代次 +1。

任何失效都不放行也不改变角色：挑战过期（`410 CHALLENGE_EXPIRED`）、应答重复提交
（`409 PROOF_ALREADY_REGISTERED`，即使签名完全相同）、候选或当前钥已变化
（`409 CHALLENGE_STALE`）、跨租户挪用（`404 CHALLENGE_NOT_FOUND`，与未知挑战不可区分）。
提升失败一律 **409** 并附权威 `roles`，原因码：`PROOF_MISSING` / `PROOF_EXPIRED` /
`PROOF_CONSUMED` / `ILLEGAL_TRANSITION`。并发提升仅有一次成功，其余拿到权威视图与原因。

### 持钥证明签名消息（逐字节规范）

字段长度前缀 + 标签分帧，域名分隔防止与普通验签流量互相伪造；`expiresAt` 取挑战响应中的原值：

```
context=<len>:coldchain-gateway:v1:promotion-proof-of-possession|tenant=<len>:<tenantId>|candidate=<len>:<candidateKeyId>|generation=<len>:<currentGeneration 十进制 ASCII>|challenge=<len>:<32 字节挑战>|expires=<len>:<expiresAt，挑战响应中的 ISO8601 字符串>
```

### 登记公钥

```http
POST /v1/tenants/{tenantId}/keys
Authorization: Bearer <admin-token>
Content-Type: application/json

{"keyId": "k-2026-09", "publicKey": "<32 字节 Ed25519 公钥，无填充 base64url>"}
```

- 201 → `{"keyId", "role": "current" | "candidate", "roles": {...}}`
- 409 → `{"error": "ILLEGAL_TRANSITION" | "KEY_ALREADY_EXISTS", "roles": {...}}`

### 验签

```http
POST /v1/verify
Authorization: Bearer <gateway-token>
X-Tenant-Id: <tenantId>
X-Key-Id: <keyId>
X-Signature: <64 字节 Ed25519 签名，无填充 base64url，覆盖原始请求体字节>

<0 .. 1048576 字节原始报文>
```

- 202 → `{"receiptId": "<uuid>"}`，回执落库（含报文 SHA-256 与大小）。
- 三个在用角色（当前 / 候选 / 退役中）均可验签。

### 错误码

| 状态 | `error` | 含义 |
|---|---|---|
| 400 | `BAD_REQUEST` | 缺少必需的头或字段非法 |
| 400 | `BAD_PUBLIC_KEY` | 公钥不是无填充 base64url 编码的 32 字节 |
| 400 | `BAD_SIGNATURE` | 签名错误或格式非法（报文验签**不产生回执**；挑战应答**不登记证明**） |
| 401 | `UNAUTHORIZED` | 令牌缺失或无效 |
| 403 | `FORBIDDEN` | 令牌有效但越权 |
| 404 | `KEY_UNKNOWN` | keyId 未知或属于其他租户（两者统一、不可区分） |
| 404 | `CHALLENGE_NOT_FOUND` | 挑战未知、ID 非法或属于其他租户（统一、不可区分） |
| 409 | `ILLEGAL_TRANSITION` / `KEY_ALREADY_EXISTS` | 非法迁移 / keyId 冲突（附权威 `roles`） |
| 409 | `PROOF_POLICY_DISABLED` | 租户未开启持钥证明策略即申请挑战 |
| 409 | `PROOF_MISSING` / `PROOF_EXPIRED` / `PROOF_CONSUMED` | 提升时无匹配证明 / 证明已过期 / 已被消费（附权威 `roles`） |
| 409 | `PROOF_ALREADY_REGISTERED` | 挑战已有成功应答，重复提交（即使签名相同；附权威 `roles`） |
| 409 | `CHALLENGE_STALE` | 应答时候选钥或当前钥代次已相对签发时变化（附权威 `roles`） |
| 410 | `KEY_RETIRED` | 读取快照晚于退休提交 |
| 410 | `CHALLENGE_EXPIRED` | 未应答的挑战已超过有效期 |
| 413 | `PAYLOAD_TOO_LARGE` | 报文超过 1048576 字节 |

## 快速开始

```bash
# 宿主机端口必须由 API_PORT 指定；compose 不占用任何默认端口，未设置会直接报错。
API_PORT=8080 docker compose up --build -d db api
curl -s http://localhost:8080/healthz

# 一次性验收：对 api 实例运行 pytest，退出码即验收结果
API_PORT=8080 docker compose up --build --exit-code-from verify verify
```

端到端示例（登记 → 验签 → 轮换 → 退休）：

```bash
AUTH="Authorization: Bearer $ADMIN_TOKEN"
# 生成密钥对（任选工具），公钥以无填充 base64url 编码后登记
curl -X POST "http://localhost:$API_PORT/v1/tenants/t1/keys" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"keyId": "k1", "publicKey": "<unpadded-base64url-32B>"}'

# 网关验签：签名覆盖原始请求体字节
curl -X POST "http://localhost:$API_PORT/v1/verify" \
  -H "Authorization: Bearer $GATEWAY_TOKEN" \
  -H 'X-Tenant-Id: t1' -H 'X-Key-Id: k1' -H "X-Signature: <unpadded-base64url-64B>" \
  --data-binary '@payload.bin'

# 轮换：登记候选 → 提升 → 退休旧钥
curl -X POST "http://localhost:$API_PORT/v1/tenants/t1/keys" -H "$AUTH" \
  -H 'Content-Type: application/json' -d '{"keyId": "k2", "publicKey": "..."}'
curl -X POST "http://localhost:$API_PORT/v1/tenants/t1/keys/promote" -H "$AUTH"
curl -X POST "http://localhost:$API_PORT/v1/tenants/t1/keys/retire"  -H "$AUTH"
```

开启持钥证明后的提升（申请挑战 → 候选私钥签回 → 提升消费证明）：

```bash
curl -X PUT "http://localhost:$API_PORT/v1/tenants/t1/policy" -H "$AUTH" \
  -H 'Content-Type: application/json' -d '{"requirePromotionProof": true}'
CH=$(curl -s -X POST "http://localhost:$API_PORT/v1/tenants/t1/proof/challenge" -H "$AUTH")
# 网关对规范消息（见上节）用候选私钥签名后应答
curl -X POST "http://localhost:$API_PORT/v1/tenants/t1/proof/challenge/$(jq -r .challengeId <<<"$CH")/answer" \
  -H "Authorization: Bearer $GATEWAY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"signature": "<unpadded-base64url-64B>"}'
curl -X POST "http://localhost:$API_PORT/v1/tenants/t1/keys/promote" -H "$AUTH"
# → 200 {"roles": {...}, "currentGeneration": 2, "consumedProofId": "<uuid>"}
```

## 环境变量

| 变量 | 服务 | 默认 | 说明 |
|---|---|---|---|
| `API_PORT` | `api`（宿主机映射） | 无（必填） | 宿主机端口；不设置则 compose 拒绝启动，避免占位 |
| `DATABASE_URL` | `api`, `api2` | compose 内置 | PostgreSQL DSN |
| `ADMIN_TOKEN` / `GATEWAY_TOKEN` | `api`, `api2`, `verify` | `dev-admin-token` / `dev-gateway-token` | 仅为本地默认值，生产必须覆盖 |
| `CHALLENGE_TTL_SECONDS` | `api`, `api2` | `300` | 持钥挑战/证明有效期（秒） |
| `ENABLE_CLOCK_CONTROL` | `api`, `api2` | `0`（关） | 为 `1` 时挂载仅用于验收的时钟推进接口 `/v1/internal/clock/*`；**生产不得开启** |
| `API_BASE_URL` / `API_BASE2_URL` | `verify` | `http://api:8000` / `http://api2:8000` | 两个共享同一数据库的被验收实例地址，用于跨实例与竞争验收 |

## 本地开发

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=postgresql://coldchain:coldchain@localhost:5432/coldchain
export ADMIN_TOKEN=dev-admin-token GATEWAY_TOKEN=dev-gateway-token
uvicorn app.main:app --reload

# 另开一个终端启动第二实例（共享同一数据库，不映射宿主端口也可）
uvicorn app.main:app --port 8010

# 再开一个终端，对两个实例做验收；过期用例需要可控时钟与短 TTL
ENABLE_CLOCK_CONTROL=1 CHALLENGE_TTL_SECONDS=30 \
API_BASE_URL=http://localhost:8000 API_BASE2_URL=http://localhost:8010 pytest tests/ -v
```
