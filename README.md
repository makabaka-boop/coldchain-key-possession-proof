# coldchain-gateway — 冷链网关密钥轮换与验签服务

冷链网关换钥时，各实例的阶段分歧会误拒新报文或放过旧钥。本服务以 PostgreSQL 为唯一权威，
集中管理每个租户的 Ed25519 公钥生命周期（当前 / 候选 / 退役中 / 已退休），并对网关报文
验签、开具回执。所有实例读取同一份角色快照，阶段分歧随之消除。

## 架构

- `api`：Python 3.12 + FastAPI，无状态，可水平扩展。
- `db`：PostgreSQL 16，保存租户密钥与验签回执。
- `verify`：一次性验收服务，以 pytest 黑盒验收 `api` 实例；不占用宿主机端口，退出码即验收结果。

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
| GET | `/v1/tenants/{tenantId}/keys` | `keys:manage` | 权威角色视图（含已退休列表） |
| GET | `/v1/tenants/{tenantId}/receipts` | `keys:manage` | 回执列表 |
| POST | `/v1/verify` | `verify` | 验签并开具回执（202） |
| GET | `/healthz` | — | 健康检查 |

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
| 400 | `BAD_SIGNATURE` | 签名错误或格式非法（**不产生回执**） |
| 401 | `UNAUTHORIZED` | 令牌缺失或无效 |
| 403 | `FORBIDDEN` | 令牌有效但越权 |
| 404 | `KEY_UNKNOWN` | keyId 未知或属于其他租户（两者统一、不可区分） |
| 409 | `ILLEGAL_TRANSITION` / `KEY_ALREADY_EXISTS` | 非法迁移 / keyId 冲突（附权威 `roles`） |
| 410 | `KEY_RETIRED` | 读取快照晚于退休提交 |
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

## 环境变量

| 变量 | 服务 | 默认 | 说明 |
|---|---|---|---|
| `API_PORT` | `api`（宿主机映射） | 无（必填） | 宿主机端口；不设置则 compose 拒绝启动，避免占位 |
| `DATABASE_URL` | `api` | compose 内置 | PostgreSQL DSN |
| `ADMIN_TOKEN` / `GATEWAY_TOKEN` | `api`, `verify` | `dev-admin-token` / `dev-gateway-token` | 仅为本地默认值，生产必须覆盖 |
| `API_BASE_URL` | `verify` | `http://api:8000` | 被验收实例的地址 |

## 本地开发

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=postgresql://coldchain:coldchain@localhost:5432/coldchain
export ADMIN_TOKEN=dev-admin-token GATEWAY_TOKEN=dev-gateway-token
uvicorn app.main:app --reload

# 另开一个终端，对运行中的实例做验收
API_BASE_URL=http://localhost:8000 pytest tests/ -v
```
