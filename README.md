# gpt_register_lite

精简版 OpenAI 协议注册：**只做「创建账号 + auth 拿 token」，无任何支付**。
收验证码支持两种后端：

- 自建 Cloud Mail（`example.com`）HTTP API
- Outlook / Microsoft Graph OAuth API（`email----password----client_id----refresh_token`）

## 链路

```
邮箱后端(Cloud Mail 或 Outlook OAuth)
  →  协议注册 8 步  →  收邮箱 OTP  →  /oauth/token 拿 platform token
  →  可选 ChatGPT Web flow 拿 backend-api AT
  →  可选 join workspace + exchange workspace-scoped AT
```

产出：`email`、`password`、`access_token`、`refresh_token`、`id_token`、`device_id`。

## 目录

```
gpt_register_lite/
├── core/              # 协议底层（从原项目移植，未改）
│   ├── pkce.py        #   PKCE / device_id / state / nonce
│   ├── profile.py     #   浏览器指纹（UA / sec-ch-ua / locale）
│   ├── http_client.py #   httpx 客户端 + 标准头 + OAuth 常量
│   └── sentinel.py    #   OpenAI Sentinel PoW
├── flow.py            # 精简注册流程（创建 + token，无支付）
├── cloudmail.py       # Cloud Mail 收码客户端（登录/建邮箱/轮询 OTP）
├── outlook.py         # Outlook / Microsoft Graph OAuth 收码客户端
├── register.py        # 顶层编排 register_and_auth()
├── config.py          # 配置加载（JSON + 环境变量覆盖）
├── cli.py             # 命令行入口
├── api.py             # 最小 HTTP 服务（FastAPI，可选）
├── batch_jobs.py      # Web 控制台批量 Outlook 注册任务
└── config.example.json
```

## 安装

```bash
pip install -r requirements.txt
cp config.example.json config.json   # 填入 admin 密码等
```

## 配置

`config.json`（敏感项可用环境变量覆盖，见下）：

| 字段 | 说明 |
|------|------|
| `cloudmail.base_url` | Cloud Mail 地址，如 `https://cloudmail.example.com` |
| `cloudmail.admin_email` | 登录用 admin 邮箱 |
| `cloudmail.admin_password` | admin 密码 |
| `cloudmail.domain` | 子邮箱域名（catch-all），如 `example.com` |
| `cloudmail.proxy` | 访问 Cloud Mail 的代理（一般直连，留 `null`） |
| `register_proxy` | OpenAI 注册走的代理（`http://user:pass@host:port` 或 socks5） |
| `otp_max_retries` / `otp_poll_interval_s` | 收码轮询次数 / 间隔秒 |
| `chatgpt_web_login` | `true` 时注册后走纯 ChatGPT Web flow，输出 backend-api AT |
| `workspace_id` | 非空时注册后加入该 workspace，并换 workspace-scoped AT |

环境变量（优先级高于文件，适合放密钥）：
`MAIL_BACKEND` `CM_BASE_URL` `CM_ADMIN_EMAIL` `CM_ADMIN_PASSWORD` `CM_DOMAIN` `CM_PROXY` `REGISTER_PROXY`

### Outlook OAuth 收码配置

把邮箱池行放到环境变量即可：

```bash
export MAIL_BACKEND=outlook
export OUTLOOK_ACCOUNT_LINE='email@outlook.com----password----client_id----refresh_token'
```

也可以拆开配置：

```bash
export MAIL_BACKEND=outlook
export OUTLOOK_EMAIL='email@outlook.com'
export OUTLOOK_CLIENT_ID='client_id'
export OUTLOOK_REFRESH_TOKEN='refresh_token'
# 可选
export OUTLOOK_TENANT='consumers'
export OUTLOOK_SCOPE='https://graph.microsoft.com/.default offline_access'
# 默认 mode=auto：先试 Graph Mail.Read，不可用时自动回退 IMAP XOAUTH2
export OUTLOOK_MODE='auto'
```

Outlook 后端不会新建邮箱；不传 `--email` 时会直接使用配置里的 Outlook 地址。
默认 `OUTLOOK_ALIAS_MODE=plus`，因此自动模式会用
`name+oai<随机>@outlook.com` 这种 Outlook 变体收码；如需固定主邮箱，设
`OUTLOOK_ALIAS_MODE=base`。

## 用法

### 1) 库

```python
import asyncio
from gpt_register_lite import CloudMailClient, CloudMailConfig, register_and_auth

async def main():
    cm = CloudMailClient(CloudMailConfig(
        base_url="https://cloudmail.example.com",
        admin_email="admin@example.com",
        admin_password="...",
        domain="example.com",
    ))
    result = await register_and_auth(cloudmail=cm)   # email=None → 自动新建子邮箱
    print(result.to_dict())

asyncio.run(main())
```

### 2) CLI

```bash
# 单个（自动新建邮箱）
python -m gpt_register_lite.cli --config config.json -v

# Outlook OAuth 单号注册（使用 OUTLOOK_ACCOUNT_LINE 指定的邮箱收码）
MAIL_BACKEND=outlook OUTLOOK_ACCOUNT_LINE='email@outlook.com----password----client_id----refresh_token' \
python -m gpt_register_lite.cli --config config.json -v

# 注册后拿纯 ChatGPT Web AT（不是 Codex/CLI OAuth）
MAIL_BACKEND=outlook OUTLOOK_ACCOUNT_LINE='email@outlook.com----password----client_id----refresh_token' \
python -m gpt_register_lite.cli --config config.json --chatgpt-web -v

# 注册后加入 workspace，并保存加入后的 workspace-scoped Web AT
MAIL_BACKEND=outlook OUTLOOK_ACCOUNT_LINE='email@outlook.com----password----client_id----refresh_token' \
python -m gpt_register_lite.cli --config config.json --workspace-id '<workspace_id>' -v

# 批量 5 个，结果写 results.json
python -m gpt_register_lite.cli --config config.json --count 5 --out results.json

# 指定邮箱
python -m gpt_register_lite.cli --config config.json --email me@example.com
```

### 3) Codex SSO RT + sub2api

```bash
# 生成 product/sub2api JSON
python -m gpt_register_lite.test_codex_browser 987654321 \
  --protocol-sso \
  --product-json \
  --out /tmp/openai_account.json

# 生成成功后自动上传到 sub2api
SUB2API_AUTHORIZATION='Bearer <admin-jwt>' \
python -m gpt_register_lite.test_codex_browser 987654321 \
  --protocol-sso \
  --product-json \
  --out /tmp/openai_account.json \
  --sub2api-upload \
  --sub2api-url https://sub2api.example.com

# 也可以把已有汇总 JSON 上传
SUB2API_AUTHORIZATION='Bearer <admin-jwt>' \
python -m gpt_register_lite.sub2api upload /tmp/accounts_product.json \
  --base-url https://sub2api.example.com \
  --mode batch
```

`--sub2api-upload` 默认使用 `POST /api/v1/admin/accounts/batch`。也支持
`SUB2API_BASE_URL`、`SUB2API_AUTHORIZATION`、`SUB2API_ADMIN_API_KEY`、
`SUB2API_UPLOAD_MODE=batch|data` 环境变量。

SSO 连接可用环境变量配置：

```bash
SSO_BASE_URL=https://sso.example.com
SSO_CONNECTION_ID=conn_xxxxxxxxxxxxxxxxxxxxxxxxxx
SSO_EMAIL_DOMAIN=example.com
CODEX_SSO_JOIN_TEAM_FIRST=false
```

默认是直接跑 Codex OAuth。只有调试旧链路时才设
`CODEX_SSO_JOIN_TEAM_FIRST=true`，或 CLI 临时加 `--join-team-first`。

`POST /codex/sso` 也支持在请求体里临时覆盖：

```bash
curl -sS http://127.0.0.1:8000/codex/sso \
  -H 'Content-Type: application/json' \
  -d '{"email":"987654321","sso_base_url":"https://sso.example.com","sso_connection_id":"conn_xxxxxxxxxxxxxxxxxxxxxxxxxx","sso_email_domain":"example.com"}'
```

### 4) HTTP 服务

```bash
pip install fastapi uvicorn
CONFIG_PATH=config.json uvicorn gpt_register_lite.api:app --host 127.0.0.1 --port 8000
```

浏览器打开：

```text
http://127.0.0.1:8000/ui
```

控制台支持：

- 粘贴 Outlook 池：`email----password----client_id----refresh_token`
- 设置原始邮箱 / plus alias、每邮箱数量、并发、重试、workspace ID
- 任务、日志、结果摘要和页面配置持久化到 SQLite（默认 `REGISTER_DB_PATH`）
- 注册后生成 `results_full.json`、AT 一行一个、sub2api product JSON
- 填 sub2api Bearer 后自动上传，或任务完成后手动上传
- 默认上传成功后清理本地 token 产物和 DB 敏感字段，只保留 summary/log/receipt

Docker 部署默认把状态放到 `/data` 挂卷：

```bash
docker compose up -d --build
```

关键环境变量：

```bash
REGISTER_DB_PATH=/data/register_console.db
BATCH_RUN_ROOT=/data/batch_runs
BATCH_PURGE_AFTER_UPLOAD=1
```

```bash
curl -X POST http://127.0.0.1:8000/register -H 'Content-Type: application/json' -d '{}'
# 自动建邮箱并注册；可带 {"email": "...", "proxy": "...", "password": "..."}
```

> ⚠️ 该接口会触发对外注册行为。**只绑 `127.0.0.1`**，或设 `API_KEY` 环境变量后请求带
> `X-API-Key`。不要裸奔公网。

## 注意事项

- **Token 复用**：Cloud Mail 的登录 token 存在 KV，单用户上限 10 个，超了挤掉最老的。
  本客户端把 JWT 缓存到本地文件（`~/.gpt_register_lite_cm_token.json`，权限 600），
  避免每次注册都重新登录而把你网页端的会话挤下线。401 时才自动重登。
- **建邮箱需人机验证**：若 Cloud Mail 后台对「新增邮箱」开了 Turnstile
  （`addVerifyOpen=true`），无人值守无法自动建邮箱 —— 改用 `--email` 指定已有地址，
  或在后台关掉该验证。
- **代理**：OpenAI 注册建议挂干净住宅代理（`register_proxy`）；Cloud Mail 一般直连。
- **风控**：批量注册默认串行，别并发猛打同一 IP。

## 致谢

感谢 [LINUX DO](https://linux.do/) 社区的交流与支持。
