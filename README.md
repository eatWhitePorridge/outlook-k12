# outlook-k12

一个轻量的 Outlook OAuth 邮箱池注册控制台：粘贴 Outlook 账号行，自动完成邮箱验证码流程，注册后可加入指定 `workspace_id`（workid），并导出可用于 sub2api 的账号 JSON。

## 核心能力

- **Outlook OAuth 接码**：支持 `email----password----client_id----refresh_token` 格式的邮箱池。
- **批量注册**：支持原始邮箱 / plus alias、并发、重试、收码轮询参数。
- **加入 Workspace**：注册后填写 `workspace_id`，自动 join workspace，并重新获取 workspace-scoped AT。
- **Web 控制台**：浏览器启动任务、查看日志、下载产物、手动上传 sub2api。
- **持久化任务**：任务、日志、结果摘要、前端配置保存到 SQLite，刷新页面不丢配置。
- **上传后清理**：sub2api 上传成功后，默认清理本地 token 产物和 DB 敏感字段。
- **Docker 部署**：单容器 + `/data` 挂卷，适合放在 VPS 上做控制台。

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 启动本地控制台

```bash
REGISTER_DB_PATH=.local_data/register_console.db \
BATCH_RUN_ROOT=.local_data/batch_runs \
BATCH_PURGE_AFTER_UPLOAD=1 \
python -m uvicorn gpt_register_lite.api:app --host 127.0.0.1 --port 8000
```

打开：

```text
http://127.0.0.1:8000/ui
```

### 3. Docker 部署

```bash
docker compose up -d --build
```

默认端口：

```text
http://127.0.0.1:8000/ui
```

如果要对公网开放，请先设置 `API_KEY`，再把 compose 里的端口改成 `8000:8000`。

## Outlook 账号格式

每行一个 Outlook 账号：

```text
email@outlook.com----password----client_id----refresh_token
```

示例：

```text
user@example.com----password----client_id----refresh_token
```

说明：

- `email`：Outlook 邮箱。
- `password`：邮箱密码，仅用于记录/兼容字段。
- `client_id`：Microsoft OAuth client id。
- `refresh_token`：Microsoft OAuth refresh token，用于 Graph/IMAP 收验证码。

## 通过 Outlook 加入 workid

在 Web 控制台里：

1. 粘贴 Outlook 账号池。
2. 填写 `Workspace ID`，也就是 workid。
3. 邮箱模式建议先选 **原始邮箱**。
4. 并发建议从 `1~3` 开始。
5. 如需代理，在“注册代理”里填写代理 URL。
6. 点击“启动任务”。

代理格式示例：

```text
http://user:pass@host:port
socks5h://user:pass@host:port
```

如果是 SOCKS5 代理，优先使用 `socks5h://`，让代理端解析域名。

## 控制台字段说明

| 字段 | 说明 |
| --- | --- |
| `Outlook 账号` | 每行一个 Outlook OAuth 账号。 |
| `Workspace ID` | 注册后要加入的 workid。 |
| `邮箱模式` | `原始邮箱` 或 `Plus 别名`。原始邮箱更稳。 |
| `每邮箱` | 每个邮箱注册数量；原始邮箱模式固定为 1。 |
| `并发` | 同时注册数量；代理不稳时建议 1~3。 |
| `重试` | 单个账号失败后的重试次数。 |
| `注册代理` | OpenAI/ChatGPT 注册链路代理。 |
| `完成后上传 sub2api` | 任务完成后自动上传生成的 sub2api JSON。 |
| `上传成功后清理本地敏感产物` | 默认开启，上传后删除 token 文件并清理 DB 敏感字段。 |

## 产物

每个任务会生成独立目录，包含：

```text
summary.json
results_full.json
access_tokens_one_per_line.txt
sub2api_product_N.json
run.log
sub2api_upload_receipt_*.json
```

如果开启上传后清理，上传成功后默认只保留：

```text
summary.json
run.log
sub2api_upload_receipt_*.json
```

## 持久化配置

Docker 默认使用：

```text
REGISTER_DB_PATH=/data/register_console.db
BATCH_RUN_ROOT=/data/batch_runs
BATCH_PURGE_AFTER_UPLOAD=1
```

本地可按需改成：

```text
REGISTER_DB_PATH=.local_data/register_console.db
BATCH_RUN_ROOT=.local_data/batch_runs
```

`.local_data/`、DB、日志、token 产物已在 `.gitignore` 中屏蔽。

## API Key

如果设置了：

```bash
API_KEY=your_api_key
```

所有批量任务接口都需要请求头：

```text
X-API-Key: your_api_key
```

Web 控制台右上角填入并保存即可。

## 常见问题

### 代理能连上但任务超时？

先用 curl 测试：

```bash
curl -x 'socks5h://user:pass@host:port' https://ipinfo.io/ip
curl -x 'socks5h://user:pass@host:port' https://auth.openai.com/
```

如果 `ipinfo` 或 `auth.openai.com` 超时，任务也会在 `敲门 authorize` 阶段超时。

### VPS 上容易失败？

VPS 机房 IP 容易触发风控。建议 VPS 只做控制台，注册链路走干净代理，并降低并发。

### 能同时开多个任务吗？

可以。每个任务内部也有并发，多个任务叠加会放大请求量。建议总并发先控制在 `1~3`。

### 页面刷新配置会丢吗？

不会。控制台配置会保存到 SQLite。

## 安全建议

- 不要提交 `.env`、SQLite DB、任务产物、日志、token 文件。
- 不要把真实 Outlook 账号行写进 README 或 issue。
- 公开部署必须设置 `API_KEY`。
- sub2api 上传成功后建议保持默认清理策略。

## 致谢

感谢 [LINUX DO](https://linux.do/) 社区的交流与支持。
