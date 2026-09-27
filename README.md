# Exchange Edge Mail Dashboard

Exchange Server 2019 Edge Transport 日志的只读 Web 仪表盘，支持最近 1/7/30 天的收件、发件、拒收、公司外发失败、系统退信、异常发件人和匿名冒充公司域检测。

主要功能：

- 最近 24 小时按小时展示，最近 7/30 天按天展示。
- 将“外部或非可信 IP 使用公司域发件地址”单独标记为“匿名冒充公司域”。
- 自动归类不存在的收件人、内容过滤、SPF/DKIM/DMARC、IP 黑名单和中继限制等拒收原因。
- 显示 SFTP 最近成功同步时间和日志中的最新记录时间。
- 点击记录查看完整详情，并可将当前筛选结果导出为 CSV。
- 使用 SQLite 持久化日志索引，历史文件未改变时不再重复解析。
- “全部日志”分页展示所有已采集原始数据行；无法分类或解析异常的行也会保留。

## 前提条件

- Docker 主机能访问 Edge 服务器 TCP 22。
- Edge 已启用 Windows OpenSSH Server。
- 准备一个只能读取 Exchange 日志的 Windows 账号。
- 仪表盘含有邮件地址和主题，请勿直接暴露到公网。

## 1. Edge 服务器准备

以管理员身份打开 PowerShell：

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
New-NetFirewallRule -Name OpenSSH-Server-In-TCP -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

创建专用账号，并仅授予日志目录读取权限（账号名仅为示例）：

```powershell
net user edge_log_reader * /add
icacls "C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\Logs" /grant "edge_log_reader:(OI)(CI)RX"
```

`net user` 会互动询问密码。不要把真实密码写在命令历史中。

## 2. 创建运行文件

目录结构：

```text
exchange-edge-dashboard/
├── compose.yaml
├── .env
└── secrets/
    └── edge_password.txt
```

`compose.yaml`：

```yaml
services:
  exchange-edge-dashboard:
    image: synologyer/exchange-edge-mail-dashboard:latest
    container_name: exchange-edge-dashboard
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      TZ: ${TZ:-Asia/Shanghai}
      COMPANY_DOMAIN: ${COMPANY_DOMAIN:?set COMPANY_DOMAIN in .env}
      TRUSTED_EXCHANGE_IP: ${TRUSTED_EXCHANGE_IP:?set TRUSTED_EXCHANGE_IP in .env}
      EDGE_HOST: ${EDGE_HOST:?set EDGE_HOST in .env}
      EDGE_PORT: ${EDGE_PORT:-22}
      EDGE_USERNAME: ${EDGE_USERNAME:?set EDGE_USERNAME in .env}
      EDGE_PASSWORD_FILE: /run/secrets/edge_password
      EDGE_LOG_PATH: ${EDGE_LOG_PATH:-/C:/Program Files/Microsoft/Exchange Server/V15/TransportRoles/Logs}
      EDGE_HOST_KEY_SHA256: ${EDGE_HOST_KEY_SHA256:-}
      SFTP_SYNC_SECONDS: ${SFTP_SYNC_SECONDS:-60}
      BACKGROUND_INDEX_SECONDS: ${BACKGROUND_INDEX_SECONDS:-30}
      SFTP_HISTORY_DAYS: ${SFTP_HISTORY_DAYS:-0}
      CACHE_SECONDS: ${CACHE_SECONDS:-60}
      DATABASE_PATH: ${DATABASE_PATH:-/data/dashboard.db}
    secrets:
      - edge_password
    volumes:
      - ./data:/data

secrets:
  edge_password:
    file: ./secrets/edge_password.txt
```

`.env`：

```dotenv
TZ=Asia/Shanghai
COMPANY_DOMAIN=company.example
TRUSTED_EXCHANGE_IP=192.0.2.10
EDGE_HOST=192.0.2.11
EDGE_PORT=22
EDGE_USERNAME=edge_log_reader
EDGE_LOG_PATH=/C:/Program Files/Microsoft/Exchange Server/V15/TransportRoles/Logs
EDGE_HOST_KEY_SHA256=
SFTP_SYNC_SECONDS=10
BACKGROUND_INDEX_SECONDS=30
SFTP_HISTORY_DAYS=0
CACHE_SECONDS=10
```

- `COMPANY_DOMAIN`：公司真实发件域名，不要带 `@`。
- `TRUSTED_EXCHANGE_IP`：向 Edge 提交公司外发邮件的 Mailbox/Mail 服务器 IP，不是 Edge IP。
- `EDGE_HOST`：Edge 服务器 IP。
- `EDGE_USERNAME`：Windows 日志只读账号。

把只读账号密码写入 `secrets/edge_password.txt`，文件中只放一行密码。

## 3. 启动

```bash
mkdir -p data
chmod 777 data
docker compose pull
docker compose up -d
docker compose ps
docker compose logs --tail=100
```

浏览器打开 `http://<Docker主机IP>:8080`。

更新镜像：

```bash
docker compose pull
docker compose up -d
```

## 多 MX / Edge 集群模式

同一个面板可以同时通过 SFTP 读取多台 MX。每台 MX 使用独立账号、密码文件、SSH 指纹和日志路径；页面可按节点筛选，并按邮件标识对跨节点记录去重。

在 `.env` 中配置：

```dotenv
COMPANY_DOMAIN=company.example
TRUSTED_EXCHANGE_IPS=192.0.2.10,192.0.2.12
EDGE_NODES=mx1,mx2

MX1_HOST=192.0.2.11
MX1_PORT=22
MX1_USERNAME=edge_log_reader
MX1_PASSWORD_FILE=/run/edge-secrets/mx1_password.txt
MX1_HOST_KEY_SHA256=

MX2_HOST=192.0.2.21
MX2_PORT=22
MX2_USERNAME=edge_log_reader
MX2_PASSWORD_FILE=/run/edge-secrets/mx2_password.txt
MX2_HOST_KEY_SHA256=
```

密码分别保存为：

```text
secrets/mx1_password.txt
secrets/mx2_password.txt
```

节点名称会转成大写环境变量前缀，例如 `mx-01` 对应 `MX_01_HOST`。现有单节点 `EDGE_HOST` 配置继续兼容。

## 本地日志挂载模式

如果日志已经通过 SMB 或定时复制到 Docker 主机，可以不设置 `EDGE_HOST`，直接只读挂载：

```bash
docker run -d \
  --name exchange-edge-dashboard \
  --restart unless-stopped \
  -p 8080:8080 \
  -e TZ=Asia/Shanghai \
  -e COMPANY_DOMAIN=company.example \
  -e TRUSTED_EXCHANGE_IP=192.0.2.10 \
  -v /path/to/TransportRoles/Logs:/logs:ro \
  synologyer/exchange-edge-mail-dashboard:latest
```

## 主要环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `COMPANY_DOMAIN` | 必填 | 公司发件域名 |
| `TRUSTED_EXCHANGE_IP` | 必填 | 向 Edge 提交外发邮件的 Mail 服务器 IP |
| `TRUSTED_EXCHANGE_IPS` | 多节点时必填 | 可信 Mail 服务器 IP，多个用逗号分隔 |
| `EDGE_NODES` | 空 | MX 节点名称，多个用逗号分隔；为空时使用原单节点配置 |
| `<节点>_HOST` | 多节点时必填 | 对应 MX 的 SFTP 地址，例如 `MX1_HOST` |
| `<节点>_PORT` | `22` | 对应 MX 的 OpenSSH 端口 |
| `<节点>_USERNAME` | 多节点时必填 | 对应 MX 的日志只读账号 |
| `<节点>_PASSWORD_FILE` | 建议设置 | 对应 MX 的密码文件 |
| `<节点>_HOST_KEY_SHA256` | 空 | 对应 MX 的 SSH 主机密钥指纹 |
| `EDGE_HOST` | 空 | Edge SFTP IP；设置后启用 SFTP 模式 |
| `EDGE_PORT` | `22` | Edge OpenSSH 端口 |
| `EDGE_USERNAME` | 空 | Windows 日志只读账号 |
| `EDGE_PASSWORD` | 空 | SFTP 密码；建议使用密码文件 |
| `EDGE_PASSWORD_FILE` | 空 | Docker Secret 密码文件 |
| `EDGE_LOG_PATH` | `/C:/Program Files/.../Logs` | Windows OpenSSH 中的日志路径 |
| `EDGE_HOST_KEY_SHA256` | 空 | 可选的 SSH 主机密钥指纹 |
| `LOG_ROOT` | `/logs` | 本地挂载模式的日志根目录 |
| `SFTP_SYNC_SECONDS` | `60` | 从 Edge 重新检查日志的最小间隔秒数 |
| `BACKGROUND_INDEX_SECONDS` | `30` | 后台检查并更新 SQLite 索引的间隔秒数 |
| `SFTP_HISTORY_DAYS` | `0` | 首次同步历史天数；`0` 表示当前保留的全部日志 |
| `CACHE_SECONDS` | `60` | 后端缓存秒数 |
| `MAX_ROWS` | `10000` | API 最大记录数 |
| `DATABASE_PATH` | `/data/dashboard.db` | SQLite 持久化日志索引路径 |

## 历史日志索引

容器启动后会在后台静默同步所有节点当前保留的日志，把原始索引、统计摘要和已经分类、关联、去重的邮件事件分别保存到 `/data/dashboard.db`。网页读取轻量统计摘要，原始日志和分类事件均按每页 200 条查询，不会在点击 30 天时重新分析或一次传输全部明细。Compose 使用 `./data:/data` 保存数据库：

- 文件未改变时直接查询 SQLite，不重新解析原始日志。
- 当天仍在增长的日志文件发生变化时，只重新索引这些文件。
- 历史日志不变时持续复用数据库索引。
- 后台更新完成后一次性替换页面快照，查询期间不会读到半成品。
- 容器更新或重建后 `./data/dashboard.db` 继续保留。
- “全部日志”直接分页查询原始索引；分类标签显示后台整理后的邮件事件。
- 字段数量不一致、时间无法识别或缺少字段定义的数据行仍会以“解析异常”保存，可在详情中查看原文。

首次启动时数据会随着后台索引逐步出现。`SFTP_HISTORY_DAYS=0` 会同步 Edge 当前仍保留的全部日志；如果历史日志很多，也可以设置具体天数限制首次同步范围。

## 安全说明

- 镜像不内置真实域名、IP、账号或密码。
- 容器只需日志读取权限，不应获得日志写入权限。
- 建议在 Edge 防火墙中将 TCP 22 限制为仅 Docker 主机 IP 可访问。
