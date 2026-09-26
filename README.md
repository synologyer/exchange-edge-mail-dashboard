# Exchange Edge Mail Dashboard

Exchange Server 2019 Edge Transport 日志的只读 Web 仪表盘，支持最近 1/7/30 天的收件、发件、拒收、公司外发失败、系统退信和异常发件人。

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
    image: whc95800/exchange-edge-mail-dashboard:latest
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
      CACHE_SECONDS: ${CACHE_SECONDS:-60}
    secrets:
      - edge_password

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
CACHE_SECONDS=10
```

- `COMPANY_DOMAIN`：公司真实发件域名，不要带 `@`。
- `TRUSTED_EXCHANGE_IP`：向 Edge 提交公司外发邮件的 Mailbox/Mail 服务器 IP，不是 Edge IP。
- `EDGE_HOST`：Edge 服务器 IP。
- `EDGE_USERNAME`：Windows 日志只读账号。

把只读账号密码写入 `secrets/edge_password.txt`，文件中只放一行密码。

## 3. 启动

```bash
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
  whc95800/exchange-edge-mail-dashboard:latest
```

## 主要环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `COMPANY_DOMAIN` | 必填 | 公司发件域名 |
| `TRUSTED_EXCHANGE_IP` | 必填 | 向 Edge 提交外发邮件的 Mail 服务器 IP |
| `EDGE_HOST` | 空 | Edge SFTP IP；设置后启用 SFTP 模式 |
| `EDGE_PORT` | `22` | Edge OpenSSH 端口 |
| `EDGE_USERNAME` | 空 | Windows 日志只读账号 |
| `EDGE_PASSWORD` | 空 | SFTP 密码；建议使用密码文件 |
| `EDGE_PASSWORD_FILE` | 空 | Docker Secret 密码文件 |
| `EDGE_LOG_PATH` | `/C:/Program Files/.../Logs` | Windows OpenSSH 中的日志路径 |
| `EDGE_HOST_KEY_SHA256` | 空 | 可选的 SSH 主机密钥指纹 |
| `LOG_ROOT` | `/logs` | 本地挂载模式的日志根目录 |
| `SFTP_SYNC_SECONDS` | `60` | 从 Edge 重新检查日志的最小间隔秒数 |
| `CACHE_SECONDS` | `60` | 后端缓存秒数 |
| `MAX_ROWS` | `10000` | API 最大记录数 |

## 安全说明

- 镜像不内置真实域名、IP、账号或密码。
- 容器只需日志读取权限，不应获得日志写入权限。
- 建议在 Edge 防火墙中将 TCP 22 限制为仅 Docker 主机 IP 可访问。
