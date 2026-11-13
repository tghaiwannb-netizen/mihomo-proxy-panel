# mihomo-hub（服务器端）

代理控制台的服务器端 + 安装包下载门户，零依赖 Python 3 服务。
主域名 `https://acis-vpn.jizhang.org`（下载门户），`https://mihomo.jizhang.org` 作为别名保留给旧版控制台。

```
浏览器 → 本机面板 /auth/login → hub /login → auth.jizhang.org 登录
      → hub /auth/callback（换 token，判断邮箱权限）→ 面板 /auth/finish?ticket=…
      → 面板向 hub 兑换 ticket，拿到 Bearer token
```

- **登录**：OIDC 授权码 + PKCE，`client_secret` 只在服务器 `hub.env`。
- **权限**：`ADMIN_EMAILS` 里的邮箱是管理员；其他邮箱必须由管理员在面板「账号」页授权。
  移除后对方的 token 立即失效。
- **代理账号**：每个邮箱对应一组 7891 代理账号密码，存在 `/var/lib/mihomo-hub/users.json`。
- **文件下发**：`/opt/mihomo-hub/files/` 下的文件会被管理员的面板按 sha256 同步：
  - `config.yaml` → 本地 `mihomo/config.base.yaml`（面板在上面注入账号块生成 `config.yaml`）
  - `mihomo-windows-amd64.exe` → 本地内核（运行中被占用时，下次启动内核前替换）
  - 换订阅、换规则、升级内核：直接替换这个目录里的文件即可，面板 30 分钟内自动同步，也可点「立即同步」。

## 部署

| 路径 | 说明 |
|---|---|
| `/opt/mihomo-hub/hub.py` | 服务 |
| `/opt/mihomo-hub/hub.env` | 配置（600，含 client_secret），模板见 `hub.env.example` |
| `/opt/mihomo-hub/files/` | 下发文件 |
| `/var/lib/mihomo-hub/` | 数据（systemd `DynamicUser` + `StateDirectory`） |
| `/etc/systemd/system/mihomo-hub.service` | 服务单元 |
| `/www/server/panel/vhost/nginx/mihomo.jizhang.org.conf` | 反代 127.0.0.1:8097 |

auth 客户端 `mihomo-panel` 已注册在 auth.jizhang.org，回调地址
`https://mihomo.jizhang.org/auth/callback`，scope `openid profile email`。

```bash
sudo systemctl restart mihomo-hub
curl -s https://mihomo.jizhang.org/healthz
```

## 下载门户

`https://acis-vpn.jizhang.org/`：用墨清账户登录，管理员和被授权的邮箱可以下载
`/opt/mihomo-hub/packages/` 里的安装包；`packages.json` 写标题、说明、排序、`adminOnly`。

重新打包（拉 fork 的 `auth-jizhang-hub` 分支 + 官方 Node.js 22 + 下发目录里的内核和模板）：

```bash
sudo python3 -I /opt/mihomo-hub/build_package.py
```
