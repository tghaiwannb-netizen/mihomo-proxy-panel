#!/usr/bin/env python3
"""
一键部署 / 更新 acis-vpn.jizhang.org（下载门户 + hub）。可重复执行。

在服务器上（需要 root）：
  git clone -b auth-jizhang-hub https://github.com/tghaiwannb-netizen/mihomo-proxy-panel /opt/mihomo-hub/src  # 首次
  sudo python3 -I /opt/mihomo-hub/src/hub/deploy/deploy_acis.py

步骤：
  1. 更新 /opt/mihomo-hub/src 到 auth-jizhang-hub 最新提交，安装 hub.py、build_package.py
  2. hub.env：PUBLIC_URL 加上 acis-vpn，补 PACKAGES_DIR / WEB_HOURS（保留原 client_secret）
  3. 备份 auth 库，给 mihomo-panel 客户端加回调 https://acis-vpn.jizhang.org/auth/callback
  4. nginx 新增 acis-vpn.jizhang.org 站点，nginx -t 通过才 reload（失败自动回滚）
  5. 打 Windows 安装包
  6. 重启 mihomo-hub 并自检
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HUB = Path("/opt/mihomo-hub")
SRC = HUB / "src"
REPO = "https://github.com/tghaiwannb-netizen/mihomo-proxy-panel.git"
REF = "auth-jizhang-hub"
AUTH_DIR = Path("/www/JiZhangBen/WEB/auth")
CLIENT_ID = "mihomo-panel"
DOMAIN = "acis-vpn.jizhang.org"
PUBLIC_URL = f"https://{DOMAIN},https://mihomo.jizhang.org"
CALLBACKS = [f"https://{DOMAIN}/auth/callback", "https://mihomo.jizhang.org/auth/callback"]
VHOST = Path(f"/www/server/panel/vhost/nginx/{DOMAIN}.conf")
TS = time.strftime("%Y%m%d-%H%M%S")
# 站点的扫描防护会拦 Python 默认 UA，自检时用面板同款 UA
UA = {"User-Agent": "mihomo-panel/2.0"}

NGINX = f"""server {{
    listen 80;
    listen [::]:80;
    server_name {DOMAIN};
    include /www/server/panel/vhost/nginx/jizhang_scanner_guard.inc;
    return 301 https://{DOMAIN}$request_uri;
}}

server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name {DOMAIN};
    include /www/server/panel/vhost/nginx/jizhang_scanner_guard.inc;
    server_tokens off;

    ssl_certificate     /etc/nginx/ssl/jizhang.crt;
    ssl_certificate_key /etc/nginx/ssl/jizhang.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_session_tickets off;

    client_max_body_size 1m;

    location / {{
        proxy_pass http://127.0.0.1:8097;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_buffering off;
    }}
}}
"""

UNIT = """[Unit]
Description=mihomo-hub (ACIS portal, panel login & file distribution)
After=network-online.target

[Service]
Type=simple
DynamicUser=yes
StateDirectory=mihomo-hub
EnvironmentFile=/opt/mihomo-hub/hub.env
Environment=HUB_ENV=/nonexistent
ExecStart=/usr/bin/python3 -I /opt/mihomo-hub/hub.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""


def run(*cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    print("$", " ".join(cmd))
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def step(title: str) -> None:
    print(f"\n== {title}")


def env_file(p: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def main() -> None:
    step("1. 更新代码")
    if not (SRC / ".git").exists():
        run("git", "clone", "--quiet", REPO, str(SRC))
    run("git", "-C", str(SRC), "fetch", "--quiet", "origin", REF)
    run("git", "-C", str(SRC), "checkout", "--quiet", "--force", "FETCH_HEAD")
    commit = run("git", "-C", str(SRC), "rev-parse", "--short", "HEAD").stdout.strip()
    print("commit", commit)
    for name in ("hub.py", "build_package.py"):
        dst = HUB / name
        if dst.exists():
            shutil.copy2(dst, f"{dst}.bak.{TS}")
        shutil.copy2(SRC / "hub" / name, dst)
        dst.chmod(0o644)
    (HUB / "packages").mkdir(exist_ok=True)

    step("2. hub.env")
    env_path = HUB / "hub.env"
    env = env_file(env_path)
    if not env.get("AUTH_CLIENT_SECRET"):
        sys.exit("hub.env 里没有 AUTH_CLIENT_SECRET，请先跑过首次安装")
    shutil.copy2(env_path, f"{env_path}.bak.{TS}")
    env["PUBLIC_URL"] = PUBLIC_URL
    env.setdefault("PACKAGES_DIR", str(HUB / "packages"))
    env.setdefault("WEB_HOURS", "72")
    env_path.write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    env_path.chmod(0o600)
    print("PUBLIC_URL =", PUBLIC_URL)

    step("3. auth 回调地址")
    auth_env = env_file(AUTH_DIR / "auth.env")
    raw = (auth_env.get("DB_URL") or auth_env.get("DATABASE_URL") or "")[len("sqlite:///"):]
    cands = [Path(raw)] if raw.startswith("/") else [(AUTH_DIR / raw).resolve(), (AUTH_DIR / "app" / raw).resolve()]
    db = next(p for p in cands if p.exists())
    shutil.copy2(db, f"{db}.bak.acis-{TS}")
    print("备份", f"{db}.bak.acis-{TS}")
    conn = sqlite3.connect(db, timeout=10)
    try:
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT redirect_uris_json FROM client_apps WHERE client_id=?", (CLIENT_ID,)).fetchone()
        if not row:
            sys.exit(f"auth 里没有客户端 {CLIENT_ID}")
        uris = json.loads(row[0] or "[]")
        for u in CALLBACKS:
            if u not in uris:
                uris.append(u)
        conn.execute("UPDATE client_apps SET redirect_uris_json=? WHERE client_id=?", (json.dumps(uris), CLIENT_ID))
        conn.commit()
        print("redirect_uris =", uris)
    finally:
        conn.close()

    step("4. systemd + nginx")
    Path("/etc/systemd/system/mihomo-hub.service").write_text(UNIT)
    run("systemctl", "daemon-reload")
    old = VHOST.read_text() if VHOST.exists() else None
    VHOST.write_text(NGINX)
    t = run("nginx", "-t", check=False)
    if t.returncode != 0:
        print(t.stderr)
        if old is None:
            VHOST.unlink()
        else:
            VHOST.write_text(old)
        sys.exit("nginx -t 失败，已回滚站点配置")
    run("systemctl", "reload", "nginx")

    step("5. 打包")
    b = run(sys.executable, "-I", str(HUB / "build_package.py"), "--src", str(SRC), "--ref", REF, check=False)
    print(b.stdout.strip())
    if b.returncode != 0:
        print(b.stderr.strip())
        print("!! 打包失败（门户照常上线，稍后可单独重跑 build_package.py）")

    step("6. 重启并自检")
    run("systemctl", "restart", "mihomo-hub")
    time.sleep(1.5)
    print("mihomo-hub:", run("systemctl", "is-active", "mihomo-hub", check=False).stdout.strip())
    ok = True
    for url, expect in [
        ("http://127.0.0.1:8097/healthz", 200),
        (f"https://{DOMAIN}/healthz", 200),
        (f"https://{DOMAIN}/", 200),
    ]:
        try:
            code = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=15).status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception as e:  # noqa: BLE001
            code = repr(e)
        print(f"{url} -> {code}")
        ok &= code == expect

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(urllib.request.Request(f"https://{DOMAIN}/web/login", headers=UA), timeout=15)
        loc = ""
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location", "")
    print("登录跳转 ->", loc[:120])
    ok &= f"redirect_uri=https%3A%2F%2F{DOMAIN}%2Fauth%2Fcallback" in loc
    if ok:
        try:
            opener.open(urllib.request.Request(loc, headers=UA), timeout=15)
            loc2 = ""
        except urllib.error.HTTPError as e:
            loc2 = e.headers.get("Location", "") if e.code in (301, 302, 303, 307) else f"HTTP {e.code}"
        print("auth 接受 ->", loc2[:80])
        ok &= "/login?tx=" in loc2
    print("\n部署", "成功" if ok else "有问题，请看上面输出", f"(commit {commit})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
