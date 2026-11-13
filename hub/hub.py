#!/usr/bin/env python3
"""
mihomo-hub —— 代理控制台的服务器端（零依赖，仅用 Python 标准库）

职责：
  1. 登录中转：对接 auth.jizhang.org（OIDC 授权码 + PKCE），client_secret 只留在服务器
  2. 账号：管理员邮箱写在配置里；子账号（邮箱 + 代理账号密码）保存在服务器
  3. 文件下发：mihomo 配置模板、内核等文件放在 FILES_DIR，由本地面板按清单拉取

本地面板流程：
  面板 /auth/login  ->  hub /login?return=<面板>/auth/finish&state=<s>
  -> auth.jizhang.org 登录 -> hub /auth/callback -> 回跳面板 ?ticket=..&state=..
  -> 面板 POST hub /api/ticket/redeem 换取 hub token（Bearer）
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ------------------------------------------------------------------ config


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


ROOT = Path(__file__).resolve().parent
load_env(Path(os.environ.get("HUB_ENV", ROOT / "hub.env")))

AUTH_BASE = os.environ.get("AUTH_BASE_URL", "https://auth.jizhang.org").rstrip("/")
CLIENT_ID = os.environ.get("AUTH_CLIENT_ID", "mihomo-panel")
CLIENT_SECRET = os.environ.get("AUTH_CLIENT_SECRET", "")
# 可配置多个域名（逗号分隔），第一个为主域名；回调地址按访问的域名选择，每个都要在 auth 里登记
PUBLIC_URLS = [u.strip().rstrip("/") for u in os.environ.get("PUBLIC_URL", "https://acis-vpn.jizhang.org").split(",") if u.strip()]
PUBLIC_URL = PUBLIC_URLS[0]
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()}
HOST = os.environ.get("HUB_HOST", "127.0.0.1")
PORT = int(os.environ.get("HUB_PORT", "8097"))
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))
FILES_DIR = Path(os.environ.get("FILES_DIR", ROOT / "files"))
# 下载门户里的安装包；packages.json 可选，给每个包写标题和说明
PACKAGES_DIR = Path(os.environ.get("PACKAGES_DIR", ROOT / "packages"))
WEB_HOURS = int(os.environ.get("WEB_HOURS", "72"))
TOKEN_DAYS = int(os.environ.get("TOKEN_DAYS", "30"))
SECRET_FILE = DATA_DIR / ".hub-secret"
USERS_FILE = DATA_DIR / "users.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
FILES_DIR.mkdir(parents=True, exist_ok=True)
PACKAGES_DIR.mkdir(parents=True, exist_ok=True)

if SECRET_FILE.exists():
    SIGN_KEY = SECRET_FILE.read_bytes()
else:
    SIGN_KEY = secrets.token_bytes(32)
    SECRET_FILE.write_bytes(SIGN_KEY)
    os.chmod(SECRET_FILE, 0o600)

LOCK = threading.Lock()
PENDING: dict[str, dict] = {}  # hub state -> {verifier, return, pstate, exp}
TICKETS: dict[str, dict] = {}  # ticket -> {email, name, exp}

# ------------------------------------------------------------------ helpers


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_dec(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(payload: dict) -> str:
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64url(hmac.new(SIGN_KEY, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify(token: str) -> dict | None:
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    expect = b64url(hmac.new(SIGN_KEY, body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expect):
        return None
    try:
        data = json.loads(b64url_dec(body))
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("exp", 0) < time.time():
        return None
    return data


def gc() -> None:
    now = time.time()
    for store in (PENDING, TICKETS):
        for k in [k for k, v in store.items() if v["exp"] < now]:
            store.pop(k, None)


def random_password(n: int = 12) -> str:
    alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,}$")
PROXY_USER_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")


def valid_proxy_pass(v: object) -> bool:
    return isinstance(v, str) and 6 <= len(v) <= 64 and not re.search(r"[\r\n'\"]", v)


# ------------------------------------------------------------------ users store
# users.json: {"users": [{"email","proxyUser","proxyPass","created"}]}
# 管理员也会有一条记录（首次登录自动创建），用于 7891 代理鉴权。


def load_users() -> dict:
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    return {"users": []}


def save_users(data: dict) -> None:
    tmp = USERS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(USERS_FILE)


def role_of(email: str) -> str | None:
    email = email.lower()
    if email in ADMIN_EMAILS:
        return "admin"
    if any(u["email"] == email for u in load_users()["users"]):
        return "user"
    return None


def proxy_name_from_email(email: str, taken: set[str]) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "", email.split("@", 1)[0])[:24] or "user"
    if len(base) < 3:
        base = (base + "user")[:6]
    name, i = base, 2
    while name.lower() in taken:
        name = f"{base}{i}"
        i += 1
    return name


def ensure_record(email: str) -> dict:
    """返回该邮箱的记录；管理员没有记录时自动创建。"""
    email = email.lower()
    with LOCK:
        data = load_users()
        for u in data["users"]:
            if u["email"] == email:
                return u
        taken = {u["proxyUser"].lower() for u in data["users"]}
        rec = {
            "email": email,
            "proxyUser": proxy_name_from_email(email, taken),
            "proxyPass": random_password(),
            "created": int(time.time() * 1000),
        }
        data["users"].append(rec)
        save_users(data)
        return rec


def public_user(u: dict) -> dict:
    return {
        "email": u["email"],
        "role": "admin" if u["email"] in ADMIN_EMAILS else "user",
        "proxyUser": u["proxyUser"],
        "proxyPass": u["proxyPass"],
        "created": u.get("created", 0),
    }


# ------------------------------------------------------------------ files


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


_hash_cache: dict[str, tuple[float, int, str]] = {}


def manifest() -> list[dict]:
    out = []
    for p in sorted(FILES_DIR.iterdir()):
        if not p.is_file() or p.name.startswith("."):
            continue
        st = p.stat()
        cached = _hash_cache.get(p.name)
        if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
            digest = cached[2]
        else:
            digest = sha256_file(p)
            _hash_cache[p.name] = (st.st_mtime, st.st_size, digest)
        out.append({"name": p.name, "size": st.st_size, "sha256": digest, "mtime": int(st.st_mtime)})
    return out


def package_list() -> list[dict]:
    meta_file = PACKAGES_DIR / "packages.json"
    try:
        meta = json.loads(meta_file.read_text(encoding="utf-8")) if meta_file.exists() else {}
    except ValueError:
        meta = {}
    out = []
    for p in sorted(PACKAGES_DIR.iterdir(), key=lambda x: x.name):
        if not p.is_file() or p.name.startswith(".") or p.name == "packages.json":
            continue
        st = p.stat()
        key = "pkg:" + p.name
        cached = _hash_cache.get(key)
        if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
            digest = cached[2]
        else:
            digest = sha256_file(p)
            _hash_cache[key] = (st.st_mtime, st.st_size, digest)
        m = meta.get(p.name, {})
        out.append(
            {
                "name": p.name,
                "title": m.get("title") or p.name,
                "desc": m.get("desc") or "",
                "order": m.get("order", 100),
                "adminOnly": bool(m.get("adminOnly")),
                "size": st.st_size,
                "sha256": digest,
                "mtime": int(st.st_mtime),
            }
        )
    out.sort(key=lambda x: (x["order"], x["name"]))
    return out


def fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


# ------------------------------------------------------------------ return url
# 面板跑在用户自己的电脑上，只允许回跳到本机 / 局域网地址，防止被拿去做开放重定向。


def valid_return(url: str) -> bool:
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if p.scheme != "http" or not p.hostname or p.username or p.password or p.fragment:
        return False
    if p.path != "/auth/finish" or p.query:
        return False
    host = p.hostname
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        # Windows 主机名（不带点），或 localhost / *.local
        return host == "localhost" or host.endswith(".local") or bool(re.fullmatch(r"[A-Za-z0-9-]{1,63}", host))


# ------------------------------------------------------------------ oauth


def exchange_code(code: str, verifier: str, redirect_uri: str) -> dict:
    form = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
    ).encode()
    req = urllib.request.Request(
        AUTH_BASE + "/oauth/token",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


# ------------------------------------------------------------------ site（官网 / 下载门户）

SITE_CSS = """
:root{--bg:#fbfaf8;--surface:#fff;--line:#ebe7e1;--ink:#1c1917;--ink-2:#57534e;--muted:#8a847d;
--accent:#b4532a;--accent-ink:#fff;--accent-soft:#f6ece6;--ok:#2f7d4f;--radius:14px}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#141211;--surface:#1c1a18;--line:#2c2926;
--ink:#f2efeb;--ink-2:#bdb6ae;--muted:#8d867e;--accent:#e07a4b;--accent-ink:#1a0e08;--accent-soft:#2a1d17;--ok:#5cc28a}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei","Segoe UI",sans-serif;
-webkit-font-smoothing:antialiased;min-height:100vh;display:flex;flex-direction:column}
a{color:inherit}
.container{width:100%;max-width:960px;margin:0 auto;padding:0 16px}
.nav{height:64px;display:flex;align-items:center;gap:12px}
.logo{display:flex;align-items:center;gap:10px;text-decoration:none;font-weight:650;letter-spacing:.3px}
.logo i{width:28px;height:28px;border-radius:8px;background:var(--accent);color:var(--accent-ink);display:grid;place-items:center}
.nav .sp{flex:1}
.nav .who{font-size:13px;color:var(--ink-2);display:flex;align-items:center;gap:12px;min-width:0}
.nav .who span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:220px}
.tag{font-style:normal;font-size:11.5px;padding:2px 8px;border-radius:999px;background:var(--accent-soft);color:var(--accent);font-weight:600;flex:none}
main{flex:1}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;height:44px;padding:0 20px;border-radius:10px;border:1px solid transparent;
background:var(--accent);color:var(--accent-ink);font:600 14.5px/1 inherit;text-decoration:none;cursor:pointer;white-space:nowrap;transition:filter .15s}
.btn:hover{filter:brightness(1.06)}.btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.btn.quiet{background:transparent;color:var(--ink-2);border-color:var(--line);height:34px;padding:0 12px;font-size:13px;font-weight:500}
.btn.quiet:hover{color:var(--ink);filter:none;border-color:var(--muted)}
.btn svg{width:16px;height:16px}
.hero{padding:72px 0 56px}
.eyebrow{font-size:13px;color:var(--accent);font-weight:600;letter-spacing:.4px;margin:0 0 14px}
.hero h1{font-size:clamp(30px,5vw,46px);line-height:1.15;letter-spacing:-.5px;margin:0 0 16px;font-weight:700}
.hero p.lead{font-size:17px;color:var(--ink-2);max-width:540px;margin:0 0 28px}
.hero .actions{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.hero .note{font-size:13px;color:var(--muted)}
.features{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;margin-bottom:72px}
.feature{background:var(--surface);padding:22px 22px 24px}
.feature b{display:block;font-size:15px;margin-bottom:6px}.feature span{color:var(--ink-2);font-size:14px}
.feature svg{width:20px;height:20px;color:var(--accent);margin-bottom:12px}
.section-title{font-size:13px;color:var(--muted);font-weight:600;letter-spacing:.4px;margin:0 0 12px}
.page-head{padding:44px 0 24px}.page-head h1{font-size:28px;margin:0 0 6px;letter-spacing:-.3px}.page-head p{margin:0;color:var(--ink-2)}
.list{border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);overflow:hidden;margin-bottom:36px}
.item{display:flex;align-items:center;gap:16px;padding:18px 20px}.item+.item{border-top:1px solid var(--line)}
.item .ic{width:40px;height:40px;border-radius:10px;background:var(--accent-soft);color:var(--accent);display:grid;place-items:center;flex:none}
.item .ic svg{width:20px;height:20px}
.item .body{flex:1;min-width:0}.item h3{margin:0;font-size:15.5px;font-weight:600}
.item p{margin:2px 0 0;font-size:13.5px;color:var(--ink-2)}
.item .meta{margin-top:6px;font-size:12.5px;color:var(--muted);display:flex;gap:6px 14px;flex-wrap:wrap}
.hash{font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:none;border:0;padding:0;color:var(--muted);cursor:pointer;text-decoration:underline dotted;text-underline-offset:3px}
.hash:hover{color:var(--ink)}
.steps{list-style:none;margin:0 0 72px;padding:0;display:grid;grid-template-columns:repeat(4,1fr);gap:12px;counter-reset:s}
.steps li{counter-increment:s;padding:18px;border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);font-size:14px;color:var(--ink-2)}
.steps li::before{content:counter(s);display:grid;place-items:center;width:24px;height:24px;border-radius:50%;background:var(--accent-soft);color:var(--accent);font-weight:700;font-size:12.5px;margin-bottom:10px}
.steps b{color:var(--ink);font-weight:600}
code{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--accent-soft);color:var(--ink);padding:1px 6px;border-radius:5px}
.notice{max-width:440px;margin:12vh auto 0;text-align:center}
.notice h1{font-size:24px;margin:0 0 10px}.notice p{color:var(--ink-2);margin:0 0 6px}.notice .btn{margin-top:20px}
.alert{border:1px solid var(--line);background:var(--accent-soft);color:var(--ink);border-radius:10px;padding:10px 14px;font-size:14px;margin:0 0 20px;max-width:540px}
.empty{padding:36px 20px;text-align:center;color:var(--muted)}
footer{border-top:1px solid var(--line);margin-top:auto}
footer .container{height:60px;display:flex;align-items:center;justify-content:space-between;font-size:12.5px;color:var(--muted);gap:12px}
form{margin:0}
@media (max-width:760px){.features{grid-template-columns:1fr}.steps{grid-template-columns:1fr 1fr}.hero{padding:44px 0 40px}}
@media (max-width:520px){.steps{grid-template-columns:1fr}.item{flex-wrap:wrap}.item .btn{width:100%}.nav .who span{max-width:120px}}
"""

ICON = {
    "logo": '<svg viewBox="0 0 24 24" width="16" height="16" fill="none"><circle cx="6" cy="12" r="2.4" fill="currentColor"/><circle cx="18" cy="6" r="2.4" fill="currentColor"/><circle cx="18" cy="18" r="2.4" fill="currentColor"/><path d="M8.2 10.9 15.8 7M8.2 13.1 15.8 17" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
    "arrow": '<svg viewBox="0 0 24 24" fill="none"><path d="M5 12h13m-5-6 6 6-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    "down": '<svg viewBox="0 0 24 24" fill="none"><path d="M12 4v11m-5-5 5 5 5-5M5 20h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    "box": '<svg viewBox="0 0 24 24" fill="none"><path d="M4 7.5 12 3l8 4.5v9L12 21l-8-4.5v-9Z M4 7.5l8 4.5 8-4.5M12 12v9" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>',
    "bolt": '<svg viewBox="0 0 24 24" fill="none"><path d="M13 3 5 14h6l-1 7 8-11h-6l1-7Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>',
    "lock": '<svg viewBox="0 0 24 24" fill="none"><rect x="5" y="10.5" width="14" height="10" rx="2.5" stroke="currentColor" stroke-width="1.6"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5" stroke="currentColor" stroke-width="1.6"/></svg>',
    "wifi": '<svg viewBox="0 0 24 24" fill="none"><path d="M2.5 9a14 14 0 0 1 19 0M6 12.6a9 9 0 0 1 12 0M9.5 16.1a4 4 0 0 1 5 0" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="12" cy="19.4" r="1.2" fill="currentColor"/></svg>',
}

SITE_JS = """document.addEventListener('click',function(e){var b=e.target.closest('[data-copy]');if(!b||!navigator.clipboard)return;
navigator.clipboard.writeText(b.dataset.copy).then(function(){var t=b.textContent;b.textContent='已复制完整 SHA256';setTimeout(function(){b.textContent=t},1400)})});"""


def site_page(title: str, inner: str, who: tuple[str, str] | None = None, nav_login: bool = True) -> bytes:
    if who:
        email, role = who
        tag = '<em class="tag">管理员</em>' if role == "admin" else ""
        right = (f'<div class="who">{tag}<span title="{html.escape(email)}">{html.escape(email)}</span>'
                 '<form method="post" action="/web/logout"><button class="btn quiet" type="submit">退出</button></form></div>')
    elif nav_login:
        right = '<a class="btn quiet" href="/web/login">登录</a>'
    else:
        right = ""
    year = time.strftime("%Y")
    doc = f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex"><title>{html.escape(title)}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='6' fill='%23b4532a'/%3E%3Ccircle cx='8' cy='12' r='2' fill='white'/%3E%3Ccircle cx='16' cy='7.5' r='2' fill='white'/%3E%3Ccircle cx='16' cy='16.5' r='2' fill='white'/%3E%3C/svg%3E">
<style>{SITE_CSS}</style></head><body>
<header class="container nav"><a class="logo" href="/"><i>{ICON["logo"]}</i>ACIS</a><span class="sp"></span>{right}</header>
<main class="container">{inner}</main>
<footer><div class="container"><span>© {year} ACIS</span><span>账户由 auth.jizhang.org 提供</span></div></footer>
<script>{SITE_JS}</script></body></html>"""
    return doc.encode()


def site_landing(error: str = "") -> str:
    alert = f'<p class="alert">{html.escape(error)}</p>' if error else ""
    feats = [
        ("bolt", "解压即用", "内置运行时和内核，双击安装，无需配置环境。"),
        ("lock", "账户登录", "墨清账户统一登录，仅授权邮箱可用，随时收回。"),
        ("wifi", "局域网共享", "一台电脑安装，同网络的手机和电脑都能接入。"),
    ]
    feat_html = "".join(f'<div class="feature">{ICON[i]}<b>{t}</b><span>{d}</span></div>' for i, t, d in feats)
    return f"""<section class="hero"><p class="eyebrow">ACIS 代理</p>
<h1>一个安装包，<br>整个局域网都能用。</h1>
<p class="lead">Windows 客户端带网页控制台：一键开关、切换节点、查看流量，并给同一网络的设备分发独立账号。</p>
{alert}<div class="actions"><a class="btn" href="/web/login">登录并下载{ICON["arrow"]}</a>
<span class="note">需要被授权的墨清账户</span></div></section>
<section class="features">{feat_html}</section>"""


def site_downloads(role: str) -> str:
    rows = []
    for p in package_list():
        if p["adminOnly"] and role != "admin":
            continue
        when = time.strftime("%Y-%m-%d", time.localtime(p["mtime"]))
        desc = f'<p>{html.escape(p["desc"])}</p>' if p["desc"] else ""
        rows.append(f"""<div class="item"><span class="ic">{ICON["box"]}</span><div class="body"><h3>{html.escape(p["title"])}</h3>{desc}
<div class="meta"><span>{fmt_size(p["size"])}</span><span>{when}</span>
<button class="hash" type="button" data-copy="{p["sha256"]}" title="复制完整 SHA256">SHA256 {p["sha256"][:12]}</button></div></div>
<a class="btn" href="/dl/{urllib.parse.quote(p["name"])}" download>{ICON["down"]}下载</a></div>""")
    body = "".join(rows) or '<div class="empty">暂时没有可下载的安装包</div>'
    return f"""<section class="page-head"><h1>下载</h1><p>Windows 10 / 11，64 位。</p></section>
<div class="list">{body}</div>
<p class="section-title">安装步骤</p>
<ol class="steps">
<li><b>解压</b><br>放到任意目录，建议纯英文路径。</li>
<li><b>双击 安装.bat</b><br>创建桌面快捷方式并打开控制台。</li>
<li><b>登录</b><br>控制台里用授权邮箱登录墨清账户。</li>
<li><b>开启</b><br>概览页打开开关即可。其他设备访问 <code>本机IP:8080</code>。</li>
</ol>"""


def site_notice(title: str, lines: list[str], back: str = "返回首页") -> str:
    ps = "".join(f"<p>{x}</p>" for x in lines)
    return f'<div class="notice"><h1>{html.escape(title)}</h1>{ps}<a class="btn quiet" href="/">{html.escape(back)}</a></div>'


# ------------------------------------------------------------------ handler


class Handler(BaseHTTPRequestHandler):
    server_version = "mihomo-hub"
    sys_version = ""

    def log_message(self, fmt, *args):  # noqa: D401
        sys.stderr.write("%s %s\n" % (self.headers.get("X-Real-IP") or self.client_address[0], fmt % args))

    # ---- io
    def send(self, status: int, body, ctype="application/json; charset=utf-8", headers=None):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def html(self, status: int, title: str, body: str):
        # body 是一段或多段 <p>…</p>
        lines = re.findall(r"<p>(.*?)</p>", body, re.S) or [body]
        self.send(status, site_page(title, site_notice(title, lines), nav_login=False), "text/html; charset=utf-8")

    def redirect(self, url: str):
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def body_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > 64 * 1024:
            raise ValueError("body too large")
        raw = self.rfile.read(n) if n else b"{}"
        data = json.loads(raw or b"{}")
        if not isinstance(data, dict):
            raise ValueError("bad json")
        return data

    def auth(self) -> tuple[str, str] | None:
        h = self.headers.get("Authorization", "")
        if not h.lower().startswith("bearer "):
            return None
        data = verify(h.split(" ", 1)[1].strip())
        if not data or data.get("t") != "api":
            return None
        email = str(data.get("e", "")).lower()
        role = role_of(email)  # 每次都按当前名单判断，删除子账号立即失效
        return (email, role) if role else None

    # ---- routing
    def do_GET(self):
        self.route("GET")

    def do_HEAD(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_DELETE(self):
        self.route("DELETE")

    def base_url(self) -> str:
        host = (self.headers.get("Host") or "").lower()
        for u in PUBLIC_URLS:
            if urllib.parse.urlsplit(u).netloc.lower() == host:
                return u
        return PUBLIC_URL

    def web_session(self) -> tuple[str, str] | None:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "acis":
                data = verify(v)
                if data and data.get("t") == "web":
                    email = str(data.get("e", "")).lower()
                    role = role_of(email)
                    return (email, role) if role else None
        return None

    def portal(self, status: int, title: str, inner: str, who=None, headers=None):
        self.send(status, site_page(title, inner, who), "text/html; charset=utf-8", headers)

    def route(self, method: str):
        gc()
        url = urllib.parse.urlsplit(self.path)
        path, qs = url.path, urllib.parse.parse_qs(url.query)
        q = lambda k: (qs.get(k) or [""])[0]  # noqa: E731
        try:
            if method == "GET" and path == "/":
                who = self.web_session()
                if not who:
                    return self.portal(200, "ACIS 代理", site_landing(q("error")))
                return self.portal(200, "下载 · ACIS 代理", site_downloads(who[1]), who)
            if method == "GET" and path == "/healthz":
                return self.send(200, {"ok": True})
            if method == "GET" and path == "/web/login":
                return self.start_login(mode="web")
            if method == "POST" and path == "/web/logout":
                return self.send_redirect("/", {"Set-Cookie": "acis=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"})
            m = re.fullmatch(r"/dl/([A-Za-z0-9._()+-]{1,160})", path)
            if method == "GET" and m:
                return self.download(urllib.parse.unquote(m.group(1)))
            if method == "GET" and path == "/login":
                return self.login(q("return"), q("state"))
            if method == "GET" and path == "/auth/callback":
                return self.callback(q("code"), q("state"), q("error"))
            if method == "POST" and path == "/api/ticket/redeem":
                return self.redeem()
            if path.startswith("/api/"):
                return self.api(method, path)
            return self.send(404, {"error": "not found"})
        except Exception as e:  # pragma: no cover
            sys.stderr.write(f"error {path}: {e!r}\n")
            return self.send(500, {"error": "服务器内部错误"})

    def send_redirect(self, url: str, headers=None):
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def download(self, name: str):
        who = self.web_session()
        if not who:
            return self.send_redirect("/")
        pkg = next((p for p in package_list() if p["name"] == name), None)
        if not pkg or (pkg["adminOnly"] and who[1] != "admin"):
            return self.portal(404, "没有这个文件", site_notice("没有这个文件", ["文件不存在，或你没有下载权限。"]), who)
        f = PACKAGES_DIR / name
        sys.stderr.write(f"download {name} by {who[0]}\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(f.stat().st_size))
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote(name))
        self.send_header("Cache-Control", "private, no-store")
        self.end_headers()
        if self.command != "HEAD":
            with f.open("rb") as fh:
                while chunk := fh.read(1 << 16):
                    self.wfile.write(chunk)
        return None

    # ---- login
    def start_login(self, mode: str, ret: str = "", pstate: str = ""):
        if not CLIENT_SECRET:
            return self.html(503, "未配置", "<p>hub 尚未配置 <code>AUTH_CLIENT_SECRET</code>。</p>")
        redirect_uri = self.base_url() + "/auth/callback"
        verifier = b64url(secrets.token_bytes(48))
        challenge = b64url(hashlib.sha256(verifier.encode()).digest())
        hstate = b64url(secrets.token_bytes(24))
        with LOCK:
            PENDING[hstate] = {
                "verifier": verifier,
                "mode": mode,
                "return": ret,
                "pstate": pstate,
                "redirect_uri": redirect_uri,
                "exp": time.time() + 600,
            }
        params = urllib.parse.urlencode(
            {
                "client_id": CLIENT_ID,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "openid profile email",
                "state": hstate,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return self.redirect(f"{AUTH_BASE}/oauth/authorize?{params}")

    def login(self, ret: str, pstate: str):
        if not valid_return(ret):
            return self.html(400, "回跳地址不合法", "<p>只允许回到本机或局域网的控制台。</p>")
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", pstate or ""):
            return self.html(400, "参数错误", "<p>缺少 state。</p>")
        return self.start_login(mode="panel", ret=ret, pstate=pstate)

    def callback(self, code: str, hstate: str, error: str):
        with LOCK:
            tx = PENDING.pop(hstate, None)
        if not tx:
            return self.html(400, "登录已过期", "<p>请回到原页面重新点「登录」。</p>")
        web = tx["mode"] == "web"
        if error or not code:
            return self.html(400, "登录未完成", f"<p>{html.escape(error or '没有拿到授权码')}</p>")
        try:
            data = exchange_code(code, tx["verifier"], tx["redirect_uri"])
        except (urllib.error.URLError, ValueError) as e:
            sys.stderr.write(f"token exchange failed: {e!r}\n")
            return self.html(502, "登录失败", "<p>认证中心换取令牌失败，请重试。</p>")
        user = data.get("user") or {}
        email = str(user.get("email") or "").lower()
        if not email:
            return self.html(
                403, "需要邮箱", "<p>该账号没有已验证的邮箱。请用 Google 或邮箱方式登录。</p>"
            )
        role = role_of(email)
        if not role:
            msg = (f"<p>账号 <code>{html.escape(email)}</code> 还没有被管理员授权。</p>"
                   "<p>请把这个邮箱发给管理员，加入后再登录。</p>")
            if web:
                return self.portal(403, "没有访问权限", site_notice("没有访问权限", re.findall(r"<p>(.*?)</p>", msg)))
            return self.html(403, "没有访问权限", msg)
        if role == "admin":
            ensure_record(email)
        if web:
            cookie = sign({"t": "web", "e": email, "exp": int(time.time()) + WEB_HOURS * 3600})
            return self.send_redirect(
                "/", {"Set-Cookie": f"acis={cookie}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={WEB_HOURS * 3600}"}
            )
        ticket = b64url(secrets.token_bytes(24))
        with LOCK:
            TICKETS[ticket] = {
                "email": email,
                "name": str(user.get("name") or user.get("display_name") or ""),
                "exp": time.time() + 120,
            }
        sep = "&" if "?" in tx["return"] else "?"
        return self.redirect(
            tx["return"] + sep + urllib.parse.urlencode({"ticket": ticket, "state": tx["pstate"]})
        )

    def redeem(self):
        try:
            body = self.body_json()
        except ValueError:
            return self.send(400, {"error": "请求格式错误"})
        with LOCK:
            t = TICKETS.pop(str(body.get("ticket", "")), None)
        if not t:
            return self.send(400, {"error": "登录票据无效或已过期"})
        role = role_of(t["email"])
        if not role:
            return self.send(403, {"error": "没有访问权限"})
        exp = int(time.time()) + TOKEN_DAYS * 86400
        token = sign({"t": "api", "e": t["email"], "exp": exp})
        return self.send(200, {"token": token, "exp": exp, "email": t["email"], "name": t["name"], "role": role})

    # ---- api
    def api(self, method: str, path: str):
        who = self.auth()
        if not who:
            return self.send(401, {"error": "未登录或已失效"})
        email, role = who
        is_admin = role == "admin"

        if method == "GET" and path == "/api/me":
            rec = ensure_record(email) if is_admin else next(u for u in load_users()["users"] if u["email"] == email)
            return self.send(200, {"email": email, "role": role, "proxyUser": rec["proxyUser"], "proxyPass": rec["proxyPass"]})

        if method == "POST" and path == "/api/me/proxy-password":
            try:
                body = self.body_json()
            except ValueError:
                return self.send(400, {"error": "请求格式错误"})
            new = str(body.get("pass") or "") or random_password()
            if not valid_proxy_pass(new):
                return self.send(400, {"error": "密码需 6-64 位，且不含换行和引号"})
            with LOCK:
                data = load_users()
                for u in data["users"]:
                    if u["email"] == email:
                        u["proxyPass"] = new
                save_users(data)
            return self.send(200, {"ok": True, "pass": new})

        if not is_admin:
            return self.send(403, {"error": "仅管理员可操作"})

        if method == "GET" and path == "/api/users":
            return self.send(200, {"users": [public_user(u) for u in load_users()["users"]]})

        if method == "POST" and path == "/api/users":
            try:
                body = self.body_json()
            except ValueError:
                return self.send(400, {"error": "请求格式错误"})
            new_email = str(body.get("email") or "").strip().lower()
            if not EMAIL_RE.match(new_email):
                return self.send(400, {"error": "邮箱格式不正确"})
            pw = str(body.get("pass") or "") or random_password()
            if not valid_proxy_pass(pw):
                return self.send(400, {"error": "密码需 6-64 位，且不含换行和引号"})
            with LOCK:
                data = load_users()
                if any(u["email"] == new_email for u in data["users"]):
                    return self.send(409, {"error": "该邮箱已存在"})
                taken = {u["proxyUser"].lower() for u in data["users"]}
                pu = str(body.get("proxyUser") or "").strip()
                if pu:
                    if not PROXY_USER_RE.match(pu):
                        return self.send(400, {"error": "代理用户名需 3-32 位字母/数字/._-"})
                    if pu.lower() in taken:
                        return self.send(409, {"error": "代理用户名已被占用"})
                else:
                    pu = proxy_name_from_email(new_email, taken)
                rec = {"email": new_email, "proxyUser": pu, "proxyPass": pw, "created": int(time.time() * 1000)}
                data["users"].append(rec)
                save_users(data)
            return self.send(201, {"ok": True, "user": public_user(rec)})

        m = re.fullmatch(r"/api/users/([^/]+)(/password)?", path)
        if m:
            target = urllib.parse.unquote(m.group(1)).lower()
            with LOCK:
                data = load_users()
                rec = next((u for u in data["users"] if u["email"] == target), None)
                if not rec:
                    return self.send(404, {"error": "账号不存在"})
                if m.group(2) and method == "POST":
                    try:
                        body = self.body_json()
                    except ValueError:
                        return self.send(400, {"error": "请求格式错误"})
                    pw = str(body.get("pass") or "") or random_password()
                    if not valid_proxy_pass(pw):
                        return self.send(400, {"error": "密码需 6-64 位，且不含换行和引号"})
                    rec["proxyPass"] = pw
                    save_users(data)
                    return self.send(200, {"ok": True, "pass": pw})
                if not m.group(2) and method == "DELETE":
                    if target in ADMIN_EMAILS:
                        return self.send(400, {"error": "管理员账号不能删除"})
                    data["users"] = [u for u in data["users"] if u["email"] != target]
                    save_users(data)
                    return self.send(200, {"ok": True})
            return self.send(405, {"error": "method not allowed"})

        if method == "GET" and path == "/api/files":
            return self.send(200, {"files": manifest()})

        m = re.fullmatch(r"/api/files/([A-Za-z0-9._-]{1,128})", path)
        if method == "GET" and m:
            f = FILES_DIR / m.group(1)
            if m.group(1).startswith(".") or not f.is_file():
                return self.send(404, {"error": "文件不存在"})
            size = f.stat().st_size
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                with f.open("rb") as fh:
                    while chunk := fh.read(1 << 16):
                        self.wfile.write(chunk)
            return None

        return self.send(404, {"error": "not found"})


def main() -> None:
    if not ADMIN_EMAILS:
        sys.stderr.write("警告：ADMIN_EMAILS 为空，没有人能以管理员身份登录\n")
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    srv.daemon_threads = True
    sys.stderr.write(f"mihomo-hub listening on {HOST}:{PORT}  public={PUBLIC_URL}  admins={sorted(ADMIN_EMAILS)}\n")
    srv.serve_forever()


if __name__ == "__main__":
    main()
