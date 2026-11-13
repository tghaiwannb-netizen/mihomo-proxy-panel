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
PUBLIC_URL = os.environ.get("PUBLIC_URL", "https://mihomo.jizhang.org").rstrip("/")
REDIRECT_URI = PUBLIC_URL + "/auth/callback"
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()}
HOST = os.environ.get("HUB_HOST", "127.0.0.1")
PORT = int(os.environ.get("HUB_PORT", "8097"))
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))
FILES_DIR = Path(os.environ.get("FILES_DIR", ROOT / "files"))
TOKEN_DAYS = int(os.environ.get("TOKEN_DAYS", "30"))
SECRET_FILE = DATA_DIR / ".hub-secret"
USERS_FILE = DATA_DIR / "users.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
FILES_DIR.mkdir(parents=True, exist_ok=True)

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


def exchange_code(code: str, verifier: str) -> dict:
    form = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "redirect_uri": REDIRECT_URI,
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


# ------------------------------------------------------------------ pages

PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<style>body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5efe6;color:#2b2420;
font:15px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif}}main{{max-width:420px;padding:32px 28px;
background:#fffaf3;border:1px solid #e6dccd;border-radius:18px;margin:16px}}h1{{font-size:20px;margin:0 0 8px}}
p{{margin:6px 0;color:#6b5d52}}code{{background:#f0e6d8;padding:1px 6px;border-radius:6px}}
a{{color:#b4532a}}</style></head><body><main><h1>{title}</h1>{body}</main></body></html>"""


def page(title: str, body: str) -> bytes:
    return PAGE.format(title=html.escape(title), body=body).encode()


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
        self.send(status, page(title, body), "text/html; charset=utf-8")

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

    def route(self, method: str):
        gc()
        url = urllib.parse.urlsplit(self.path)
        path, qs = url.path, urllib.parse.parse_qs(url.query)
        q = lambda k: (qs.get(k) or [""])[0]  # noqa: E731
        try:
            if method == "GET" and path == "/":
                return self.html(200, "Mihomo Hub", "<p>代理控制台的登录与文件下发服务。</p><p>请在本机控制台里点「登录」。</p>")
            if method == "GET" and path == "/healthz":
                return self.send(200, {"ok": True})
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

    # ---- login
    def login(self, ret: str, pstate: str):
        if not CLIENT_SECRET:
            return self.html(503, "未配置", "<p>hub 尚未配置 <code>AUTH_CLIENT_SECRET</code>。</p>")
        if not valid_return(ret):
            return self.html(400, "回跳地址不合法", "<p>只允许回到本机或局域网的控制台。</p>")
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", pstate or ""):
            return self.html(400, "参数错误", "<p>缺少 state。</p>")
        verifier = b64url(secrets.token_bytes(48))
        challenge = b64url(hashlib.sha256(verifier.encode()).digest())
        hstate = b64url(secrets.token_bytes(24))
        with LOCK:
            PENDING[hstate] = {"verifier": verifier, "return": ret, "pstate": pstate, "exp": time.time() + 600}
        params = urllib.parse.urlencode(
            {
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "openid profile email",
                "state": hstate,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return self.redirect(f"{AUTH_BASE}/oauth/authorize?{params}")

    def callback(self, code: str, hstate: str, error: str):
        with LOCK:
            tx = PENDING.pop(hstate, None)
        if not tx:
            return self.html(400, "登录已过期", "<p>请回到控制台重新点「登录」。</p>")
        if error or not code:
            return self.html(400, "登录未完成", f"<p>{html.escape(error or '没有拿到授权码')}</p>")
        try:
            data = exchange_code(code, tx["verifier"])
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
            return self.html(
                403,
                "没有访问权限",
                f"<p>账号 <code>{html.escape(email)}</code> 还没有被管理员授权。</p>"
                "<p>请把这个邮箱发给管理员，加入后再登录。</p>",
            )
        if role == "admin":
            ensure_record(email)
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
