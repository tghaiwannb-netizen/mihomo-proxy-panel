'use strict';

/**
 * 代理控制台 —— 零依赖 Node 服务
 *  · 静态前端
 *  · 登录走 auth.jizhang.org（经服务器 hub 中转，client_secret 不落本地）
 *  · 管理员 / 子账号名单、mihomo 配置模板、内核文件都由服务器 hub 下发
 *  · 子账号同步进 mihomo 的 7891 监听器（强制鉴权，无法绕过）
 *  · 反向代理 mihomo external-controller（仅管理员）
 *  · 网页内开关代理（启动/停止内核 + 系统代理）
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { spawn, execFile } = require('child_process');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const CONFIG_FILE = path.join(ROOT, 'config.json');
const HUB_CACHE = path.join(ROOT, '.hub-cache.json');
const SECRET_FILE = path.join(ROOT, '.session-secret');
const FIREWALL_MARK = path.join(ROOT, '.lan-ok');
const SET_PROXY_PS1 = path.join(ROOT, 'lib', 'set-proxy.ps1');

const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
const PORT = Number(config.port) || 8080;
const SESSION_HOURS = Number(config.sessionHours) || 12;
const LAN_PORT = Number(config.lanPort) || 7891;
const HUB = String(config.hub || 'https://mihomo.jizhang.org').replace(/\/+$/, '');
const SYNC_MINUTES = Number(config.syncMinutes) || 30;

let secret;
if (fs.existsSync(SECRET_FILE)) {
  secret = fs.readFileSync(SECRET_FILE);
} else {
  secret = crypto.randomBytes(32);
  fs.writeFileSync(SECRET_FILE, secret, { mode: 0o600 });
}

/* ------------------------------------------------------------------ utils */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2'
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (v) => crypto.createHash('sha256').update(String(v)).digest();

function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha256(a), sha256(b));
}

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verify(token) {
  if (!token || typeof token !== 'string') return null;
  const i = token.lastIndexOf('.');
  if (i < 0) return null;
  const body = token.slice(0, i);
  const sig = token.slice(i + 1);
  const expect = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  if (sig.length !== expect.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
  try {
    const data = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}

function readBody(req, limit = 2 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function send(res, status, body, headers = {}) {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers
  });
  res.end(data);
}

const exec = (file, args, opts) =>
  new Promise((resolve) => {
    execFile(file, args, { timeout: 20000, windowsHide: true, ...(opts || {}) }, (err, stdout) =>
      resolve({ err, out: String(stdout || '') })
    );
  });

/* ------------------------------------------------------------- hub cache */
// .hub-cache.json：服务器下发内容的本地缓存，断网时也能按上次的名单起内核
//   { users: [{proxyUser, proxyPass}], files: {name: sha256}, admin: {email, token, exp}, syncedAt, error }

function loadCache() {
  try {
    return JSON.parse(fs.readFileSync(HUB_CACHE, 'utf8'));
  } catch {
    return { users: [], files: {}, admin: null, syncedAt: 0, error: '' };
  }
}

function saveCache(data) {
  fs.writeFileSync(HUB_CACHE, JSON.stringify(data, null, 2), { mode: 0o600 });
}

/* ------------------------------------------------------------- hub client */

function hubRequest(method, apiPath, token, body, timeout = 15000) {
  const url = new URL(HUB + apiPath);
  const lib = url.protocol === 'https:' ? https : http;
  const data = body === undefined ? null : JSON.stringify(body);
  const headers = { Accept: 'application/json', 'User-Agent': 'mihomo-panel/2.0' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (data) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(data);
  }
  return new Promise((resolve, reject) => {
    const req = lib.request(url, { method, headers, timeout }, (r) => {
      const chunks = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try {
          json = text ? JSON.parse(text) : {};
        } catch {
          json = { error: text.slice(0, 200) };
        }
        resolve({ status: r.statusCode || 502, json });
      });
    });
    req.on('timeout', () => req.destroy(new Error('服务器响应超时')));
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function hubDownload(name, token, dest) {
  const url = new URL(`${HUB}/api/files/${encodeURIComponent(name)}`);
  const lib = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(
      url,
      { method: 'GET', headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'mihomo-panel/2.0' }, timeout: 120000 },
      (r) => {
        if (r.statusCode !== 200) {
          r.resume();
          return reject(new Error(`下载 ${name} 失败：HTTP ${r.statusCode}`));
        }
        const hash = crypto.createHash('sha256');
        const out = fs.createWriteStream(dest);
        r.on('data', (c) => hash.update(c));
        r.pipe(out);
        out.on('finish', () => resolve(hash.digest('hex')));
        out.on('error', reject);
        r.on('error', reject);
      }
    );
    req.on('timeout', () => req.destroy(new Error(`下载 ${name} 超时`)));
    req.on('error', reject);
    req.end();
  });
}

/* --------------------------------------------------- mihomo config sync */

function mihomoDir() {
  return path.resolve(ROOT, config.mihomoDir || '../mihomo');
}

function mihomoExe() {
  return path.join(mihomoDir(), config.mihomoExe || 'mihomo-windows-amd64.exe');
}

function mihomoConfig() {
  return path.join(mihomoDir(), 'config.yaml');
}

// 服务器下发的 config.yaml 存成 config.base.yaml，面板在它上面注入 7891 的账号块
function mihomoBase() {
  return path.join(mihomoDir(), 'config.base.yaml');
}

// 服务器文件名 -> 本地路径
function localPathFor(name) {
  if (name === 'config.yaml') return mihomoBase();
  return path.join(mihomoDir(), name);
}

function fileSha256(file) {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  } catch {
    return '';
  }
}

function yamlStr(v) {
  return `'${String(v).replace(/'/g, "''")}'`;
}

function usersBlock(users) {
  // 名单为空时放一个随机占位账号：mihomo 的 users 为空等于不鉴权，绝不能留空
  const list = users.length ? users : [{ proxyUser: 'locked', proxyPass: crypto.randomBytes(18).toString('hex') }];
  const lines = [
    '# >>> panel-users (auto-generated by panel, do not edit)',
    'listeners:',
    '  - name: lan-mixed',
    '    type: mixed',
    `    port: ${LAN_PORT}`,
    '    listen: 0.0.0.0',
    '    users:'
  ];
  for (const u of list) {
    lines.push(`      - username: ${yamlStr(u.proxyUser)}`);
    lines.push(`        password: ${yamlStr(u.proxyPass)}`);
  }
  lines.push('# <<< panel-users');
  return lines.join('\n');
}

function injectUsers(text, block) {
  if (/# >>> panel-users[\s\S]*?# <<< panel-users/.test(text)) {
    return text.replace(/# >>> panel-users[\s\S]*?# <<< panel-users/, () => block);
  }
  if (/^listeners:[\s\S]*?(?=^proxy-providers:)/m.test(text)) {
    return text.replace(/^listeners:[\s\S]*?(?=^proxy-providers:)/m, () => block + '\n\n');
  }
  if (/^proxy-providers:/m.test(text)) return text.replace(/^proxy-providers:/m, () => block + '\n\nproxy-providers:');
  return text.trimEnd() + '\n\n' + block + '\n';
}

function baseConfigText() {
  for (const f of [mihomoBase(), mihomoConfig(), path.join(mihomoDir(), 'config.example.yaml')]) {
    if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8');
  }
  return null;
}

// 用「服务器模板 + 当前名单」生成 config.yaml；内容有变化才热重载
async function writeMihomoConfig() {
  try {
    const base = baseConfigText();
    if (base == null) throw new Error('没有可用的 mihomo 配置模板，请先从服务器同步');
    const text = injectUsers(base, usersBlock(loadCache().users || []));
    const file = mihomoConfig();
    const old = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    if (old === text) return true;
    fs.writeFileSync(file, text);
    await reloadCore();
    return true;
  } catch (e) {
    console.error('生成 mihomo 配置失败:', e.message);
    return false;
  }
}

/* ------------------------------------------------------------ hub sync */

let syncing = null;

// 拉名单 + 拉文件 + 重写配置。token 为管理员的 hub token
function syncFromHub(token) {
  if (syncing) return syncing;
  syncing = (async () => {
    const cache = loadCache();
    const tk = token || (cache.admin && cache.admin.exp * 1000 > Date.now() ? cache.admin.token : '');
    if (!tk) return { ok: false, error: '还没有管理员登录过，无法同步' };
    const report = { ok: true, updated: [], pending: [], error: '' };
    try {
      const u = await hubRequest('GET', '/api/users', tk);
      if (u.status !== 200) throw new Error(u.json.error || `拉取名单失败 HTTP ${u.status}`);
      cache.users = (u.json.users || []).map((x) => ({ proxyUser: x.proxyUser, proxyPass: x.proxyPass }));

      const f = await hubRequest('GET', '/api/files', tk);
      if (f.status !== 200) throw new Error(f.json.error || `拉取文件清单失败 HTTP ${f.status}`);
      cache.files = cache.files || {};
      for (const item of f.json.files || []) {
        if (!/^[A-Za-z0-9._-]{1,128}$/.test(item.name)) continue;
        const dest = localPathFor(item.name);
        if (fileSha256(dest) === item.sha256) {
          cache.files[item.name] = item.sha256;
          continue;
        }
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        const tmp = dest + '.download';
        const got = await hubDownload(item.name, tk, tmp);
        if (got !== item.sha256) {
          fs.rmSync(tmp, { force: true });
          throw new Error(`${item.name} 校验失败`);
        }
        try {
          fs.renameSync(tmp, dest);
          report.updated.push(item.name);
        } catch {
          // Windows 上内核运行中 exe 被占用：先放成 .new，下次启动内核前替换
          fs.renameSync(tmp, dest + '.new');
          report.pending.push(item.name);
        }
        cache.files[item.name] = item.sha256;
      }
      cache.syncedAt = Date.now();
      cache.error = '';
    } catch (e) {
      report.ok = false;
      report.error = e.message;
      cache.error = e.message;
    }
    saveCache(cache);
    await writeMihomoConfig();
    report.syncedAt = cache.syncedAt;
    return report;
  })().finally(() => {
    syncing = null;
  });
  return syncing;
}

// 把同步时被占用的文件（*.new）换上去；只在内核停止时调用
function applyPendingFiles() {
  try {
    for (const f of fs.readdirSync(mihomoDir())) {
      if (!f.endsWith('.new')) continue;
      const dest = path.join(mihomoDir(), f.slice(0, -4));
      try {
        fs.renameSync(path.join(mihomoDir(), f), dest);
      } catch (e) {
        console.error('替换文件失败:', f, e.message);
      }
    }
  } catch {
    /* dir missing */
  }
}

/* ------------------------------------------------------------ core request */

function coreTarget(session) {
  const raw = (session && session.core) || config.core || '127.0.0.1:9090';
  const idx = raw.lastIndexOf(':');
  return { host: raw.slice(0, idx) || '127.0.0.1', port: Number(raw.slice(idx + 1)) || 9090 };
}

function coreRequest(session, method, apiPath, body, timeout = 15000) {
  const { host, port } = coreTarget(session);
  return new Promise((resolve, reject) => {
    const headers = { Accept: 'application/json' };
    if (body) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(body);
    }
    if (config.secret) headers.Authorization = `Bearer ${config.secret}`;

    const req = http.request({ host, port, method, path: apiPath, headers, timeout }, (r) => {
      const chunks = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () =>
        resolve({ status: r.statusCode || 502, type: r.headers['content-type'] || '', body: Buffer.concat(chunks) })
      );
    });
    req.on('timeout', () => req.destroy(new Error('内核响应超时')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function coreUp() {
  try {
    const r = await coreRequest(null, 'GET', '/version', null, 2500);
    return r.status === 200;
  } catch {
    return false;
  }
}

async function reloadCore() {
  try {
    const body = JSON.stringify({ path: mihomoConfig() });
    const r = await coreRequest(null, 'PUT', '/configs?force=true', body, 10000);
    return r.status >= 200 && r.status < 300;
  } catch {
    return false;
  }
}

/* --------------------------------------------------------- proxy control */

async function setSystemProxy(enable) {
  const { err } = await exec('powershell', [
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    SET_PROXY_PS1,
    enable ? '1' : '0',
    config.proxy || '127.0.0.1:7890'
  ]);
  return !err;
}

async function systemProxyState() {
  const { err, out } = await exec('reg', [
    'query',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
    '/v',
    'ProxyEnable'
  ]);
  if (err) return false;
  return /0x1\b/i.test(out);
}

async function proxyStatus() {
  const online = await coreUp();
  const sys = await systemProxyState();
  return {
    online,
    systemProxy: sys,
    active: online && sys,
    proxy: config.proxy || '127.0.0.1:7890',
    lanPort: LAN_PORT
  };
}

async function startProxy() {
  if (!fs.existsSync(mihomoExe())) {
    return { error: '找不到内核：mihomo\\mihomo-windows-amd64.exe，请先下载', online: false, active: false };
  }
  let online = await coreUp();
  if (!online) {
    applyPendingFiles();
    await writeMihomoConfig();
    try {
      const child = spawn(mihomoExe(), ['-d', mihomoDir()], {
        cwd: mihomoDir(),
        detached: true,
        stdio: 'ignore',
        windowsHide: true
      });
      child.unref();
    } catch (e) {
      console.error('启动内核失败:', e.message);
    }
    for (let i = 0; i < 40 && !online; i++) {
      await sleep(500);
      online = await coreUp();
    }
  }
  if (online) {
    await reloadCore();
    await setSystemProxy(true);
  }
  return proxyStatus();
}

async function stopProxy() {
  await setSystemProxy(false);
  await exec('taskkill', ['/IM', config.mihomoExe || 'mihomo-windows-amd64.exe', '/F']);
  await sleep(700);
  applyPendingFiles();
  return proxyStatus();
}

/* ------------------------------------------------------------- LAN details */

function lanAddresses() {
  const out = [];
  const nets = os.networkInterfaces();
  for (const [name, list] of Object.entries(nets)) {
    for (const n of list || []) {
      if (n.family === 'IPv4' && !n.internal) {
        out.push({ iface: name, ip: n.address, cidr: n.cidr || '' });
      }
    }
  }
  return out;
}

function panelUrls(ip) {
  const port = PORT === 80 ? '' : `:${PORT}`;
  return {
    ip: `http://${ip}${port}`,
    host: `http://${os.hostname().toLowerCase()}${port}`
  };
}

function lanSummary(user) {
  const ips = lanAddresses();
  const primary = ips[0] || { ip: '127.0.0.1', iface: '', cidr: '' };
  const urls = panelUrls(primary.ip);
  const lanProxyIp = `${primary.ip}:${LAN_PORT}`;
  return {
    hostname: os.hostname(),
    port: PORT,
    ips,
    panelUrl: urls.ip,
    panelHostUrl: urls.host,
    proxyUrl: lanProxyIp,
    lanProxyUrl: lanProxyIp,
    lanUser: (user && user.proxyUser) || '',
    firewallOpen: fs.existsSync(FIREWALL_MARK),
    core: config.core
  };
}

/* -------------------------------------------------------------- exit lookup */

let exitCache = { at: 0, data: null, errorAt: 0, error: '' };

function proxyJson(target, host) {
  const proxy = config.proxy || '127.0.0.1:7890';
  const idx = proxy.lastIndexOf(':');
  const ph = proxy.slice(0, idx) || '127.0.0.1';
  const pp = Number(proxy.slice(idx + 1)) || 7890;

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: ph,
        port: pp,
        method: 'GET',
        path: target,
        headers: { Host: host, 'User-Agent': 'panel/1.0', Accept: 'application/json' },
        timeout: 9000
      },
      (r) => {
        const chunks = [];
        r.on('data', (c) => chunks.push(c));
        r.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if (r.statusCode !== 200) return reject(new Error(`HTTP ${r.statusCode}`));
          try {
            resolve(JSON.parse(text));
          } catch {
            reject(new Error('返回内容无法解析'));
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('出口查询超时')));
    req.on('error', reject);
    req.end();
  });
}

async function exitInfo() {
  if (exitCache.data && Date.now() - exitCache.at < 30_000) return exitCache.data;
  if (exitCache.errorAt && Date.now() - exitCache.errorAt < 8000) throw new Error(exitCache.error);

  try {
    const d = await proxyJson(
      'http://ip-api.com/json/?fields=status,country,regionName,city,isp,query',
      'ip-api.com'
    );
    if (d.status !== 'success') throw new Error(d.message || '查询失败');
    const out = { query: d.query, country: d.country, regionName: d.regionName, city: d.city, isp: d.isp };
    exitCache = { at: Date.now(), data: out, errorAt: 0, error: '' };
    return out;
  } catch (first) {
    try {
      const d = await proxyJson('http://ipwho.is/', 'ipwho.is');
      if (!d.success) throw new Error(d.message || '查询失败');
      const out = {
        query: d.ip,
        country: d.country,
        regionName: d.region,
        city: d.city,
        isp: (d.connection && d.connection.isp) || ''
      };
      exitCache = { at: Date.now(), data: out, errorAt: 0, error: '' };
      return out;
    } catch {
      exitCache.errorAt = Date.now();
      exitCache.error = first.message;
      throw first;
    }
  }
}

/* ------------------------------------------------------------------ static */

function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  rel = decodeURIComponent(rel.split('?')[0]);
  const file = path.join(PUBLIC_DIR, path.normalize(rel).replace(/^([/\\])+/, ''));
  if (!file.startsWith(PUBLIC_DIR)) return send(res, 403, { error: 'forbidden' });

  fs.readFile(file, (err, data) => {
    if (err) {
      if (pathname !== '/' && !path.extname(pathname)) {
        return fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (e2, html) => {
          if (e2) return send(res, 404, { error: 'not found' });
          res.writeHead(200, { 'Content-Type': MIME['.html'], 'Cache-Control': 'no-cache' });
          res.end(html);
        });
      }
      return send(res, 404, { error: 'not found' });
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
      'Cache-Control': 'no-cache'
    });
    res.end(data);
  });
}

/* ---------------------------------------------------------------- session */
// sid Cookie = HMAC 签名的 { e: 邮箱, r: 角色, h: hub token, exp }
// hub token 每次调用 hub 时由服务器重新校验，子账号被删后立即失效

function getSession(req) {
  const s = verify(parseCookies(req.headers.cookie || '').sid);
  if (!s || !s.e || !s.h) return null;
  return { email: s.e, role: s.r === 'admin' ? 'admin' : 'user', token: s.h, core: config.core };
}

function sessionCookie(email, role, token) {
  const sid = sign({ e: email, r: role, h: token, exp: Date.now() + SESSION_HOURS * 3600 * 1000 });
  return `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}`;
}

function originOf(req) {
  const host = String(req.headers.host || `127.0.0.1:${PORT}`);
  if (!/^[A-Za-z0-9.\-:[\]]{1,255}$/.test(host)) return `http://127.0.0.1:${PORT}`;
  return `http://${host}`;
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, { Location: location, 'Cache-Control': 'no-store', ...headers });
  res.end();
}

async function readJson(req) {
  try {
    return JSON.parse((await readBody(req, 8192)) || '{}');
  } catch {
    return null;
  }
}

// 把 hub 的响应原样转给浏览器
function relay(res, r) {
  return send(res, r.status, r.json || {});
}

async function hubCall(res, method, apiPath, token, body) {
  try {
    return await hubRequest(method, apiPath, token, body);
  } catch (e) {
    send(res, 502, { error: '连不上服务器：' + e.message });
    return null;
  }
}

/* ------------------------------------------------------------------ server */

const server = http.createServer(async (req, res) => {
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch {
    return send(res, 400, { error: 'bad url' });
  }
  const pathname = url.pathname;

  // ---------- 登录：跳到服务器 hub，再由 hub 跳 auth.jizhang.org ----------
  if (pathname === '/auth/login' && req.method === 'GET') {
    const st = crypto.randomBytes(24).toString('base64url');
    const ret = `${originOf(req)}/auth/finish`;
    const target = `${HUB}/login?${new URLSearchParams({ return: ret, state: st })}`;
    return redirect(res, target, {
      'Set-Cookie': `pst=${st}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=600`
    });
  }

  if (pathname === '/auth/finish' && req.method === 'GET') {
    const fail = (msg) => redirect(res, `/?login_error=${encodeURIComponent(msg)}`, {
      'Set-Cookie': 'pst=; Path=/auth; HttpOnly; Max-Age=0'
    });
    const ticket = url.searchParams.get('ticket') || '';
    const st = url.searchParams.get('state') || '';
    const expect = parseCookies(req.headers.cookie || '').pst || '';
    if (!st || !expect || !safeEqual(st, expect)) return fail('登录状态校验失败，请重新登录');

    let r;
    try {
      r = await hubRequest('POST', '/api/ticket/redeem', null, { ticket });
    } catch (e) {
      return fail('连不上服务器：' + e.message);
    }
    if (r.status !== 200 || !r.json.token) return fail(r.json.error || '登录失败');

    const { token, email, role, exp } = r.json;
    if (role === 'admin') {
      const cache = loadCache();
      cache.admin = { email, token, exp };
      saveCache(cache);
      syncFromHub(token).then((rep) => {
        if (!rep.ok) console.error('同步失败:', rep.error);
      });
    }
    res.writeHead(302, {
      Location: '/',
      'Cache-Control': 'no-store',
      'Set-Cookie': [sessionCookie(email, role, token), 'pst=; Path=/auth; HttpOnly; Max-Age=0']
    });
    return res.end();
  }

  if (pathname === '/api/logout' && req.method === 'POST') {
    return send(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; Path=/; HttpOnly; Max-Age=0' });
  }

  // ---------- 会话 ----------
  if (pathname === '/api/session' && req.method === 'GET') {
    const s = getSession(req);
    if (!s) return send(res, 200, { authed: false, hub: HUB });
    return send(res, 200, {
      authed: true,
      user: s.email,
      role: s.role,
      core: s.core,
      hub: HUB,
      lan: lanSummary(null)
    });
  }

  // ---------- 以下需要登录 ----------
  const session = getSession(req);
  if (pathname.startsWith('/api/') && !session) {
    return send(res, 401, { authed: false, error: '未登录' });
  }

  const isAdmin = !!session && session.role === 'admin';
  const needAdmin = () => send(res, 403, { error: '仅管理员可操作' });

  if (pathname === '/api/me' && req.method === 'GET') {
    const r = await hubCall(res, 'GET', '/api/me', session.token);
    if (!r) return;
    if (r.status === 401 || r.status === 403) {
      return send(res, 401, { authed: false, error: r.json.error || '账号已失效' }, {
        'Set-Cookie': 'sid=; Path=/; HttpOnly; Max-Age=0'
      });
    }
    if (r.status !== 200) return relay(res, r);
    const lan = lanSummary(r.json);
    return send(res, 200, {
      user: r.json.email,
      role: r.json.role,
      proxyUser: r.json.proxyUser,
      proxyPass: r.json.proxyPass,
      lan,
      proxy: { address: lan.lanProxyUrl, port: LAN_PORT }
    });
  }

  if (pathname === '/api/me/password' && req.method === 'POST') {
    const body = await readJson(req);
    if (!body) return send(res, 400, { error: '请求格式错误' });
    const r = await hubCall(res, 'POST', '/api/me/proxy-password', session.token, { pass: body.next || '' });
    if (!r) return;
    if (r.status === 200) {
      if (isAdmin) await syncFromHub(session.token);
      else syncFromHub().catch(() => {});
    }
    return relay(res, r);
  }

  if (pathname === '/api/lan' && req.method === 'GET') {
    return send(res, 200, lanSummary(null));
  }

  if (pathname === '/api/exit' && req.method === 'GET') {
    if (!isAdmin) return needAdmin();
    try {
      return send(res, 200, await exitInfo());
    } catch (e) {
      return send(res, 502, { error: e.message });
    }
  }

  // ---------- 服务器下发 ----------
  if (pathname === '/api/sync' && req.method === 'GET') {
    if (!isAdmin) return needAdmin();
    const c = loadCache();
    return send(res, 200, { hub: HUB, syncedAt: c.syncedAt || 0, error: c.error || '', files: c.files || {}, users: (c.users || []).length });
  }

  if (pathname === '/api/sync' && req.method === 'POST') {
    if (!isAdmin) return needAdmin();
    const rep = await syncFromHub(session.token);
    return send(res, rep.ok ? 200 : 502, rep);
  }

  // ---------- 代理开关 ----------
  if (pathname === '/api/proxy/status' && req.method === 'GET') {
    if (!isAdmin) return needAdmin();
    return send(res, 200, await proxyStatus());
  }

  if (pathname === '/api/proxy/start' && req.method === 'POST') {
    if (!isAdmin) return needAdmin();
    const result = await startProxy();
    if (result.error) return send(res, 400, result);
    return send(res, 200, result);
  }

  if (pathname === '/api/proxy/stop' && req.method === 'POST') {
    if (!isAdmin) return needAdmin();
    return send(res, 200, await stopProxy());
  }

  // ---------- 账号管理（数据在服务器，改完立即同步到本机内核） ----------
  if (pathname === '/api/users' && req.method === 'GET') {
    if (!isAdmin) return needAdmin();
    const r = await hubCall(res, 'GET', '/api/users', session.token);
    if (r) relay(res, r);
    return;
  }

  if (pathname === '/api/users' && req.method === 'POST') {
    if (!isAdmin) return needAdmin();
    const body = await readJson(req);
    if (!body) return send(res, 400, { error: '请求格式错误' });
    const r = await hubCall(res, 'POST', '/api/users', session.token, {
      email: body.email,
      proxyUser: body.proxyUser,
      pass: body.pass
    });
    if (!r) return;
    if (r.status < 300) await syncFromHub(session.token);
    return relay(res, r);
  }

  const userMatch = /^\/api\/users\/([^/]+)(\/password)?$/.exec(pathname);
  if (userMatch) {
    if (!isAdmin) return needAdmin();
    const name = encodeURIComponent(decodeURIComponent(userMatch[1]));
    let r;
    if (userMatch[2] && req.method === 'POST') {
      const body = (await readJson(req)) || {};
      r = await hubCall(res, 'POST', `/api/users/${name}/password`, session.token, { pass: body.pass || '' });
    } else if (!userMatch[2] && req.method === 'DELETE') {
      r = await hubCall(res, 'DELETE', `/api/users/${name}`, session.token);
    } else {
      return send(res, 405, { error: 'method not allowed' });
    }
    if (!r) return;
    if (r.status < 300) await syncFromHub(session.token);
    return relay(res, r);
  }

  // ---------- 内核反代（仅管理员） ----------
  if (pathname.startsWith('/api/core/')) {
    if (!isAdmin) return needAdmin();
    const apiPath = req.url.slice('/api/core'.length);
    let body = '';
    if (!['GET', 'HEAD'].includes(req.method)) {
      try {
        body = await readBody(req);
      } catch {
        return send(res, 413, { error: '请求体过大' });
      }
    }
    try {
      const timeout = apiPath.includes('/healthcheck') ? 180000 : 15000;
      const r = await coreRequest(session, req.method, apiPath, body, timeout);
      res.writeHead(r.status, {
        'Content-Type': r.type || 'application/json; charset=utf-8',
        'Cache-Control': 'no-store'
      });
      res.end(r.body);
    } catch (e) {
      return send(res, 502, { error: '内核未连接：' + e.message });
    }
    return;
  }

  if (pathname.startsWith('/api/')) return send(res, 404, { error: 'not found' });

  return serveStatic(req, res, pathname);
});

/* --------------------------------------------------------------- websocket */

server.on('upgrade', (req, socket) => {
  const session = getSession(req);
  const m = /^\/api\/ws(\/.*)$/.exec(req.url || '');
  if (!session || session.role !== 'admin' || !m) {
    socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    return socket.destroy();
  }

  const { host, port } = coreTarget(session);
  const headers = { ...req.headers, host: `${host}:${port}` };
  if (config.secret) headers.authorization = `Bearer ${config.secret}`;

  const upstream = http.request({ host, port, method: 'GET', path: m[1], headers });
  upstream.on('upgrade', (r, upSocket, upHead) => {
    const lines = [`HTTP/1.1 ${r.statusCode} ${r.statusMessage || 'Switching Protocols'}`];
    for (let i = 0; i < r.rawHeaders.length; i += 2) lines.push(`${r.rawHeaders[i]}: ${r.rawHeaders[i + 1]}`);
    socket.write(lines.join('\r\n') + '\r\n\r\n');
    if (upHead && upHead.length) socket.write(upHead);

    upSocket.pipe(socket);
    socket.pipe(upSocket);
    const kill = () => {
      socket.destroy();
      upSocket.destroy();
    };
    upSocket.on('error', kill);
    socket.on('error', kill);
    upSocket.on('close', kill);
    socket.on('close', kill);
  });
  upstream.on('error', () => {
    socket.write('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
    socket.destroy();
  });
  upstream.end();
});

/* -------------------------------------------------------------------- boot */

(async function boot() {
  // 先用本地缓存生成配置（离线也能用），再尝试从服务器拉最新
  await writeMihomoConfig();
  const rep = await syncFromHub();
  if (rep.ok) console.log(`  已从服务器同步${rep.updated.length ? '：' + rep.updated.join(', ') : '（无变化）'}`);
  else console.log(`  未同步服务器：${rep.error}`);
  setInterval(() => syncFromHub().catch(() => {}), SYNC_MINUTES * 60 * 1000).unref();
})();

server.listen(PORT, '0.0.0.0', () => {
  const lan = lanSummary(null);
  console.log('');
  console.log('  代理控制台已启动');
  console.log('  ─────────────────────────────');
  console.log(`  本机     http://127.0.0.1:${PORT}`);
  for (const i of lan.ips) console.log(`  局域网   http://${i.ip}:${PORT}   (${i.iface})`);
  console.log(`  主机名   ${lan.panelHostUrl}`);
  console.log(`  内核     ${config.core}`);
  console.log(`  服务器   ${HUB}（登录 / 名单 / 文件下发）`);
  console.log(`  代理入口 ${lan.lanProxyUrl}（需子账号）`);
  console.log('');
});

process.on('SIGINT', () => {
  console.log('\n  已停止。');
  process.exit(0);
});
