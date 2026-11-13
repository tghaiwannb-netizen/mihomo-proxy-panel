#!/usr/bin/env python3
"""
打 Windows 安装包，放进下载门户（PACKAGES_DIR）。

  sudo python3 -I build_package.py [--src /opt/mihomo-hub/src] [--ref auth-jizhang-hub]

产物：
  ACIS-Proxy-Windows.zip  一键包：控制台 + 脚本 + 内置 Node.js + mihomo 内核 + 配置模板
  ACIS-Proxy-Update.zip   仅控制台和脚本，已经装过的机器覆盖更新用
内核与配置模板取自 FILES_DIR（和控制台同步用的是同一份）。
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

HUB = Path("/opt/mihomo-hub")
FILES_DIR = Path(os.environ.get("FILES_DIR", HUB / "files"))
PACKAGES_DIR = Path(os.environ.get("PACKAGES_DIR", HUB / "packages"))
CACHE = HUB / "build-cache"
REPO = "https://github.com/tghaiwannb-netizen/mihomo-proxy-panel.git"
HUB_URL = "https://acis-vpn.jizhang.org"
ROOT_NAME = "ACIS-Proxy"
UA = {"User-Agent": "acis-package-builder"}

# 仓库里要打进包的内容（相对仓库根目录）
INCLUDE = [
    "panel/server.js",
    "panel/public",
    "panel/lib",
    "panel/start-panel.bat",
    "panel/start-panel.ps1",
    "panel/allow-panel-firewall.bat",
    "panel/README.md",
    "start-auth.ps1",
    "stop-auth.ps1",
    "make-shortcuts.ps1",
    "allow-lan-firewall.bat",
    "安装.bat",
    "README.md",
]


def fetch(url: str, timeout: int = 300) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


def git_checkout(src: Path, ref: str) -> str:
    if not (src / ".git").exists():
        subprocess.run(["git", "clone", "--quiet", REPO, str(src)], check=True)
    subprocess.run(["git", "-C", str(src), "fetch", "--quiet", "origin", ref], check=True)
    subprocess.run(["git", "-C", str(src), "checkout", "--quiet", "--force", "FETCH_HEAD"], check=True)
    return subprocess.run(["git", "-C", str(src), "rev-parse", "--short", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()


def node_exe() -> tuple[bytes, str]:
    """官方 Node.js 22 LTS 的 win-x64 node.exe，按 SHASUMS256 校验后缓存。"""
    CACHE.mkdir(parents=True, exist_ok=True)
    sums = fetch("https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt", 60).decode()
    m = re.search(r"^([0-9a-f]{64})\s+(node-v([\d.]+)-win-x64\.zip)$", sums, re.M)
    if not m:
        raise SystemExit("找不到 Node.js win-x64 包")
    digest, name, version = m.groups()
    cached = CACHE / f"node-v{version}.exe"
    if cached.exists():
        return cached.read_bytes(), version
    data = fetch(f"https://nodejs.org/dist/latest-v22.x/{name}")
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit("Node.js 下载校验失败")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        exe = z.read(f"node-v{version}-win-x64/node.exe")
    cached.write_bytes(exe)
    return exe, version


def add_tree(z: zipfile.ZipFile, src: Path, rel: str) -> None:
    p = src / rel
    if p.is_dir():
        for f in sorted(p.rglob("*")):
            if f.is_file():
                z.write(f, f"{ROOT_NAME}/{f.relative_to(src).as_posix()}")
    elif p.is_file():
        z.write(p, f"{ROOT_NAME}/{rel}")
    else:
        raise SystemExit(f"仓库里缺少 {rel}")


def panel_config(src: Path) -> bytes:
    cfg = json.loads((src / "panel/config.json").read_text(encoding="utf-8"))
    cfg["hub"] = HUB_URL
    return (json.dumps(cfg, indent=2, ensure_ascii=False) + "\n").encode()


def readme(commit: str, node_ver: str, full: bool) -> bytes:
    lines = [
        "ACIS 代理 —— Windows 安装包",
        "",
        f"版本：{commit}    打包时间：{time.strftime('%Y-%m-%d %H:%M')}",
        f"下载页：{HUB_URL}",
        "",
        "使用：",
        "  1. 解压到任意目录",
        "  2. 双击「安装.bat」：创建桌面快捷方式并打开控制台",
        "  3. 控制台里点「使用墨清账户登录」，用被授权的邮箱登录",
        "  4. 管理员登录后会自动同步配置模板和内核；概览页打开开关即可",
        "",
    ]
    if full:
        lines += [f"已内置 Node.js v{node_ver}（runtime\\node.exe）和 mihomo 内核，无需另外安装。", ""]
    else:
        lines += ["这是更新包：解压覆盖到原安装目录即可，账号缓存和内核不会被覆盖。", ""]
    return "\r\n".join(lines).encode("utf-8-sig")


def write_zip(target: Path, build) -> None:
    tmp = target.with_suffix(".tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        build(z)
    os.chmod(tmp, 0o644)
    tmp.replace(target)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(HUB / "src"))
    ap.add_argument("--ref", default="auth-jizhang-hub")
    args = ap.parse_args()
    src = Path(args.src)

    commit = git_checkout(src, args.ref)
    node, node_ver = node_exe()
    kernel = FILES_DIR / "mihomo-windows-amd64.exe"
    template = FILES_DIR / "config.yaml"
    for f in (kernel, template):
        if not f.exists():
            raise SystemExit(f"缺少下发文件 {f}")
    PACKAGES_DIR.mkdir(parents=True, exist_ok=True)

    def common(z: zipfile.ZipFile, full: bool) -> None:
        for rel in INCLUDE:
            add_tree(z, src, rel)
        z.writestr(f"{ROOT_NAME}/panel/config.json", panel_config(src))
        z.writestr(f"{ROOT_NAME}/使用说明.txt", readme(commit, node_ver, full))

    def full(z: zipfile.ZipFile) -> None:
        common(z, True)
        z.writestr(f"{ROOT_NAME}/runtime/node.exe", node)
        z.write(kernel, f"{ROOT_NAME}/mihomo/mihomo-windows-amd64.exe")
        z.write(template, f"{ROOT_NAME}/mihomo/config.example.yaml")

    def update(z: zipfile.ZipFile) -> None:
        common(z, False)

    write_zip(PACKAGES_DIR / "ACIS-Proxy-Windows.zip", full)
    write_zip(PACKAGES_DIR / "ACIS-Proxy-Update.zip", update)

    meta = {
        "ACIS-Proxy-Windows.zip": {
            "title": "Windows 一键包",
            "desc": f"控制台 + mihomo 内核 + Node.js v{node_ver}，解压后双击「安装.bat」。版本 {commit}。",
            "order": 1,
        },
        "ACIS-Proxy-Update.zip": {
            "title": "控制台更新包",
            "desc": f"只含控制台和脚本，已经装过的电脑解压覆盖即可。版本 {commit}。",
            "order": 2,
        },
    }
    (PACKAGES_DIR / "packages.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(PACKAGES_DIR / "packages.json", 0o644)
    for p in sorted(PACKAGES_DIR.iterdir()):
        print(p.name, p.stat().st_size)
    print("commit", commit, "node", node_ver)


if __name__ == "__main__":
    sys.exit(main())
