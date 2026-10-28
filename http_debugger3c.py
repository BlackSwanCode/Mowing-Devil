#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP Debugger v3c — client HTTP/WebSocket graphique & CLI piloté par templates YAML.

Tests de conformité / durcissement / WebSocket de VOS propres serveurs uniquement.
N'exécutez jamais cette suite contre des machines dont vous n'êtes pas responsable.

GUI : python http_debugger3c.py [templates/]
CLI : python http_debugger3c.py --cli templates/ --base-url URL \
         --junit rapport.xml --html rapport.html --fail-on high

Changements v3c vs v3b :
  - assertion `raw_headers_regex` : matche sur le bloc d'en-têtes sérialisé
    "Name: value\\nName: value\\n..." — sémantique Nuclei part=header (regex).
  - assertion `raw_headers_contains` : équivalent word pour part=header.
  - utilitaires `_headers_block()` / `_raw_headers_search()` factorisés.
  - les patches v3b (template_dir init, verdict_semantics) sont conservés.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import ipaddress
import json
import os
import re
import shlex
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable

# ── Dépendances (dégradation propre) ───────────────────────────────────────
try:
    import httpx
    HAVE_HTTPX = True
except ImportError:
    HAVE_HTTPX = False
try:
    import requests, urllib3
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False
try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False
try:
    from charset_normalizer import from_bytes as detect_charset
except ImportError:
    detect_charset = None
try:
    import websockets.sync.client as ws_sync
    from websockets.exceptions import ConnectionClosed as WsConnectionClosed
    HAVE_WS = True
except ImportError:
    HAVE_WS = False
    WsConnectionClosed = Exception


# ════════════════════════════════════════════════════════════════════════════
#  Palette & constantes
# ════════════════════════════════════════════════════════════════════════════
C = dict(bg="#171926", panel="#1f2233", panel2="#292d44", border="#363b5a",
         text="#e6e8f2", muted="#8a90ad", accent="#8b7cf6", accent2="#a99bff",
         ok="#4ade80", warn="#fbbf24", err="#f87171", info="#60a5fa",
         cyan="#22d3ee", pink="#f472b6", orange="#fb923c")

SEV_COLOR = {"critical": C["err"], "high": C["err"], "medium": C["orange"],
             "low": C["warn"], "info": C["info"]}
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SECURITY_HEADERS = {"strict-transport-security", "content-security-policy",
                    "x-content-type-options", "x-frame-options", "referrer-policy",
                    "permissions-policy", "cross-origin-opener-policy",
                    "cross-origin-resource-policy", "cross-origin-embedder-policy"}
LEAK_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-generator", "x-runtime"}
PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                 "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]
MAX_BODY = 8 * 1024 * 1024

USER_AGENTS = {
    "(défaut : vide)": "",
    "Chrome / Windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Firefox / Linux": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Safari / iPhone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
                       "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "curl": "curl/8.5.0",
    "Googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "python-httpx": "python-httpx/0.27",
}

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
           "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "PURGE"]

ATTACK_PAYLOADS = {
    "xss": ["{{canary}}<img src=x onerror=alert(1)>",
            '"><svg onload=alert(1)>',
            "javascript:alert('{{canary}}')"],
    "sqli_time_mysql": ["' OR SLEEP({{delay}})-- -", "' AND SLEEP({{delay}})#"],
    "sqli_time_pg": ["'; SELECT pg_sleep({{delay}})--",
                     "1' AND 1=(SELECT 1 FROM pg_sleep({{delay}}))--"],
    "sqli_error": ["' AND 1=CONVERT(int,@@version)--",
                   "' AND extractvalue(1,concat(0x7e,version()))--"],
    "cmdi": ["; sleep {{delay}}", "| sleep {{delay}}", "`sleep {{delay}}`"],
    "traversal": ["../../../../{{canary}}.txt", "....//....//....//{{canary}}.txt"],
    "open_redirect": ["//evil.com", "https://evil.com", "/\\evil.com"],
    "crlf": ["%0d%0aX-Injected:{{canary}}"],
}

DB_ERROR_PATTERNS = {
    "mysql": [r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException"],
    "postgresql": [r"PostgreSQL.*ERROR", r"pg_query\(\)", r"psql:"],
    "mssql": [r"Microsoft OLE DB.*SQL Server", r"Unclosed quotation mark"],
    "sqlite": [r"SQLite/JDBCDriver", r"System.Data.SQLite"],
}


# ════════════════════════════════════════════════════════════════════════════
#  Modèle de données
# ════════════════════════════════════════════════════════════════════════════
@dataclass
class RequestSpec:
    method: str = "GET"
    url: str = ""
    headers: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    body: bytes = b""
    body_mode: str = "Aucun"
    proxy: str = ""
    timeout: tuple = (10.0, 30.0)
    verify: Any = True
    follow_redirects: bool = True
    max_redirects: int = 10
    http2: bool = False
    auth: tuple = None
    cert: tuple = None
    retries: int = 0

    def clone(self) -> "RequestSpec":
        return replace(self, headers=dict(self.headers), params=dict(self.params),
                       cookies=dict(self.cookies))


@dataclass
class ResponseData:
    error: str = ""
    status: int = 0
    reason: str = ""
    version: str = ""
    url: str = ""
    headers: list = field(default_factory=list)
    set_cookies: list = field(default_factory=list)
    body: bytes = b""
    truncated: bool = False
    elapsed: float = 0.0
    ttfb: float = 0.0
    history: list = field(default_factory=list)
    raw_request: str = ""
    encoding: str = "utf-8"
    tls: dict = field(default_factory=dict)

    @property
    def text(self) -> str:
        return self.body.decode(self.encoding or "utf-8", errors="replace")


@dataclass
class WsFrame:
    direction: str
    opcode: str
    payload: bytes
    ts: float
    elapsed_ms: float = 0.0


@dataclass
class WsResult:
    url: str = ""
    connected: bool = False
    handshake_headers: dict = field(default_factory=dict)
    origin_sent: str = ""
    origin_accepted: bool = False
    subprotocol: str = ""
    frames: list = field(default_factory=list)
    error: str = ""
    close_code: int = 0
    close_reason: str = ""
    elapsed: float = 0.0

    @property
    def frame_count(self) -> int:
        return len(self.frames)

    def texts_recv(self) -> list:
        return [f.payload.decode("utf-8", "replace")
                for f in self.frames if f.direction == "recv" and f.opcode == "text"]


@dataclass
class Check:
    ok: bool
    label: str
    detail: str = ""


@dataclass
class Job:
    name: str
    suite: str = ""
    key: tuple = None
    severity: str = "info"
    test: dict = field(default_factory=dict)
    defaults: dict = field(default_factory=dict)
    vars: dict = field(default_factory=dict)
    spec: RequestSpec = None
    asserts: list = field(default_factory=list)
    capture: dict = field(default_factory=dict)
    skip_if: str = ""
    depends_on: str = ""
    tid: str = ""
    retries: int = 0
    kind: str = "http"
    # "hardening" (défaut) : toutes les assertions vraies ⇒ PASS
    # "vulnerability"       : toutes les assertions vraies ⇒ FAIL (vuln détectée)
    verdict_semantics: str = "hardening"


@dataclass
class TestResult:
    job: Job
    resp: ResponseData
    checks: list
    duration: float = 0.0
    skipped: bool = False
    ws_result: WsResult = None

    def verdict(self) -> tuple:
        if self.skipped:
            return "SKIP", C["muted"]
        if self.resp.error:
            return "ERREUR", C["err"]
        if not self.checks:
            return "INFO", C["info"]
        all_ok = all(c.ok for c in self.checks)
        if getattr(self.job, "verdict_semantics", "hardening") == "vulnerability":
            if all_ok:
                return "FAIL", SEV_COLOR.get(self.job.severity, C["err"])
            return "PASS", C["ok"]
        return ("PASS", C["ok"]) if all_ok else \
               ("FAIL", SEV_COLOR.get(self.job.severity, C["err"]))


# ════════════════════════════════════════════════════════════════════════════
#  Substitution de variables
# ════════════════════════════════════════════════════════════════════════════
_VAR = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


def _resolve(expr: str, vars_: dict) -> str:
    expr = expr.strip()
    if expr.startswith("repeat:"):
        _, ch, n = expr.split(":", 2)
        return ch * int(n)
    if expr.startswith("env:"):
        return os.environ.get(expr[4:].strip(), "")
    if expr.startswith("b64:"):
        return base64.b64encode(str(vars_.get(expr[4:].strip(), "")).encode()).decode()
    if expr.startswith("sha1:"):
        return hashlib.sha1(str(vars_.get(expr[5:].strip(), "")).encode()).hexdigest()
    if expr.startswith("sha256:"):
        return hashlib.sha256(str(vars_.get(expr[8:].strip(), "")).encode()).hexdigest()
    if expr == "uuid":
        import uuid as _uuid
        return str(_uuid.uuid4())
    if expr == "timestamp":
        return str(int(time.time() * 1000))
    return str(vars_.get(expr, ""))


def subst(obj, vars_: dict):
    if isinstance(obj, str):
        return _VAR.sub(lambda m: _resolve(m.group(1), vars_), obj)
    if isinstance(obj, dict):
        return {subst(k, vars_): subst(v, vars_) for k, v in obj.items()}
    if isinstance(obj, list):
        return [subst(v, vars_) for v in obj]
    return obj


def has_header(headers: dict, name: str) -> bool:
    return any(k.lower() == name.lower() for k in headers)


def set_header(headers: dict, name: str, value: str):
    for k in [k for k in headers if k.lower() == name.lower()]:
        del headers[k]
    headers[name] = value


def hget(resp: ResponseData, name: str):
    for k, v in resp.headers:
        if k.lower() == name.lower():
            return v
    return None


def hall(resp: ResponseData, name: str) -> list:
    return [v for k, v in resp.headers if k.lower() == name.lower()]


def _headers_block(resp: ResponseData) -> str:
    """Sérialise le bloc d'en-têtes façon HTTP : 'Name: value\\nName: value...'"""
    return "\n".join(f"{k}: {v}" for k, v in resp.headers)


def _is_private_url(url: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        if host in ("localhost",):
            return True
        addr = ipaddress.ip_address(host)
        return any(addr in n for n in PRIVATE_NETS)
    except ValueError:
        return False


def jpath(obj, path: str):
    if path.startswith("$"):
        path = path.lstrip("$").lstrip(".")
    tokens = re.findall(r"\.?([^.\[\]]+)|\[(\d+|'.*?'|\".*?\")\]", path)
    for key, idx in tokens:
        if key:
            obj = obj[key]
        else:
            i = idx.strip("'\"")
            obj = obj[int(i)] if i.lstrip("-").isdigit() else obj[i]
    return obj


def parse_set_cookie(raw: str) -> tuple:
    parts = [p.strip() for p in raw.split(";")]
    name, _, _ = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name, attrs


# ════════════════════════════════════════════════════════════════════════════
#  Construction de RequestSpec
# ════════════════════════════════════════════════════════════════════════════
def build_spec(test: dict, defaults: dict, vars_: dict) -> RequestSpec:
    d = subst(defaults or {}, vars_)
    t = subst(test.get("request", {}) or {}, vars_)
    headers = {**(d.get("headers") or {}), **(t.get("headers") or {})}
    headers = {k: str(v) for k, v in headers.items() if v is not None}

    base = str(vars_.get("base_url", "")).rstrip("/")
    url = t.get("url") or (base + "/" + str(t.get("path", "")).lstrip("/"))

    body, mode = b"", "Aucun"
    if "json" in t:
        body = json.dumps(t["json"], indent=2, ensure_ascii=False).encode()
        mode = "JSON"
        if not has_header(headers, "Content-Type"):
            headers["Content-Type"] = "application/json"
    elif "form" in t:
        body = urllib.parse.urlencode(t["form"]).encode()
        mode = "Formulaire"
        if not has_header(headers, "Content-Type"):
            headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif "body_file" in t:
        p = Path(str(t["body_file"]))
        body = p.read_bytes() if p.exists() else b""
        mode = "Fichier"
    elif "body" in t:
        body = str(t["body"]).encode()
        mode = "Brut"

    def pick(key, default):
        return t.get(key, d.get(key, default))

    verify = pick("verify", True)
    auth = pick("auth", None)
    if isinstance(auth, dict):
        auth = (auth.get("user", ""), auth.get("password", ""))
    cert = pick("cert", None)
    if isinstance(cert, list) and len(cert) == 2:
        cert = (cert[0], cert[1])

    return RequestSpec(
        method=str(t.get("method", "GET")).upper(), url=url, headers=headers,
        params={**(d.get("params") or {}), **(t.get("params") or {})},
        cookies={**(d.get("cookies") or {}), **(t.get("cookies") or {})},
        body=body, body_mode=mode, proxy=str(pick("proxy", "") or ""),
        timeout=(float(pick("connect_timeout", 10)), float(pick("read_timeout", 30))),
        verify=verify if isinstance(verify, str) else bool(verify),
        follow_redirects=bool(pick("follow_redirects", True)),
        max_redirects=int(pick("max_redirects", 10)),
        http2=bool(pick("http2", False)),
        auth=auth, cert=cert, retries=int(pick("retries", 0)))


# ════════════════════════════════════════════════════════════════════════════
#  Transport HTTP
# ════════════════════════════════════════════════════════════════════════════
def _raw_request(spec: RequestSpec, body: bytes) -> str:
    u = urllib.parse.urlparse(spec.url)
    path = u.path or "/"
    if spec.params:
        path += ("&" if u.query else "?") + urllib.parse.urlencode(spec.params)
    elif u.query:
        path += "?" + u.query
    lines = [f"{spec.method} {path} HTTP/1.1", f"Host: {u.netloc}"]
    for k, v in spec.headers.items():
        lines.append(f"{k}: {v}")
    if spec.cookies:
        lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in spec.cookies.items()))
    if body:
        lines.append(f"Content-Length: {len(body)}")
    out = "\n".join(lines) + "\n\n"
    if body:
        out += body[:20000].decode("utf-8", "replace")
    return out


def _detect_encoding(content_type: str, body: bytes) -> str:
    m = re.search(r"charset=([\w\-]+)", content_type, re.I)
    if m:
        return m.group(1)
    if detect_charset and body:
        try:
            best = detect_charset(body[:4096]).best()
            if best and best.encoding:
                return best.encoding
        except Exception:
            pass
    return "utf-8"


def send_request(spec: RequestSpec, block_private: bool = False) -> ResponseData:
    r = ResponseData()
    if block_private and _is_private_url(spec.url):
        r.error = "Cible privée bloquée (--block-private)"
        return r

    t0 = time.perf_counter()
    raw = _raw_request(spec, spec.body or b"")

    for attempt in range(spec.retries + 1):
        try:
            if HAVE_HTTPX:
                _send_httpx(spec, r, t0, raw)
            elif HAVE_REQUESTS:
                _send_requests(spec, r, t0, raw)
            else:
                raise RuntimeError("Installez httpx ou requests")
            if r.status < 500 or attempt >= spec.retries:
                return r
        except Exception as e:
            r.error = f"{type(e).__name__}: {e}"
            r.elapsed = time.perf_counter() - t0
            if attempt >= spec.retries:
                return r
        time.sleep(min(2 ** attempt * 0.2, 2.0))
    return r


def _send_httpx(spec: RequestSpec, r: ResponseData, t0: float, raw: str):
    proxies = spec.proxy or None
    with httpx.Client(
            verify=spec.verify, http2=spec.http2,
            timeout=httpx.Timeout(spec.timeout[1], connect=spec.timeout[0]),
            follow_redirects=spec.follow_redirects, max_redirects=spec.max_redirects,
            proxy=proxies, trust_env=False,
            cert=spec.cert, auth=spec.auth) as client:
        req = client.build_request(spec.method, spec.url, headers=spec.headers,
                                   params=spec.params, cookies=spec.cookies,
                                   content=spec.body or None)
        resp = client.send(req, stream=False)
        r.ttfb = time.perf_counter() - t0
        chunks, total = [], 0
        for chunk in resp.iter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_BODY:
                r.truncated = True
                break
        r.body = b"".join(chunks)
        r.status, r.reason, r.url = resp.status_code, resp.reason_phrase or "", str(resp.url)
        v = resp.http_version
        r.version = "2" if v == "HTTP/2" else ("1.1" if v == "HTTP/1.1" else "1.0")
        r.headers = [(k, v) for k, v in resp.headers.multi_items()]
        r.set_cookies = resp.headers.get_list("set-cookie")
        r.history = [(h.status_code, str(h.url), h.headers.get("location", "")) for h in resp.history]
        r.raw_request = raw
        r.encoding = _detect_encoding(resp.headers.get("content-type", ""), r.body)
        r.elapsed = time.perf_counter() - t0


def _send_requests(spec: RequestSpec, r: ResponseData, t0: float, raw: str):
    s = requests.Session()
    s.trust_env = False
    s.headers.clear()
    s.max_redirects = spec.max_redirects
    headers = dict(spec.headers)
    if spec.cookies:
        ck = "; ".join(f"{k}={v}" for k, v in spec.cookies.items())
        old = next((v for k, v in headers.items() if k.lower() == "cookie"), None)
        set_header(headers, "Cookie", f"{old}; {ck}" if old else ck)
    req = requests.Request(spec.method, spec.url, headers=headers,
                           params=spec.params or None, data=spec.body or None,
                           auth=spec.auth)
    prep = s.prepare_request(req)
    r.raw_request = raw
    if spec.verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        resp = s.send(prep, timeout=spec.timeout[1], verify=spec.verify,
                      allow_redirects=spec.follow_redirects,
                      proxies={"http": spec.proxy, "https": spec.proxy} if spec.proxy else None,
                      cert=spec.cert)
        r.elapsed = r.ttfb = time.perf_counter() - t0
        r.status, r.reason, r.url = resp.status_code, resp.reason or "", resp.url
        r.version = {10: "1.0", 11: "1.1", 20: "2"}.get(getattr(resp.raw, "version", 11), "1.1")
        r.headers = [(k, v) for k, v in resp.raw.headers.items()]
        r.set_cookies = list(resp.raw.headers.getlist("Set-Cookie"))
        r.body = resp.content[:MAX_BODY]
        r.truncated = len(resp.content) > MAX_BODY
        r.encoding = _detect_encoding(resp.headers.get("Content-Type", ""), r.body)
        r.history = [(h.status_code, h.url, h.headers.get("Location", "")) for h in resp.history]
    finally:
        s.close()


# ════════════════════════════════════════════════════════════════════════════
#  Transport WebSocket
# ════════════════════════════════════════════════════════════════════════════
def run_ws_job(test: dict, block_private: bool = False) -> WsResult:
    if not HAVE_WS:
        return WsResult(error="pip install websockets")
    wscfg = test.get("websocket", {}) or {}
    url = wscfg.get("url", "")
    result = WsResult(url=url)
    if block_private and _is_private_url(url):
        result.error = "Cible privée bloquée"
        return result

    headers = dict(wscfg.get("headers") or {})
    origin = wscfg.get("origin", "")
    if origin:
        result.origin_sent = origin

    t0 = time.perf_counter()
    try:
        with ws_sync.connect(
                url,
                additional_headers=headers if headers else None,
                origin=origin if origin else None,
                subprotocols=wscfg.get("subprotocols"),
                open_timeout=wscfg.get("connect_timeout", 5),
                close_timeout=2) as ws:
            result.connected = True
            result.origin_accepted = bool(origin)
            result.subprotocol = ws.subprotocol or ""
            try:
                result.handshake_headers = dict(ws.response.headers)
            except Exception:
                pass
            for step in wscfg.get("messages", []) or []:
                _ws_step(ws, step, result)
            try:
                ws.close()
            except Exception:
                pass
    except WsConnectionClosed as e:
        result.close_code = getattr(e, "code", 0) or 0
        result.close_reason = getattr(e, "reason", "") or ""
        if not result.error:
            result.error = f"ConnectionClosed: {result.close_code} {result.close_reason}"
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
    result.elapsed = time.perf_counter() - t0
    return result


def _ws_step(ws, step: dict, result: WsResult):
    t_send = time.perf_counter()
    payload = b""
    opcode = "text"
    if "send_text" in step:
        payload = str(step["send_text"]).encode("utf-8")
    elif "send_json" in step:
        payload = json.dumps(step["send_json"], ensure_ascii=False).encode()
    elif "send_binary" in step:
        raw = step["send_binary"]
        payload = bytes.fromhex(raw) if isinstance(raw, str) else raw
        opcode = "binary"
    else:
        return
    try:
        ws.send(payload)
    except Exception as e:
        result.error = f"send error: {e}"
        return
    result.frames.append(WsFrame("send", opcode, payload, t_send))

    expect_timeout = float(step.get("expect_timeout", 3))
    try:
        recv_data = ws.recv(timeout=expect_timeout)
    except TimeoutError:
        return
    except Exception:
        return

    t_recv = time.perf_counter()
    recv_opcode = "text" if isinstance(recv_data, str) else "binary"
    recv_bytes = recv_data.encode("utf-8") if isinstance(recv_data, str) else recv_data
    result.frames.append(WsFrame("recv", recv_opcode, recv_bytes, t_recv,
                                 (t_recv - t_send) * 1000))


# ════════════════════════════════════════════════════════════════════════════
#  Registre d'assertions
# ════════════════════════════════════════════════════════════════════════════
ASSERTIONS: dict = {}


def assertion(name: str):
    def deco(fn):
        ASSERTIONS[name] = fn
        return fn
    return deco


def status_match(code: int, exp) -> bool:
    for e in (exp if isinstance(exp, list) else [exp]):
        if isinstance(e, int) and code == e:
            return True
        if isinstance(e, str):
            eu = e.upper()
            if re.fullmatch(r"\dXX", eu) and str(code)[0] == eu[0]:
                return True
            if "-" in eu:
                a, b = eu.split("-", 1)
                if a.isdigit() and b.isdigit() and int(a) <= code <= int(b):
                    return True
            if eu.isdigit() and code == int(eu):
                return True
    return False


# ── HTTP ───────────────────────────────────────────────────────────────────
@assertion("status")
def _a_status(v, r): return Check(status_match(r.status, v), f"status ∈ {v}", f"reçu {r.status}")


@assertion("status_not")
def _a_status_not(v, r): return Check(not status_match(r.status, v), f"status ∉ {v}", f"reçu {r.status}")


@assertion("header_present")
def _a_hp(v, r):
    val = hget(r, v)
    return Check(val is not None, f"en-tête « {v} » présent", val or "absent")


@assertion("header_absent")
def _a_ha(v, r):
    val = hget(r, v)
    return Check(val is None, f"en-tête « {v} » absent", f"présent : {val}" if val else "")


@assertion("header_equals")
def _a_he(v, r):
    val = hget(r, v["name"])
    ok = val is not None and val.strip().lower() == str(v["value"]).strip().lower()
    return Check(ok, f"{v['name']} == {v['value']}", f"reçu : {val}")


@assertion("header_matches")
def _a_hm(v, r):
    val = hget(r, v["name"])
    ok = val is not None and re.search(v["regex"], val, re.I) is not None
    return Check(ok, f"{v['name']} ~ /{v['regex']}/", f"reçu : {val}")


@assertion("header_not_matches")
def _a_hnm(v, r):
    val = hget(r, v["name"])
    m = re.search(v["regex"], val, re.I) if val else None
    return Check(m is None, f"{v['name']} ≁ /{v['regex']}/", f"reçu : {val}" if m else "")


@assertion("header_count")
def _a_hc(v, r):
    n = len(hall(r, v["name"]))
    return Check(n == int(v["equals"]), f"nb « {v['name']} » == {v['equals']}", f"reçu {n}")


# ── NOUVEAU v3c : bloc brut d'en-têtes (sémantique Nuclei part=header) ─────
@assertion("raw_headers_regex")
def _a_rhr(v, r):
    """Matcher regex sur le bloc d'en-têtes sérialisé 'Name: value\\n...'.
    Équivalent à un matcher Nuclei { type: regex, part: header }."""
    block = _headers_block(r)
    if not block:
        return Check(False, f"bloc en-têtes ~ /{v}/", "aucun en-tête")
    try:
        m = re.search(v, block, re.S | re.I)
    except re.error as e:
        return Check(False, f"bloc en-têtes ~ /{v}/", f"regex invalide : {e}")
    detail = m.group(0)[:120] if m else f"aucun match sur {len(block)} octets"
    return Check(m is not None, f"bloc en-têtes ~ /{v}/", detail)


@assertion("raw_headers_not_regex")
def _a_rhnr(v, r):
    block = _headers_block(r)
    try:
        m = re.search(v, block, re.S | re.I)
    except re.error as e:
        return Check(False, f"bloc en-têtes ≁ /{v}/", f"regex invalide : {e}")
    return Check(m is None, f"bloc en-têtes ≁ /{v}/",
                 m.group(0)[:120] if m else "")


@assertion("raw_headers_contains")
def _a_rhc(v, r):
    """Matcher word sur le bloc d'en-têtes sérialisé.
    Équivalent à un matcher Nuclei { type: word, part: header }."""
    block = _headers_block(r)
    present = str(v) in block
    return Check(present, f"bloc en-têtes contient « {v} »",
                 f"{len(block)} octets" if not present else "")


@assertion("raw_headers_not_contains")
def _a_rhnc(v, r):
    block = _headers_block(r)
    present = str(v) in block
    return Check(not present, f"bloc en-têtes ne contient pas « {v} »",
                 "trouvé" if present else "")


@assertion("body_contains")
def _a_bc(v, r): return Check(v in r.text, f"corps contient « {v} »")


@assertion("body_not_contains")
def _a_bnc(v, r): return Check(v not in r.text, f"corps ne contient pas « {v} »")


@assertion("body_regex")
def _a_br(v, r): return Check(re.search(v, r.text, re.S) is not None, f"corps ~ /{v}/")


@assertion("body_not_regex")
def _a_bnr(v, r):
    m = re.search(v, r.text, re.S)
    return Check(m is None, f"corps ≁ /{v}/", f"trouvé : {m.group(0)[:80]!r}" if m else "")


@assertion("body_empty")
def _a_be(v, r):
    ok = (len(r.body) == 0) == bool(v)
    return Check(ok, "corps vide" if v else "corps non vide", f"{len(r.body)} octets")


@assertion("body_hash")
def _a_bh(v, r):
    algo = v.get("algo", "sha256")
    h = hashlib.new(algo, r.body).hexdigest()
    return Check(h == v["equals"], f"{algo}(body) == {v['equals'][:12]}…", h[:16] + "…")


@assertion("time_lt")
def _a_tl(v, r): return Check(r.elapsed < float(v), f"temps < {v}s", f"{r.elapsed:.3f}s")


@assertion("time_gt")
def _a_tgt(v, r): return Check(r.elapsed > float(v), f"temps > {v}s", f"{r.elapsed:.3f}s")


@assertion("ttfb_lt")
def _a_ttfb(v, r): return Check(r.ttfb < float(v), f"TTFB < {v}s", f"{r.ttfb:.3f}s")


@assertion("json_path")
def _a_jp(v, r):
    try:
        val = jpath(json.loads(r.text), v["path"])
        found = True
    except (KeyError, IndexError, ValueError, TypeError):
        val, found = None, False
    if "equals" in v:
        return Check(found and val == v["equals"], f"{v['path']} == {v['equals']!r}", f"reçu : {val!r}")
    if "type" in v:
        types = {"str": str, "int": int, "float": (int, float), "bool": bool,
                 "list": list, "dict": dict, "null": type(None)}
        want = types.get(v["type"], object)
        return Check(found and isinstance(val, want) and not (v["type"] == "int" and isinstance(val, bool)),
                     f"{v['path']} de type {v['type']}", f"reçu : {type(val).__name__}")
    want = v.get("exists", True)
    return Check(found == bool(want), f"{v['path']} {'existe' if want else 'absent'}",
                 f"valeur : {val!r}" if found else "introuvable")


@assertion("json_schema")
def _a_js(v, r):
    try:
        import jsonschema
    except ImportError:
        return Check(False, "json_schema", "pip install jsonschema")
    try:
        jsonschema.validate(json.loads(r.text), v)
        return Check(True, "JSON conforme au schéma")
    except Exception as e:
        return Check(False, "JSON non conforme", str(e)[:200])


@assertion("cookie_flags")
def _a_cf(v, r):
    need = [x.lower() for x in v.get("require", ["Secure", "HttpOnly", "SameSite"])]
    target = v.get("name", "*")
    if not r.set_cookies:
        return Check(True, "cookies : flags", "aucun cookie émis")
    bad = []
    for raw in r.set_cookies:
        name, attrs = parse_set_cookie(raw)
        if target not in ("*", name):
            continue
        miss = [n for n in need if n not in attrs]
        if miss:
            bad.append(f"{name}: manque {', '.join(miss)}")
    return Check(not bad, f"cookies {target} : {'/'.join(need)}", " ; ".join(bad))


@assertion("cookie_secure_only")
def _a_cso(v, r):
    bad = [parse_set_cookie(c)[0] for c in r.set_cookies
           if "secure" not in parse_set_cookie(c)[1]]
    return Check(not bad, "tous les cookies Secure", ", ".join(bad))


@assertion("redirect_count")
def _a_rc(v, r):
    return Check(len(r.history) == int(v), f"nb redirections == {v}", f"reçu {len(r.history)}")


# ── Attaque ────────────────────────────────────────────────────────────────
@assertion("body_contains_canary")
def _a_bcc(v, r):
    canary = str(v)
    return Check(canary in r.text, f"canary « {canary} » reflété",
                 "présent" if canary in r.text else "absent")


@assertion("location_host_differs")
def _a_lhd(v, r):
    loc = hget(r, "location") or ""
    try:
        host = urllib.parse.urlparse(loc).netloc
        expected = urllib.parse.urlparse(r.url).netloc
        return Check(bool(host) and host != expected, "redirection externe", f"Location: {loc}")
    except Exception:
        return Check(False, "redirection externe", "pas de Location")


@assertion("header_injected")
def _a_hi(v, r):
    val = hget(r, str(v))
    return Check(val is not None, f"en-tête injecté « {v} »", val or "absent")


# ── WebSocket ──────────────────────────────────────────────────────────────
@assertion("ws_connected")
def _a_wsc(v, r):
    return Check(r.connected == bool(v), f"connecté == {v}",
                 "connecté" if r.connected else (r.error or "non connecté"))


@assertion("ws_origin_accepted")
def _a_woa(v, r):
    if not r.origin_sent:
        return Check(False, "Origin accepté", "aucun Origin envoyé")
    ok = r.connected == bool(v)
    return Check(ok, f"Origin {'accepté' if v else 'refusé'}",
                 f"Origin: {r.origin_sent} — {'accepté' if r.connected else 'refusé'}")


@assertion("ws_frame_count_lt")
def _a_wfcl(v, r):
    return Check(r.frame_count < int(v), f"frames < {v}", f"reçu {r.frame_count}")


@assertion("ws_close_code")
def _a_wcc(v, r):
    return Check(r.close_code == int(v), f"close code == {v}", f"reçu {r.close_code}")


@assertion("ws_message_regex")
def _a_wmr(v, r):
    for t in r.texts_recv():
        if re.search(v, t, re.S):
            return Check(True, f"message ~ /{v}/", t[:100])
    return Check(False, f"message ~ /{v}/", f"{len(r.texts_recv())} message(s)")


@assertion("ws_echo_ok")
def _a_weo(v, r):
    sent = [f for f in r.frames if f.direction == "send"]
    if not sent:
        return Check(False, "écho", "aucun message envoyé")
    last = sent[-1].payload
    for f in r.frames:
        if f.direction == "recv" and f.payload == last:
            return Check(True, "écho identique", last[:60].decode("utf-8", "replace"))
    return Check(False, "écho identique", f"envoyé: {last[:60]!r}")


@assertion("ws_latency_lt")
def _a_wll(v, r):
    recv = [f for f in r.frames if f.direction == "recv" and f.elapsed_ms > 0]
    if not recv:
        return Check(True, "latence", "aucune frame reçue")
    worst = max(f.elapsed_ms for f in recv)
    return Check(worst < float(v) * 1000, f"latence < {v}s", f"max {worst:.0f} ms")


@assertion("ws_subprotocol")
def _a_wsp(v, r):
    return Check(r.subprotocol == str(v), f"subprotocol == {v}",
                 f"négocié: {r.subprotocol or '(aucun)'}")


def evaluate(asserts: list, resp) -> list:
    if isinstance(resp, ResponseData) and resp.error and not isinstance(resp, WsResult):
        return [Check(False, "Connexion / transport", resp.error)]
    out = []
    for a in asserts or []:
        if not isinstance(a, dict) or len(a) != 1:
            out.append(Check(False, "assertion invalide", str(a)))
            continue
        (k, v), = a.items()
        fn = ASSERTIONS.get(k)
        if not fn:
            out.append(Check(False, f"assertion inconnue « {k} »"))
            continue
        try:
            out.append(fn(v, resp))
        except Exception as e:
            out.append(Check(False, k, f"erreur d'évaluation : {e}"))
    return out


# ════════════════════════════════════════════════════════════════════════════
#  Capture & cURL
# ════════════════════════════════════════════════════════════════════════════
def do_capture(capture: dict, resp: ResponseData, vars_: dict):
    for name, rule in (capture or {}).items():
        val = None
        try:
            if "header" in rule:
                val = hget(resp, rule["header"])
            elif "json_path" in rule:
                val = jpath(json.loads(resp.text), rule["json_path"])
            elif "regex" in rule:
                m = re.search(rule["regex"], resp.text, re.S)
                if m:
                    val = m.group(1) if m.groups() else m.group(0)
            elif "cookie" in rule:
                for raw in resp.set_cookies:
                    n, _ = parse_set_cookie(raw)
                    if n == rule["cookie"]:
                        val = raw.split(";")[0].partition("=")[2]
                        break
        except Exception:
            val = None
        if val is not None:
            vars_[name] = str(val)


def to_curl(spec: RequestSpec) -> str:
    u = urllib.parse.urlparse(spec.url)
    url = spec.url
    if spec.params:
        url += ("&" if u.query else "?") + urllib.parse.urlencode(spec.params)
    p = ["curl", "-i", "-X", spec.method, "--compressed"]
    if spec.verify is False:
        p.append("-k")
    if spec.follow_redirects:
        p += ["-L", "--max-redirs", str(spec.max_redirects)]
    if spec.proxy:
        p += ["-x", spec.proxy]
    p += ["--connect-timeout", str(int(spec.timeout[0])), "--max-time", str(int(spec.timeout[1]))]
    if spec.http2:
        p.append("--http2")
    if spec.cert:
        p += ["--cert", spec.cert[0], "--key", spec.cert[1]]
    if spec.auth:
        p += ["-u", f"{spec.auth[0]}:{spec.auth[1]}"]
    for k, v in spec.headers.items():
        p += ["-H", f"{k}: {v}"]
    if spec.cookies:
        p += ["-b", "; ".join(f"{k}={v}" for k, v in spec.cookies.items())]
    if spec.body:
        p += ["--data-raw", spec.body.decode("utf-8", "replace")]
    p.append(url)
    return " ".join(shlex.quote(x) for x in p)


# ════════════════════════════════════════════════════════════════════════════
#  Moteur d'attaque
# ════════════════════════════════════════════════════════════════════════════
def _inject_body(original: bytes, param: str, payload: str) -> bytes:
    try:
        data = json.loads(original.decode("utf-8"))
        if isinstance(data, dict) and param in data:
            data[param] = payload
            return json.dumps(data, ensure_ascii=False).encode()
    except (ValueError, UnicodeDecodeError):
        pass
    try:
        parsed = urllib.parse.parse_qs(original.decode("utf-8"))
        if param in parsed:
            parsed[param] = [payload]
            return urllib.parse.urlencode(parsed, doseq=True).encode()
    except Exception:
        pass
    return original


def run_attack(spec: RequestSpec, attack: dict, vars_: dict,
               block_private: bool = False) -> tuple:
    checks = []
    canary = vars_.get("canary", "canary-xyz")
    delay = vars_.get("delay", "3")
    payloads = subst(attack.get("payloads") or ATTACK_PAYLOADS.get(attack.get("category", ""), []),
                     {**vars_, "canary": canary, "delay": delay})
    success_if = subst(attack.get("success_if") or [], vars_)
    last = None

    for p in payloads:
        s = spec.clone()
        target = attack.get("target", "query")
        param = attack.get("param", "q")
        if target == "query":
            s.params[param] = p
        elif target == "body":
            s.body = _inject_body(s.body, param, p)
        elif target == "header":
            set_header(s.headers, param, p)
        resp = send_request(s, block_private)
        last = resp
        if attack.get("category") == "sqli_error":
            for dbms, patterns in DB_ERROR_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, resp.text, re.I):
                        checks.append(Check(False, f"Erreur DBMS ({dbms})",
                                            f"payload: {p[:60]}"))
                        break
        checks += evaluate(success_if, resp)
    return checks, last


# ════════════════════════════════════════════════════════════════════════════
#  Chargement de templates
# ════════════════════════════════════════════════════════════════════════════
def load_suite(path: Path) -> dict:
    if not HAVE_YAML:
        raise RuntimeError("pyyaml requis")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data.get("tests"), list):
        raise ValueError(f"{path.name}: « tests » doit être une liste")
    return data


def resolve_env_files(suite: dict) -> dict:
    v = dict(suite.get("variables") or {})
    for envfile in suite.get("env_files") or []:
        p = Path(envfile)
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, val = line.partition("=")
                    v[k.strip()] = val.strip().strip('"').strip("'")
    return v


def expand_matrix(suite: dict) -> list:
    out = []
    base_tests = suite.get("tests") or []
    matrix = suite.get("matrix") or []
    if not matrix:
        return [dict(t) for t in base_tests]
    for row in matrix:
        for t in base_tests:
            out.append({**t, "_matrix": row})
    return out


# ════════════════════════════════════════════════════════════════════════════
#  Engine unifié HTTP / WebSocket / Attaque
# ════════════════════════════════════════════════════════════════════════════
class Engine:
    def __init__(self, base_url: str = "", block_private: bool = False, delay_ms: int = 0):
        self.base_url = base_url
        self.block_private = block_private
        self.delay_ms = delay_ms
        self.runtime_vars: dict = {}
        self.results: list = []

    def _vars(self, job: Job) -> dict:
        v = {**job.vars, **self.runtime_vars}
        if self.base_url:
            v["base_url"] = self.base_url
        return v

    def run_job(self, job: Job) -> TestResult:
        t0 = time.perf_counter()
        vars_ = self._vars(job)
        if job.skip_if:
            cond = subst(job.skip_if, vars_)
            if cond.strip().lower() in ("true", "1", "yes"):
                return TestResult(job, ResponseData(), [], 0.0, skipped=True)

        try:
            if job.kind == "websocket" or job.test.get("type") == "websocket":
                ws_res = run_ws_job(job.test, self.block_private)
                checks = evaluate(subst(job.asserts, vars_), ws_res)
                fake = ResponseData(
                    error=ws_res.error,
                    status=101 if ws_res.connected else 0,
                    reason="Switching Protocols" if ws_res.connected else "WS Error",
                    url=ws_res.url, elapsed=ws_res.elapsed,
                    headers=list(ws_res.handshake_headers.items()))
                return TestResult(job, fake, checks, time.perf_counter() - t0,
                                  ws_result=ws_res)

            if job.kind == "attack" or job.test.get("mode") == "attack":
                spec = build_spec(job.test, job.defaults, vars_)
                attack = subst(job.test.get("attack", {}) or {}, vars_)
                checks, last = run_attack(spec, attack, vars_, self.block_private)
                return TestResult(job, last or ResponseData(error="Aucune réponse"),
                                  checks, time.perf_counter() - t0)

            spec = job.spec or build_spec(job.test, job.defaults, vars_)
            if job.retries:
                spec = replace(spec, retries=job.retries)
            resp = send_request(spec, self.block_private)
        except Exception as e:
            resp = ResponseData(error=f"{type(e).__name__}: {e}")

        if not resp.error:
            do_capture(subst(job.capture, vars_), resp, self.runtime_vars)
        checks = evaluate(subst(job.asserts, {**vars_, **self.runtime_vars}), resp)
        return TestResult(job, resp, checks, time.perf_counter() - t0)

    def run(self, jobs: Iterable, concurrency: int = 1,
            progress: Callable = None, stop_flag: Callable = lambda: False) -> list:
        jobs = list(jobs)
        total = len(jobs)
        self.results = []
        if concurrency <= 1:
            for i, j in enumerate(jobs, 1):
                if stop_flag():
                    break
                r = self.run_job(j)
                self.results.append(r)
                if progress:
                    progress(i, total, r)
                if self.delay_ms:
                    time.sleep(self.delay_ms / 1000)
        else:
            done = 0
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                futures = {ex.submit(self.run_job, j): j for j in jobs}
                for f in as_completed(futures):
                    if stop_flag():
                        break
                    r = f.result()
                    self.results.append(r)
                    done += 1
                    if progress:
                        progress(done, total, r)
        return self.results


# ════════════════════════════════════════════════════════════════════════════
#  Exporteurs
# ════════════════════════════════════════════════════════════════════════════
def results_to_json(results: list) -> str:
    out = []
    for r in results:
        out.append({"test": r.job.name, "id": r.job.tid, "suite": r.job.suite,
                    "kind": r.job.kind, "severity": r.job.severity,
                    "verdict_semantics": getattr(r.job, "verdict_semantics", "hardening"),
                    "verdict": r.verdict()[0],
                    "status": r.resp.status, "elapsed_s": round(r.resp.elapsed, 4),
                    "error": r.resp.error, "url": r.resp.url,
                    "checks": [{"ok": c.ok, "label": c.label, "detail": c.detail}
                               for c in r.checks]})
    return json.dumps(out, indent=2, ensure_ascii=False)


def results_to_junit(results: list) -> str:
    total = len(results)
    fails = [r for r in results if r.verdict()[0] == "FAIL"]
    errs = [r for r in results if r.verdict()[0] == "ERREUR"]
    skips = [r for r in results if r.skipped]
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             f'<testsuite name="http-debugger" tests="{total}" failures="{len(fails)}" '
             f'errors="{len(errs)}" skipped="{len(skips)}">']
    for r in results:
        verdict = r.verdict()[0]
        cls = html.escape(r.job.suite or "default")
        name = html.escape(r.job.name)
        t = f'{r.resp.elapsed:.3f}'
        if verdict == "SKIP":
            lines.append(f'  <testcase classname="{cls}" name="{name}" time="0"><skipped/></testcase>')
        elif verdict == "PASS":
            lines.append(f'  <testcase classname="{cls}" name="{name}" time="{t}"/>')
        elif verdict == "ERREUR":
            lines.append(f'  <testcase classname="{cls}" name="{name}" time="{t}">'
                         f'<error message="{html.escape(r.resp.error)}"/></testcase>')
        else:
            det = " ; ".join(f"{c.label} ({c.detail})" for c in r.checks if not c.ok)
            lines.append(f'  <testcase classname="{cls}" name="{name}" time="{t}">'
                         f'<failure message="{html.escape(det[:500])}"/></testcase>')
    lines.append('</testsuite>')
    return "\n".join(lines)


def results_to_html(results: list) -> str:
    rows = []
    for r in results:
        v, col = r.verdict()
        det = " ; ".join(f"{c.label} — {c.detail}" for c in r.checks if not c.ok) or r.resp.error
        rows.append(f'<tr><td style="color:{col};font-weight:bold">{v}</td>'
                    f'<td>{html.escape(r.job.severity)}</td>'
                    f'<td>{html.escape(r.job.kind)}</td>'
                    f'<td>{html.escape(r.job.name)}</td>'
                    f'<td>{r.resp.status or "—"}</td>'
                    f'<td>{r.resp.elapsed*1000:.0f} ms</td>'
                    f'<td>{html.escape(det)}</td></tr>')
    return ("<html><head><meta charset='utf-8'><style>"
            "body{font-family:system-ui;background:#171926;color:#e6e8f2;padding:24px}"
            "table{border-collapse:collapse;width:100%}"
            "th,td{padding:8px;border-bottom:1px solid #363b5a;text-align:left}"
            "th{color:#8b7cf6}</style></head><body><h1>HTTP Debugger v3c — Rapport</h1>"
            "<table><tr><th>Verdict</th><th>Sév.</th><th>Type</th><th>Test</th>"
            "<th>HTTP</th><th>Temps</th><th>Détail</th></tr>"
            + "".join(rows) + "</table></body></html>")


# ════════════════════════════════════════════════════════════════════════════
#  CLI (CI/headless)
# ════════════════════════════════════════════════════════════════════════════
def cli_main(args) -> int:
    folder = Path(args.cli)
    files = sorted([*folder.glob("*.yaml"), *folder.glob("*.yml")])
    jobs = []
    for path in files:
        try:
            suite = load_suite(path)
        except Exception as e:
            print(f"[ERREUR] {path.name}: {e}", file=sys.stderr)
            continue
        base_vars = resolve_env_files(suite)
        suite["variables"] = base_vars
        for t in expand_matrix(suite):
            mvars = dict(base_vars)
            mvars.update(t.pop("_matrix", {}) or {})
            kind = "websocket" if t.get("type") == "websocket" else \
                   "attack" if t.get("mode") == "attack" else "http"
            jobs.append(Job(name=str(t.get("name", t.get("id", path.stem))),
                            suite=str(suite.get("name", path.stem)),
                            severity=str(t.get("severity", "info")).lower(),
                            test=t, defaults=suite.get("defaults") or {},
                            vars=mvars, asserts=t.get("assert") or [],
                            capture=t.get("capture") or {},
                            skip_if=str(t.get("skip_if", "")),
                            tid=str(t.get("id", "")), kind=kind,
                            retries=int(t.get("retries", 0)),
                            verdict_semantics=str(t.get("verdict_semantics",
                                                        "hardening")).lower()))
    if not jobs:
        print("Aucun test trouvé.", file=sys.stderr)
        return 2

    engine = Engine(base_url=args.base_url, block_private=args.block_private,
                    delay_ms=args.delay)

    def on_progress(i, n, r):
        v, _ = r.verdict()
        print(f"[{i}/{n}] {v:7s} {r.job.name}"
              + (f" — {r.resp.error}" if r.resp.error else ""),
              file=sys.stderr)
    results = engine.run(jobs, concurrency=args.concurrency, progress=on_progress)

    if args.junit:
        Path(args.junit).write_text(results_to_junit(results), encoding="utf-8")
    if args.json:
        Path(args.json).write_text(results_to_json(results), encoding="utf-8")
    if args.html:
        Path(args.html).write_text(results_to_html(results), encoding="utf-8")

    worst = max(results, key=lambda x: SEV_ORDER.get(x.job.severity, 0), default=None)
    n_fail = sum(r.verdict()[0] == "FAIL" for r in results)
    n_err = sum(r.verdict()[0] == "ERREUR" for r in results)
    if args.fail_on == "any" and (n_fail or n_err):
        return 1
    if args.fail_on == "high" and worst and \
            worst.job.severity in ("high", "critical") and \
            worst.verdict()[0] in ("FAIL", "ERREUR"):
        return 1
    return 0


# ════════════════════════════════════════════════════════════════════════════
#  GUI PySide6
# ════════════════════════════════════════════════════════════════════════════
def gui_main(template_dir: Path = None) -> int:
    from PySide6.QtCore import Qt, QThread, Signal
    from PySide6.QtGui import (QColor, QFont, QKeySequence, QShortcut,
                               QSyntaxHighlighter, QTextCharFormat)
    from PySide6.QtWidgets import (
        QAbstractItemView, QApplication, QCheckBox, QComboBox, QDoubleSpinBox,
        QFileDialog, QFormLayout, QHBoxLayout, QHeaderView, QInputDialog,
        QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
        QProgressBar, QPushButton, QSpinBox, QSplitter, QTableWidget,
        QTableWidgetItem, QTabWidget, QTextEdit, QTreeWidget, QTreeWidgetItem,
        QVBoxLayout, QWidget)

    QSS = """
    * { font-family:'Inter','Segoe UI','Ubuntu',sans-serif; font-size:13px; }
    QMainWindow, QWidget { background:%(bg)s; color:%(text)s; }
    QSplitter::handle { background:%(border)s; }
    QLabel[class="h"] { color:%(accent2)s; font-weight:700; letter-spacing:1px; }
    QLabel[class="muted"] { color:%(muted)s; }
    QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {
        background:%(panel)s; border:1px solid %(border)s; border-radius:6px;
        padding:5px 8px; color:%(text)s; }
    QPlainTextEdit, QTextEdit { font-family:'JetBrains Mono','Consolas',monospace; font-size:12px; }
    QPushButton { background:%(panel2)s; border:1px solid %(border)s; border-radius:6px; padding:6px 14px; }
    QPushButton:hover { border-color:%(accent)s; }
    QPushButton:disabled { color:%(muted)s; }
    QPushButton[class="primary"] { background:%(accent)s; color:#12131f; font-weight:700; border:none; }
    QPushButton[class="primary"]:hover { background:%(accent2)s; }
    QPushButton[class="danger"] { background:transparent; border:1px solid %(err)s; color:%(err)s; }
    QTabWidget::pane { border:1px solid %(border)s; border-radius:6px; }
    QTabBar::tab { background:%(panel)s; padding:7px 14px; color:%(muted)s; }
    QTabBar::tab:selected { background:%(panel2)s; color:%(text)s; border-bottom:2px solid %(accent)s; }
    QTableWidget, QTreeWidget { background:%(panel)s; alternate-background-color:#232640;
        border:1px solid %(border)s; border-radius:6px; }
    QHeaderView::section { background:%(panel2)s; color:%(muted)s; padding:5px 8px; }
    QProgressBar { background:%(panel)s; border:1px solid %(border)s; border-radius:6px;
        text-align:center; height:14px; }
    QProgressBar::chunk { background:%(accent)s; border-radius:5px; }
    """ % C

    def fmt(color, bold=False):
        f = QTextCharFormat()
        f.setForeground(QColor(color))
        if bold:
            f.setFontWeight(QFont.Weight.Bold)
        return f

    class CodeHighlighter(QSyntaxHighlighter):
        def __init__(self, doc):
            super().__init__(doc)
            self.rules = [
                (re.compile(r'"(?:\\.|[^"\\])*"(?=\s*:)'), fmt(C["accent2"], True)),
                (re.compile(r'"(?:\\.|[^"\\])*"'), fmt(C["ok"])),
                (re.compile(r"\b-?\d+(?:\.\d+)?\b"), fmt(C["orange"])),
                (re.compile(r"\b(?:true|false|null)\b"), fmt(C["pink"], True)),
            ]

        def highlightBlock(self, text):
            for rx, f in self.rules:
                for m in rx.finditer(text):
                    self.setFormat(m.start(), m.end() - m.start(), f)

    class KVTable(QTableWidget):
        def __init__(self, k="Nom", v="Valeur"):
            super().__init__(0, 3)
            self.setHorizontalHeaderLabels(["", k, v])
            h = self.horizontalHeader()
            h.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
            h.setStretchLastSection(True)
            self.setColumnWidth(0, 34)
            self.setColumnWidth(1, 240)
            self.verticalHeader().hide()
            self.setAlternatingRowColors(True)
            self.itemChanged.connect(lambda _: self._ensure_blank())
            self._ensure_blank()

        def _add_row(self, k="", v="", on=True):
            self.blockSignals(True)
            r = self.rowCount()
            self.insertRow(r)
            it = QTableWidgetItem()
            it.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            it.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
            self.setItem(r, 0, it)
            self.setItem(r, 1, QTableWidgetItem(k))
            self.setItem(r, 2, QTableWidgetItem(v))
            self.blockSignals(False)

        def _ensure_blank(self):
            last = self.rowCount() - 1
            if last < 0 or self.item(last, 1).text() or self.item(last, 2).text():
                self._add_row()

        def keyPressEvent(self, e):
            if e.key() == Qt.Key.Key_Delete:
                for r in sorted({i.row() for i in self.selectedItems()}, reverse=True):
                    self.removeRow(r)
                self._ensure_blank()
            else:
                super().keyPressEvent(e)

        def to_dict(self):
            out = {}
            for r in range(self.rowCount()):
                k = self.item(r, 1).text().strip()
                if k and self.item(r, 0).checkState() == Qt.CheckState.Checked:
                    out[k] = self.item(r, 2).text()
            return out

        def set_dict(self, d):
            self.blockSignals(True)
            self.setRowCount(0)
            self.blockSignals(False)
            for k, v in (d or {}).items():
                self._add_row(str(k), str(v))
            self._ensure_blank()

    def make_table(headers, widths=None):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.verticalHeader().hide()
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.horizontalHeader().setStretchLastSection(True)
        for i, w in enumerate(widths or []):
            t.setColumnWidth(i, w)
        return t

    def cell(text, color=None, bold=False, tip=None):
        it = QTableWidgetItem(text)
        if color:
            it.setForeground(QColor(color))
        if bold:
            f = it.font()
            f.setBold(True)
            it.setFont(f)
        if tip:
            it.setToolTip(tip)
        return it

    def status_color(code):
        if code == 0: return C["err"]
        if code < 200: return C["info"]
        if code < 300: return C["ok"]
        if code < 400: return C["info"]
        if code < 500: return C["warn"]
        return C["err"]

    def human(n):
        for u in ("o", "Ko", "Mo", "Go"):
            if n < 1024:
                return f"{n:.0f} {u}" if u == "o" else f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} To"

    # ── Vue réponse ────────────────────────────────────────────────────
    class ResponseView(QWidget):
        def __init__(self):
            super().__init__()
            self.last = None
            lay = QVBoxLayout(self)
            lay.setContentsMargins(0, 0, 0, 0)
            top = QHBoxLayout()
            self.badge = QLabel("—")
            self.badge.setStyleSheet(f"background:{C['panel2']};color:{C['muted']};"
                                     "border-radius:8px;padding:4px 14px;font-weight:700;")
            self.time_lbl, self.size_lbl, self.url_lbl = QLabel(""), QLabel(""), QLabel("")
            for w in (self.time_lbl, self.size_lbl, self.url_lbl):
                w.setProperty("class", "muted")
            self.pretty = QCheckBox("Formater")
            self.pretty.setChecked(True)
            self.pretty.toggled.connect(self._refresh_body)
            top.addWidget(self.badge); top.addWidget(self.time_lbl)
            top.addWidget(self.size_lbl); top.addWidget(self.url_lbl, 1)
            top.addWidget(self.pretty)
            lay.addLayout(top)

            self.tabs = QTabWidget()
            self.body = QPlainTextEdit(readOnly=True)
            CodeHighlighter(self.body.document())
            self.headers = make_table(["En-tête", "Valeur"], [260])
            self.cookies = make_table(["Cookie", "Valeur", "Secure", "HttpOnly", "SameSite"],
                                      [160, 220, 70, 80, 90])
            self.raw = QTextEdit(readOnly=True)
            self.redirects = make_table(["Code", "URL", "→ Location"], [70, 380])
            self.checks = make_table(["", "Assertion", "Détail"], [34, 340])
            self.frames = make_table(["Dir", "Opcode", "Taille", "Latence", "Payload"],
                                     [60, 80, 80, 90])
            for w, n in ((self.body, "Corps"), (self.headers, "En-têtes"),
                         (self.cookies, "Cookies"), (self.raw, "Brut"),
                         (self.redirects, "Redirections"),
                         (self.checks, "Assertions"), (self.frames, "Frames WS")):
                self.tabs.addTab(w, n)
            lay.addWidget(self.tabs, 1)

        def _body_text(self, r):
            if r.error:
                return r.error
            txt = r.text
            if len(r.body) > 2_000_000:
                txt = txt[:2_000_000] + "\n… [tronqué] …"
            elif self.pretty.isChecked():
                try:
                    txt = json.dumps(json.loads(txt), indent=2, ensure_ascii=False)
                except ValueError:
                    pass
            if r.truncated:
                txt += f"\n\n⚠ Corps tronqué à {human(len(r.body))}"
            return txt

        def _refresh_body(self):
            if self.last:
                self.body.setPlainText(self._body_text(self.last[0]))

        def show_result(self, r, checks, ws_result=None):
            self.last = (r, checks)
            if r.error:
                txt, col = "ERREUR", C["err"]
            else:
                txt, col = f"{r.status} {r.reason}".strip(), status_color(r.status)
            self.badge.setText(txt)
            self.badge.setStyleSheet(f"background:{col};color:#12131f;border-radius:8px;"
                                     "padding:4px 14px;font-weight:700;")
            self.time_lbl.setText(f"⏱ {r.elapsed*1000:.0f} ms")
            self.size_lbl.setText(f"▣ {human(len(r.body))}")
            self.url_lbl.setText(r.url)
            self.body.setPlainText(self._body_text(r))

            self.headers.setRowCount(0)
            for k, v in r.headers:
                kl = k.lower()
                kc = C["ok"] if kl in SECURITY_HEADERS else \
                     C["orange"] if kl in LEAK_HEADERS else C["cyan"]
                row = self.headers.rowCount()
                self.headers.insertRow(row)
                self.headers.setItem(row, 0, cell(k, kc, True))
                self.headers.setItem(row, 1, cell(v))

            self.cookies.setRowCount(0)
            for raw in r.set_cookies:
                name, attrs = parse_set_cookie(raw)
                val = raw.split(";")[0].partition("=")[2]
                row = self.cookies.rowCount()
                self.cookies.insertRow(row)
                self.cookies.setItem(row, 0, cell(name, C["accent2"], True))
                self.cookies.setItem(row, 1, cell(val))
                for ci, flag in ((2, "secure"), (3, "httponly"), (4, "samesite")):
                    present = flag in attrs
                    lbl = ("✔ " + attrs[flag]).strip() if present and attrs[flag] else \
                          "✔" if present else "✘"
                    self.cookies.setItem(row, ci, cell(lbl,
                                          C["ok"] if present else C["err"], True))

            raw_lines = [f"HTTP/{r.version} {r.status} {r.reason}"] + \
                        [f"{k}: {v}" for k, v in r.headers]
            self.raw.setPlainText("\n".join(raw_lines) + "\n\n" + r.text[:20000])

            self.redirects.setRowCount(0)
            for code, url, loc in r.history:
                row = self.redirects.rowCount()
                self.redirects.insertRow(row)
                self.redirects.setItem(row, 0, cell(str(code), status_color(code), True))
                self.redirects.setItem(row, 1, cell(url))
                self.redirects.setItem(row, 2, cell(loc, C["cyan"]))

            self.checks.setRowCount(0)
            for c in checks:
                row = self.checks.rowCount()
                self.checks.insertRow(row)
                self.checks.setItem(row, 0, cell("✔" if c.ok else "✘",
                                     C["ok"] if c.ok else C["err"], True))
                self.checks.setItem(row, 1, cell(c.label))
                self.checks.setItem(row, 2, cell(c.detail, C["muted"]))
            okn = sum(c.ok for c in checks)
            self.tabs.setTabText(5, f"Assertions ({okn}/{len(checks)})"
                                if checks else "Assertions")

            self.frames.setRowCount(0)
            if ws_result:
                for f in ws_result.frames:
                    row = self.frames.rowCount()
                    self.frames.insertRow(row)
                    dir_col = C["accent2"] if f.direction == "send" else C["ok"]
                    self.frames.setItem(row, 0, cell(f.direction, dir_col, True))
                    self.frames.setItem(row, 1, cell(f.opcode, C["cyan"]))
                    self.frames.setItem(row, 2, cell(human(len(f.payload))))
                    self.frames.setItem(row, 3, cell(f"{f.elapsed_ms:.0f} ms", C["muted"]))
                    payload_txt = f.payload[:200].decode("utf-8", "replace")
                    self.frames.setItem(row, 4, cell(payload_txt))
                self.tabs.setTabText(6, f"Frames WS ({len(ws_result.frames)})")
            else:
                self.tabs.setTabText(6, "Frames WS")

    # ── Thread d'exécution ────────────────────────────────────────────
    class Runner(QThread):
        result = Signal(object)
        progress = Signal(int, int)
        done = Signal()

        def __init__(self, engine, jobs, concurrency):
            super().__init__()
            self.engine = engine
            self.jobs = jobs
            self.concurrency = concurrency
            self._stop = False

        def stop(self):
            self._stop = True

        def run(self):
            def progress(i, n, r):
                self.progress.emit(i, n)
                self.result.emit(r)
            try:
                self.engine.run(self.jobs, self.concurrency, progress,
                                lambda: self._stop)
            finally:
                self.done.emit()

    # ── Fenêtre principale ────────────────────────────────────────────
    class MainWindow(QMainWindow):
        def __init__(self, folder=None):
            super().__init__()
            self.setWindowTitle("HTTP Debugger v3c")
            self.resize(1600, 960)
            self.template_dir = None            # ← patch v3b conservé
            self.suites = []
            self.results = []
            self.item_map = {}
            self.runner = None
            self.current_asserts = []
            self.current_sev = "info"
            self.current_capture = {}
            self._build_ui()
            QShortcut(QKeySequence("Ctrl+Return"), self, activated=self.send_manual)
            QShortcut(QKeySequence("Ctrl+Shift+V"), self,
                      activated=self.import_curl_clipboard)
            if folder and folder.is_dir():
                self.load_templates(folder)

        def _lbl(self, t):
            l = QLabel(t); l.setProperty("class", "muted"); return l

        def _build_ui(self):
            split = QSplitter(Qt.Orientation.Horizontal)
            split.addWidget(self._build_left())
            right = QSplitter(Qt.Orientation.Vertical)
            right.addWidget(self._build_request_panel())
            right.addWidget(self._build_result_panel())
            right.setSizes([420, 540])
            split.addWidget(right)
            split.setSizes([340, 1260])
            self.setCentralWidget(split)
            self.statusBar().showMessage(
                "Prêt — Ctrl+Entrée envoyer, Ctrl+Maj+V coller cURL")

        def _build_left(self):
            w = QWidget(); lay = QVBoxLayout(w)
            title = QLabel("TEMPLATES YAML"); title.setProperty("class", "h")
            lay.addWidget(title)
            row = QHBoxLayout()
            self.dir_lbl = QLabel("aucun dossier"); self.dir_lbl.setProperty("class", "muted")
            b_open = QPushButton("Ouvrir…"); b_open.clicked.connect(self.choose_dir)
            b_reload = QPushButton("↻"); b_reload.setFixedWidth(36)
            b_reload.clicked.connect(
                lambda: (d := getattr(self, "template_dir", None))
                        and self.load_templates(d))   # ← patch v3b conservé
            row.addWidget(self.dir_lbl, 1); row.addWidget(b_open); row.addWidget(b_reload)
            lay.addLayout(row)
            lay.addWidget(self._lbl("Cible (base_url)"))
            self.base_url = QLineEdit("http://localhost:8080")
            lay.addWidget(self.base_url)
            self.filter = QLineEdit(); self.filter.setPlaceholderText("Filtrer…")
            self.filter.textChanged.connect(self._filter_tree)
            lay.addWidget(self.filter)
            self.tree = QTreeWidget(); self.tree.setHeaderHidden(True)
            self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
            self.tree.itemDoubleClicked.connect(self.load_test_into_editor)
            lay.addWidget(self.tree, 1)
            row = QHBoxLayout()
            row.addWidget(self._lbl("Délai (ms)"))
            self.delay = QSpinBox(); self.delay.setRange(0, 60000); row.addWidget(self.delay)
            row.addWidget(self._lbl("Concurrence"))
            self.conc = QSpinBox(); self.conc.setRange(1, 32); row.addWidget(self.conc)
            lay.addLayout(row)
            row = QHBoxLayout()
            self.btn_run = QPushButton("▶ Lancer")
            self.btn_run.setProperty("class", "primary")
            self.btn_run.clicked.connect(self.run_selection)
            self.btn_stop = QPushButton("■")
            self.btn_stop.setProperty("class", "danger")
            self.btn_stop.setFixedWidth(40); self.btn_stop.setEnabled(False)
            self.btn_stop.clicked.connect(lambda: self.runner and self.runner.stop())
            row.addWidget(self.btn_run, 1); row.addWidget(self.btn_stop)
            lay.addLayout(row)
            self.progress = QProgressBar(); self.progress.setTextVisible(False)
            lay.addWidget(self.progress)
            return w

        def _build_request_panel(self):
            w = QWidget(); lay = QVBoxLayout(w)
            bar = QHBoxLayout()
            self.method = QComboBox(); self.method.setEditable(True)
            self.method.addItems(METHODS); self.method.setMinimumWidth(110)
            self.url = QLineEdit()
            self.url.setPlaceholderText("http://localhost:8080/api/health")
            self.url.returnPressed.connect(self.send_manual)
            self.btn_send = QPushButton("Envoyer ➤")
            self.btn_send.setProperty("class", "primary")
            self.btn_send.clicked.connect(self.send_manual)
            b_curl = QPushButton("curl"); b_curl.clicked.connect(self.copy_curl)
            b_paste = QPushButton("Coller cURL")
            b_paste.clicked.connect(self.import_curl_clipboard)
            b_save = QPushButton("Enregistrer")
            b_save.clicked.connect(self.save_yaml)
            bar.addWidget(self.method); bar.addWidget(self.url, 1)
            bar.addWidget(self.btn_send); bar.addWidget(b_curl)
            bar.addWidget(b_paste); bar.addWidget(b_save)
            lay.addLayout(bar)
            self.tpl_lbl = QLabel("")
            self.tpl_lbl.setStyleSheet(f"color:{C['accent2']};")
            lay.addWidget(self.tpl_lbl)

            self.tabs = QTabWidget()
            self.params = KVTable("Paramètre", "Valeur")
            self.hdrs = KVTable("En-tête", "Valeur")
            self.hdrs.set_dict({"Accept": "*/*", "Accept-Encoding": "gzip, deflate"})
            self.cooks = KVTable("Cookie", "Valeur")

            body_w = QWidget(); bl = QVBoxLayout(body_w)
            brow = QHBoxLayout()
            self.body_mode = QComboBox()
            self.body_mode.addItems(["Aucun", "Brut", "JSON", "Formulaire"])
            b_fmt = QPushButton("Indenter JSON"); b_fmt.clicked.connect(self.prettify_body)
            brow.addWidget(self.body_mode); brow.addWidget(b_fmt); brow.addStretch(1)
            self.body_edit = QPlainTextEdit()
            CodeHighlighter(self.body_edit.document())
            bl.addLayout(brow); bl.addWidget(self.body_edit, 1)

            net_w = QWidget(); form = QFormLayout(net_w)
            self.ua = QComboBox(); self.ua.setEditable(True)
            for name, val in USER_AGENTS.items():
                self.ua.addItem(name if not val else val[:70], val)
            self.ua.currentIndexChanged.connect(
                lambda i: self.ua.setEditText(self.ua.itemData(i) or ""))
            self.referer = QLineEdit()
            self.proxy = QLineEdit()
            self.proxy.setPlaceholderText("http://127.0.0.1:8080")
            self.timeout = QDoubleSpinBox()
            self.timeout.setRange(0.1, 600); self.timeout.setValue(30)
            self.timeout.setSuffix(" s")
            self.verify = QCheckBox("Vérifier TLS")
            self.follow = QCheckBox("Suivre redirections"); self.follow.setChecked(True)
            self.http2 = QCheckBox("Forcer HTTP/2")
            form.addRow("User-Agent", self.ua)
            form.addRow("Referer", self.referer)
            form.addRow("Proxy", self.proxy)
            form.addRow("Timeout", self.timeout)
            form.addRow("", self.verify); form.addRow("", self.follow)
            form.addRow("", self.http2)

            ws_w = QWidget(); wl = QVBoxLayout(ws_w)
            ws_form = QFormLayout()
            self.ws_url = QLineEdit()
            self.ws_url.setPlaceholderText("ws://localhost:8080/ws")
            self.ws_origin = QLineEdit()
            self.ws_origin.setPlaceholderText("https://evil.example.com (test CSWSH)")
            self.ws_subproto = QLineEdit()
            self.ws_subproto.setPlaceholderText("json, graphql-ws")
            ws_form.addRow("URL WebSocket", self.ws_url)
            ws_form.addRow("Origin (CSWSH)", self.ws_origin)
            ws_form.addRow("Subprotocols", self.ws_subproto)
            wl.addLayout(ws_form)
            wl.addWidget(QLabel("Messages (un par ligne, JSON) :"))
            self.ws_messages = QPlainTextEdit()
            self.ws_messages.setPlaceholderText('{"action":"ping","id":1}\n{"action":"echo"}')
            wl.addWidget(self.ws_messages, 1)
            b_ws = QPushButton("Envoyer via WebSocket")
            b_ws.setProperty("class", "primary")
            b_ws.clicked.connect(self.send_websocket_manual)
            wl.addWidget(b_ws)

            for wdg, n in ((self.params, "Paramètres"), (self.hdrs, "En-têtes"),
                           (self.cooks, "Cookies"), (body_w, "Corps"),
                           (net_w, "Réseau"), (ws_w, "WebSocket")):
                self.tabs.addTab(wdg, n)
            lay.addWidget(self.tabs, 1)
            return w

        def _build_result_panel(self):
            self.rtabs = QTabWidget()
            self.view = ResponseView()
            rep = QWidget(); rl = QVBoxLayout(rep)
            row = QHBoxLayout()
            self.summary = QLabel("Aucun résultat")
            b_junit = QPushButton("JUnit")
            b_junit.clicked.connect(lambda: self._export("junit"))
            b_html = QPushButton("HTML")
            b_html.clicked.connect(lambda: self._export("html"))
            b_json = QPushButton("JSON")
            b_json.clicked.connect(lambda: self._export("json"))
            b_clear = QPushButton("Vider")
            b_clear.clicked.connect(self.clear_results)
            row.addWidget(self.summary, 1)
            for b in (b_junit, b_html, b_json, b_clear):
                row.addWidget(b)
            rl.addLayout(row)
            self.report = make_table(
                ["Verdict", "Sév.", "Type", "Test", "HTTP", "Temps", "Détail"],
                [80, 80, 70, 320, 70, 80])
            self.report.itemSelectionChanged.connect(self._report_selected)
            rl.addWidget(self.report, 1)
            self.rtabs.addTab(self.view, "Réponse")
            self.rtabs.addTab(rep, "Rapport")
            return self.rtabs

        # ── Templates ────────────────────────────────────────────────
        def choose_dir(self):
            start = self.template_dir if self.template_dir else Path.home()
            d = QFileDialog.getExistingDirectory(self, "Dossier YAML", str(start))
            if d:
                self.load_templates(Path(d))

        def load_templates(self, folder):
            if not folder or not Path(folder).is_dir():
                self.statusBar().showMessage("Dossier invalide", 4000)
                return
            folder = Path(folder)
            self.template_dir = folder
            self.dir_lbl.setText(folder.name)
            self.dir_lbl.setToolTip(str(folder))
            self.suites.clear(); self.tree.clear(); self.item_map.clear()
            for path in sorted([*folder.glob("*.yaml"), *folder.glob("*.yml")]):
                try:
                    suite = load_suite(path)
                except Exception as e:
                    it = QTreeWidgetItem([f"⚠ {path.name}"])
                    it.setForeground(0, QColor(C["err"]))
                    it.setToolTip(0, str(e))
                    self.tree.addTopLevelItem(it)
                    continue
                base_vars = resolve_env_files(suite)
                suite["variables"] = base_vars
                si = len(self.suites)
                self.suites.append({"path": path, "data": suite})
                top = QTreeWidgetItem(
                    [f"📋 {suite.get('name', path.stem)}  ({len(suite['tests'])})"])
                top.setData(0, Qt.ItemDataRole.UserRole, ("suite", si))
                top.setForeground(0, QColor(C["accent2"]))
                self.tree.addTopLevelItem(top)
                for ti, t in enumerate(suite["tests"]):
                    sev = str(t.get("severity", "info")).lower()
                    child = QTreeWidgetItem(
                        [f"•  {t.get('name', t.get('id', f'test {ti+1}'))}"])
                    child.setData(0, Qt.ItemDataRole.UserRole, ("test", si, ti))
                    child.setForeground(0, QColor(SEV_COLOR.get(sev, C["text"])))
                    child.setToolTip(0, f"[{sev}] {t.get('description', '')}".strip())
                    top.addChild(child)
                    self.item_map[(si, ti)] = child
                top.setExpanded(True)
            self.statusBar().showMessage(f"{len(self.suites)} suite(s) chargée(s)")

        def _filter_tree(self, text):
            text = text.lower().strip()

            def visit(item):
                match = not text or text in item.text(0).lower()
                child_match = any(visit(item.child(i))
                                  for i in range(item.childCount()))
                item.setHidden(not (match or child_match))
                return match or child_match
            for i in range(self.tree.topLevelItemCount()):
                visit(self.tree.topLevelItem(i))

        def _suite_vars(self, si):
            v = dict(self.suites[si]["data"].get("variables") or {})
            if self.base_url.text().strip():
                v["base_url"] = self.base_url.text().strip()
            return v

        def _make_job(self, si, ti):
            s = self.suites[si]["data"]; t = s["tests"][ti]
            kind = "websocket" if t.get("type") == "websocket" else \
                   "attack" if t.get("mode") == "attack" else "http"
            return Job(name=str(t.get("name", t.get("id", f"test {ti+1}"))),
                       suite=str(s.get("name", "")), key=(si, ti),
                       severity=str(t.get("severity", "info")).lower(), test=t,
                       defaults=s.get("defaults") or {}, vars=self._suite_vars(si),
                       asserts=t.get("assert") or [], capture=t.get("capture") or {},
                       skip_if=str(t.get("skip_if", "")), tid=str(t.get("id", "")),
                       retries=int(t.get("retries", 0)), kind=kind,
                       verdict_semantics=str(t.get("verdict_semantics",
                                                   "hardening")).lower())

        def _selected_jobs(self):
            items = self.tree.selectedItems() or \
                    [self.tree.topLevelItem(i)
                     for i in range(self.tree.topLevelItemCount())]
            keys = []
            for it in items:
                d = it.data(0, Qt.ItemDataRole.UserRole)
                if not d:
                    continue
                if d[0] == "suite":
                    keys += [(d[1], i)
                             for i in range(len(self.suites[d[1]]["data"]["tests"]))]
                else:
                    keys.append((d[1], d[2]))
            seen, jobs = set(), []
            for k in sorted(set(keys)):
                if k not in seen:
                    seen.add(k); jobs.append(self._make_job(*k))
            return jobs

        def load_test_into_editor(self, item):
            d = item.data(0, Qt.ItemDataRole.UserRole)
            if not d or d[0] != "test":
                return
            job = self._make_job(d[1], d[2])
            if job.kind == "websocket":
                self._populate_ws_editor(job)
            else:
                spec = build_spec(job.test, job.defaults, job.vars)
                self.populate_editor(spec)
            self.current_asserts = job.asserts
            self.current_sev = job.severity
            self.current_capture = job.capture
            self.tpl_lbl.setText(f"Template : {job.name} — {len(job.asserts)} assertion(s)")

        def _populate_ws_editor(self, job):
            wscfg = job.test.get("websocket", {}) or {}
            self.tabs.setCurrentIndex(5)
            self.ws_url.setText(wscfg.get("url", ""))
            self.ws_origin.setText(wscfg.get("origin", ""))
            self.ws_subproto.setText(", ".join(wscfg.get("subprotocols") or []))
            msgs = []
            for step in wscfg.get("messages", []) or []:
                if "send_json" in step:
                    msgs.append(json.dumps(step["send_json"], ensure_ascii=False))
                elif "send_text" in step:
                    msgs.append(str(step["send_text"]))
            self.ws_messages.setPlainText("\n".join(msgs))

        def populate_editor(self, s):
            self.method.setCurrentText(s.method)
            self.url.setText(s.url)
            self.params.set_dict(s.params)
            self.hdrs.set_dict(s.headers)
            self.cooks.set_dict(s.cookies)
            self.body_mode.setCurrentText(s.body_mode)
            self.body_edit.setPlainText(s.body.decode("utf-8", "replace"))
            self.proxy.setText(s.proxy)
            self.timeout.setValue(s.timeout[1])
            self.verify.setChecked(bool(s.verify))
            self.follow.setChecked(s.follow_redirects)
            self.http2.setChecked(s.http2)
            self.ua.setCurrentIndex(0); self.ua.setEditText(""); self.referer.clear()

        def prettify_body(self):
            try:
                self.body_edit.setPlainText(
                    json.dumps(json.loads(self.body_edit.toPlainText()),
                               indent=2, ensure_ascii=False))
            except ValueError as e:
                self.statusBar().showMessage(f"JSON invalide : {e}", 5000)

        def collect_spec(self):
            headers = self.hdrs.to_dict()
            ua = self.ua.currentText().strip()
            if ua and ua != list(USER_AGENTS)[0]:
                set_header(headers, "User-Agent", ua)
            if self.referer.text().strip():
                set_header(headers, "Referer", self.referer.text().strip())
            mode = self.body_mode.currentText()
            body = self.body_edit.toPlainText() if mode != "Aucun" else ""
            if body and mode == "JSON" and not has_header(headers, "Content-Type"):
                headers["Content-Type"] = "application/json"
            url = self.url.text().strip()
            if url and "://" not in url:
                url = "http://" + url
            return RequestSpec(
                method=self.method.currentText().strip().upper() or "GET", url=url,
                headers=headers, params=self.params.to_dict(),
                cookies=self.cooks.to_dict(), body=body.encode(),
                body_mode=mode, proxy=self.proxy.text().strip(),
                timeout=(10, self.timeout.value()), verify=self.verify.isChecked(),
                follow_redirects=self.follow.isChecked(), http2=self.http2.isChecked())

        def import_curl_clipboard(self):
            txt = QApplication.clipboard().text().strip()
            if not txt.startswith("curl"):
                self.statusBar().showMessage(
                    "Le presse-papiers ne contient pas une commande curl", 4000)
                return
            try:
                toks = shlex.split(txt)
            except ValueError:
                toks = txt.split()
            method, url, headers, data = "GET", "", {}, ""
            i = 1
            while i < len(toks):
                t = toks[i]
                if t in ("-X", "--request") and i + 1 < len(toks):
                    method = toks[i + 1].upper(); i += 2
                elif t in ("-H", "--header") and i + 1 < len(toks):
                    k, _, v = toks[i + 1].partition(":")
                    headers[k.strip()] = v.strip(); i += 2
                elif t in ("-d", "--data", "--data-raw", "--data-binary") \
                        and i + 1 < len(toks):
                    data = toks[i + 1]; i += 2
                elif t in ("-b", "--cookie") and i + 1 < len(toks):
                    headers["Cookie"] = toks[i + 1]; i += 2
                elif t.startswith("-"):
                    i += 1
                else:
                    url = t; i += 1
            self.method.setCurrentText(method)
            self.url.setText(url)
            self.hdrs.set_dict(headers)
            if data:
                try:
                    self.body_edit.setPlainText(
                        json.dumps(json.loads(data), indent=2, ensure_ascii=False))
                    self.body_mode.setCurrentText("JSON")
                except ValueError:
                    self.body_edit.setPlainText(data)
                    self.body_mode.setCurrentText("Brut")
            self.statusBar().showMessage("cURL importé")

        def send_manual(self):
            if self.runner and self.runner.isRunning():
                return
            spec = self.collect_spec()
            if not spec.url:
                self.statusBar().showMessage("Saisissez une URL", 4000); return
            job = Job(name=f"{spec.method} {spec.url}", spec=spec,
                      asserts=self.current_asserts,
                      severity=self.current_sev, capture=self.current_capture,
                      kind="http")
            self.rtabs.setCurrentIndex(0)
            self._start([job], clear=False)

        def send_websocket_manual(self):
            if self.runner and self.runner.isRunning():
                return
            ws_url = self.ws_url.text().strip() or self.url.text().strip()
            if not ws_url:
                self.statusBar().showMessage("Saisissez une URL WebSocket", 4000)
                return
            messages = []
            for line in self.ws_messages.toPlainText().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    messages.append({"send_json": json.loads(line)})
                except ValueError:
                    messages.append({"send_text": line})
            wscfg = {"url": ws_url,
                     "origin": self.ws_origin.text().strip() or None,
                     "subprotocols": [x.strip() for x in
                                      self.ws_subproto.text().split(",") if x.strip()] or None,
                     "connect_timeout": 5,
                     "messages": messages}
            test = {"type": "websocket", "websocket": wscfg}
            job = Job(name=f"WS {ws_url}", test=test, kind="websocket",
                      severity="info")
            self.rtabs.setCurrentIndex(0)
            self._start([job], clear=False)

        def run_selection(self):
            if self.runner and self.runner.isRunning():
                return
            jobs = self._selected_jobs()
            if not jobs:
                self.statusBar().showMessage("Aucun test", 4000); return
            target = self.base_url.text().strip() or "(base_url)"
            if len(jobs) > 1 and QMessageBox.question(
                    self, "Confirmer",
                    f"Exécuter {len(jobs)} test(s) contre\n{target} ?\n\n"
                    "N'utilisez cette fonction que sur des serveurs "
                    "dont vous êtes responsable."
            ) != QMessageBox.StandardButton.Yes:
                return
            if not self._confirm_attack(jobs):
                return
            self._start(jobs, clear=True)

        def _confirm_attack(self, jobs):
            attack_jobs = [j for j in jobs if j.kind == "attack"]
            if not attack_jobs:
                return True
            scope_ok = all(
                (j.test.get("scope", {}) or {}).get("active_testing") is True or
                (j.key and (self.suites[j.key[0]]["data"].get("scope", {}) or {})
                 .get("active_testing") is True)
                for j in attack_jobs)
            if not scope_ok:
                QMessageBox.warning(
                    self, "Mode attaque bloqué",
                    "Le template doit déclarer `scope.active_testing: true` "
                    "au niveau de la suite ou du test.")
                return False
            target = self.base_url.text().strip() or "(base_url)"
            cats = sorted({j.test.get("attack", {}).get("category", "?")
                           for j in attack_jobs})
            reply = QMessageBox.question(
                self, "Confirmer le mode attaque",
                f"⚠ MODE ATTAQUE — {len(attack_jobs)} test(s)\n\n"
                f"Cible : {target}\n"
                f"Catégories : {', '.join(cats)}\n\n"
                f"Payloads NON DESTRUCTIFS (canary, time-based, error-based).",
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
            if reply != QMessageBox.StandardButton.Ok:
                return False
            host = urllib.parse.urlparse(target).hostname or ""
            typed, ok = QInputDialog.getText(
                self, "Double confirmation",
                f"Tapez « {host} » pour lancer :")
            if not ok or typed.strip() != host:
                self.statusBar().showMessage("Confirmation incorrecte — annulé", 4000)
                return False
            return True

        def _start(self, jobs, clear):
            if clear:
                self.clear_results()
            engine = Engine(base_url=self.base_url.text().strip() or "",
                            delay_ms=self.delay.value())
            self.progress.setMaximum(len(jobs)); self.progress.setValue(0)
            self.btn_send.setEnabled(False)
            self.btn_run.setEnabled(False)
            self.btn_stop.setEnabled(True)
            self.runner = Runner(engine, jobs, self.conc.value())
            self.runner.result.connect(self._on_result)
            self.runner.progress.connect(lambda i, n: self.progress.setValue(i))
            self.runner.done.connect(self._on_done)
            self.runner.start()

        def _on_done(self):
            self.btn_send.setEnabled(True)
            self.btn_run.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.statusBar().showMessage("Terminé", 4000)

        def _on_result(self, res):
            self.results.append(res)
            verdict, col = res.verdict()
            row = self.report.rowCount(); self.report.insertRow(row)
            r = res.resp
            detail = r.error or next(
                (f"{c.label} — {c.detail}" for c in res.checks if not c.ok), "")
            self.report.setItem(row, 0, cell(verdict, col, True))
            self.report.setItem(row, 1, cell(res.job.severity,
                                 SEV_COLOR.get(res.job.severity, C["muted"])))
            self.report.setItem(row, 2, cell(res.job.kind, C["cyan"]))
            self.report.setItem(row, 3, cell(res.job.name))
            self.report.setItem(row, 4, cell(str(r.status) if r.status else "—",
                                 status_color(r.status), True))
            self.report.setItem(row, 5, cell(f"{r.elapsed*1000:.0f} ms", C["muted"]))
            self.report.setItem(row, 6, cell(detail, C["muted"]))
            if res.job.key in self.item_map:
                it = self.item_map[res.job.key]
                mark = "✔ " if verdict in ("PASS", "INFO") else "✘ "
                it.setText(0, mark + it.text(0)[2:])
                it.setForeground(0, QColor(C["ok"] if verdict in ("PASS", "INFO") else col))
            self.view.show_result(r, res.checks, res.ws_result)
            v = [x.verdict()[0] for x in self.results]
            np_, nf, ne = v.count("PASS"), v.count("FAIL"), v.count("ERREUR")
            self.summary.setText(
                f'<b>{len(v)}</b> — '
                f'<span style="color:{C["ok"]}">✔ {np_}</span> '
                f'<span style="color:{C["err"]}">✘ {nf}</span> '
                f'<span style="color:{C["warn"]}">⚠ {ne}</span>')
            self.rtabs.setTabText(1, f"Rapport ({nf + ne})" if nf + ne else "Rapport")

        def _report_selected(self):
            rows = {i.row() for i in self.report.selectedItems()}
            if rows:
                res = self.results[min(rows)]
                self.view.show_result(res.resp, res.checks, res.ws_result)

        def clear_results(self):
            self.results.clear(); self.report.setRowCount(0)
            self.summary.setText("Aucun résultat"); self.rtabs.setTabText(1, "Rapport")

        def _export(self, kind):
            if not self.results:
                return
            ext = {"junit": "xml", "html": "html", "json": "json"}[kind]
            path, _ = QFileDialog.getSaveFileName(
                self, "Exporter", f"rapport.{ext}", f"*.{ext}")
            if not path:
                return
            fn = {"junit": results_to_junit, "html": results_to_html,
                  "json": results_to_json}[kind]
            Path(path).write_text(fn(self.results), encoding="utf-8")
            self.statusBar().showMessage(f"Exporté : {path}", 5000)

        def copy_curl(self):
            QApplication.clipboard().setText(to_curl(self.collect_spec()))
            self.statusBar().showMessage("curl copié", 4000)

        def save_yaml(self):
            spec = self.collect_spec()
            path, _ = QFileDialog.getSaveFileName(
                self, "Enregistrer",
                str((getattr(self, "template_dir", None) or Path.home()) /
                    "nouveau_test.yaml"), "YAML (*.yaml *.yml)")
            if not path:
                return
            u = urllib.parse.urlparse(spec.url)
            req = {"method": spec.method,
                   "path": (u.path or "/") + (f"?{u.query}" if u.query else "")}
            if spec.headers: req["headers"] = spec.headers
            if spec.params: req["params"] = spec.params
            if spec.cookies: req["cookies"] = spec.cookies
            if spec.body:
                if spec.body_mode == "JSON":
                    try:
                        req["json"] = json.loads(spec.body)
                    except ValueError:
                        req["body"] = spec.body.decode()
                else:
                    req["body"] = spec.body.decode()
            last = self.results[-1].resp if self.results else None
            asserts = self.current_asserts or \
                      ([{"status": last.status}] if last and last.status else [])
            doc = {"name": "Test enregistré",
                   "variables": {"base_url": f"{u.scheme}://{u.netloc}"},
                   "defaults": {"read_timeout": spec.timeout[1],
                                "verify": spec.verify},
                   "tests": [{"id": "saved-001",
                              "name": f"{spec.method} {req['path']}",
                              "severity": "info", "request": req,
                              "assert": asserts}]}
            Path(path).write_text(
                yaml.safe_dump(doc, sort_keys=False, allow_unicode=True),
                encoding="utf-8")
            self.statusBar().showMessage(f"Enregistré : {path}", 5000)

        def closeEvent(self, e):
            if self.runner and self.runner.isRunning():
                self.runner.stop(); self.runner.wait(3000)
            super().closeEvent(e)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
    win = MainWindow(template_dir)
    win.show()
    return app.exec()


# ════════════════════════════════════════════════════════════════════════════
#  Entrée principale
# ════════════════════════════════════════════════════════════════════════════
def main() -> int:
    ap = argparse.ArgumentParser(
        description="HTTP Debugger v3c — GUI + CLI (HTTP/WebSocket/attaque)")
    ap.add_argument("templates", nargs="?",
                    help="Dossier de templates YAML (GUI)")
    ap.add_argument("--cli", help="Mode CLI : dossier de templates")
    ap.add_argument("--base-url", default="", help="Surcharge {{base_url}}")
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--delay", type=int, default=0,
                    help="Délai entre tests (ms)")
    ap.add_argument("--block-private", action="store_true",
                    help="Bloquer les CIDR privés")
    ap.add_argument("--fail-on", choices=["never", "any", "high"], default="high")
    ap.add_argument("--junit"); ap.add_argument("--json"); ap.add_argument("--html")
    args = ap.parse_args()
    if args.cli:
        return cli_main(args)
    return gui_main(Path(args.templates) if args.templates else None)


if __name__ == "__main__":
    sys.exit(main() or 0)
