#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP Debugger — client HTTP graphique (PySide6) piloté par des templates YAML.

Usage prévu : tests de développement / conformité / durcissement de VOS propres
serveurs (Nginx, PHP, Node.js, API, serveurs MCP...). N'exécutez des suites
que contre des machines dont vous êtes responsable.

Dépendances :  pip install PySide6 requests pyyaml
Lancement   :  python http_debugger.py [dossier_de_templates]
"""
from __future__ import annotations

import html
import json
import re
import shlex
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import requests
import urllib3
import yaml
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import (QColor, QFont, QKeySequence, QShortcut,
                           QSyntaxHighlighter, QTextCharFormat)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox,
                               QComboBox, QDoubleSpinBox, QFileDialog,
                               QFormLayout, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMainWindow, QMessageBox,
                               QPlainTextEdit, QProgressBar, QPushButton,
                               QSpinBox, QSplitter, QTableWidget,
                               QTableWidgetItem, QTabWidget, QTextEdit,
                               QTreeWidget, QTreeWidgetItem, QVBoxLayout,
                               QWidget)

# ════════════════════════════════════════════════════════════════════════════
#  Palette & feuille de style
# ════════════════════════════════════════════════════════════════════════════
C = dict(bg="#171926", panel="#1f2233", panel2="#292d44", border="#363b5a",
         text="#e6e8f2", muted="#8a90ad", accent="#8b7cf6", accent2="#a99bff",
         ok="#4ade80", warn="#fbbf24", err="#f87171", info="#60a5fa",
         cyan="#22d3ee", pink="#f472b6", orange="#fb923c")

SEV_COLOR = {"critical": C["err"], "high": C["err"], "medium": C["orange"],
             "low": C["warn"], "info": C["info"]}

QSS = """
* { font-family: 'Inter','Segoe UI','Ubuntu','Noto Sans',sans-serif; font-size: 13px; }
QMainWindow, QWidget { background: %(bg)s; color: %(text)s; }
QSplitter::handle { background: %(border)s; }
QSplitter::handle:horizontal { width: 2px; }
QSplitter::handle:vertical { height: 2px; }
QLabel[class="h"] { color: %(accent2)s; font-weight: 700; font-size: 14px; letter-spacing: 1px; }
QLabel[class="muted"] { color: %(muted)s; }
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {
    background: %(panel)s; border: 1px solid %(border)s; border-radius: 6px;
    padding: 5px 8px; selection-background-color: %(accent)s; color: %(text)s; }
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QSpinBox:focus { border: 1px solid %(accent)s; }
QComboBox QAbstractItemView { background: %(panel)s; selection-background-color: %(accent)s; border: 1px solid %(border)s; }
QPlainTextEdit, QTextEdit { font-family: 'JetBrains Mono','Fira Code','Consolas','DejaVu Sans Mono',monospace; font-size: 12px; }
QPushButton { background: %(panel2)s; border: 1px solid %(border)s; border-radius: 6px; padding: 6px 14px; }
QPushButton:hover { border-color: %(accent)s; background: #32375a; }
QPushButton:disabled { color: %(muted)s; background: %(panel)s; }
QPushButton[class="primary"] { background: %(accent)s; color: #12131f; font-weight: 700; border: none; }
QPushButton[class="primary"]:hover { background: %(accent2)s; }
QPushButton[class="danger"] { background: transparent; border: 1px solid %(err)s; color: %(err)s; }
QTabWidget::pane { border: 1px solid %(border)s; border-radius: 6px; top: -1px; }
QTabBar::tab { background: %(panel)s; padding: 7px 14px; border: 1px solid %(border)s;
    border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 2px; color: %(muted)s; }
QTabBar::tab:selected { background: %(panel2)s; color: %(text)s; border-bottom: 2px solid %(accent)s; }
QTableWidget, QTreeWidget { background: %(panel)s; alternate-background-color: #232640;
    border: 1px solid %(border)s; border-radius: 6px; gridline-color: %(border)s; }
QTableWidget::item:selected, QTreeWidget::item:selected { background: #3b3f6b; color: %(text)s; }
QHeaderView::section { background: %(panel2)s; color: %(muted)s; border: none;
    border-right: 1px solid %(border)s; padding: 5px 8px; font-weight: 600; }
QProgressBar { background: %(panel)s; border: 1px solid %(border)s; border-radius: 6px; text-align: center; height: 14px; }
QProgressBar::chunk { background: %(accent)s; border-radius: 5px; }
QScrollBar:vertical { background: %(bg)s; width: 10px; }
QScrollBar::handle:vertical { background: %(border)s; border-radius: 5px; min-height: 24px; }
QScrollBar:horizontal { background: %(bg)s; height: 10px; }
QScrollBar::handle:horizontal { background: %(border)s; border-radius: 5px; min-width: 24px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QStatusBar { background: %(panel)s; color: %(muted)s; }
QCheckBox::indicator { width: 15px; height: 15px; border-radius: 4px; border: 1px solid %(border)s; background: %(panel)s; }
QCheckBox::indicator:checked { background: %(accent)s; border-color: %(accent)s; }
QToolTip { background: %(panel2)s; color: %(text)s; border: 1px solid %(accent)s; }
""" % C

USER_AGENTS = {
    "(par défaut : vide)": "",
    "Chrome / Windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Firefox / Linux": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Safari / iPhone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "curl": "curl/8.5.0",
    "Googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "python-requests": "python-requests/2.31.0",
}

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
           "PROPFIND", "PURGE"]

SECURITY_HEADERS = {"strict-transport-security", "content-security-policy",
                    "x-content-type-options", "x-frame-options", "referrer-policy",
                    "permissions-policy", "cross-origin-opener-policy",
                    "cross-origin-resource-policy", "cross-origin-embedder-policy"}
LEAK_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-generator", "x-runtime"}


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
    body: str = ""
    body_mode: str = "Brut"          # informatif (GUI)
    proxy: str = ""
    timeout: float = 15.0
    verify: bool = True
    follow_redirects: bool = True
    max_redirects: int = 10


@dataclass
class ResponseData:
    error: str = ""
    status: int = 0
    reason: str = ""
    version: str = "1.1"
    url: str = ""
    headers: list = field(default_factory=list)       # [(nom, valeur)]
    set_cookies: list = field(default_factory=list)   # [chaîne Set-Cookie brute]
    body: bytes = b""
    elapsed: float = 0.0
    history: list = field(default_factory=list)       # [(status, url, location)]
    raw_request: str = ""
    encoding: str = "utf-8"

    @property
    def text(self) -> str:
        return self.body.decode(self.encoding or "utf-8", errors="replace")


@dataclass
class Check:
    ok: bool
    label: str
    detail: str = ""


@dataclass
class Job:
    name: str
    suite: str = ""
    key: tuple | None = None
    severity: str = "info"
    test: dict | None = None
    defaults: dict = field(default_factory=dict)
    vars: dict = field(default_factory=dict)
    spec: RequestSpec | None = None
    asserts: list = field(default_factory=list)
    capture: dict = field(default_factory=dict)
    tid: str = ""


@dataclass
class TestResult:
    job: Job
    resp: ResponseData
    checks: list

    def verdict(self) -> tuple[str, str]:
        if self.resp.error:
            return "ERREUR", C["err"]
        if not self.checks:
            return "INFO", C["info"]
        if all(c.ok for c in self.checks):
            return "PASS", C["ok"]
        return "FAIL", SEV_COLOR.get(self.job.severity, C["err"])


# ════════════════════════════════════════════════════════════════════════════
#  Moteur : variables, requêtes, assertions
# ════════════════════════════════════════════════════════════════════════════
_VAR = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


def subst(obj, vars_: dict):
    """Remplace {{var}} et {{repeat:X:N}} récursivement."""
    if isinstance(obj, str):
        def rep(m):
            expr = m.group(1)
            if expr.startswith("repeat:"):
                _, ch, n = expr.split(":", 2)
                return ch * int(n)
            return str(vars_.get(expr, m.group(0)))
        return _VAR.sub(rep, obj)
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


def build_spec(test: dict, defaults: dict, vars_: dict) -> RequestSpec:
    d = subst(defaults or {}, vars_)
    t = subst(test.get("request", {}) or {}, vars_)
    headers = {**(d.get("headers") or {}), **(t.get("headers") or {})}
    headers = {k: str(v) for k, v in headers.items() if v is not None}
    base = str(vars_.get("base_url", "")).rstrip("/")
    url = t.get("url") or (base + "/" + str(t.get("path", "")).lstrip("/"))
    body, mode = "", "Aucun"
    if "json" in t:
        body, mode = json.dumps(t["json"], indent=2, ensure_ascii=False), "JSON"
        if not has_header(headers, "Content-Type"):
            headers["Content-Type"] = "application/json"
    elif "form" in t:
        body, mode = urllib.parse.urlencode(t["form"]), "Formulaire"
        if not has_header(headers, "Content-Type"):
            headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif "body" in t:
        body, mode = str(t["body"]), "Brut"

    def pick(key, default):
        return t.get(key, d.get(key, default))

    return RequestSpec(
        method=str(t.get("method", "GET")).upper(), url=url, headers=headers,
        params={**(d.get("params") or {}), **(t.get("params") or {})},
        cookies={**(d.get("cookies") or {}), **(t.get("cookies") or {})},
        body=body, body_mode=mode, proxy=str(pick("proxy", "") or ""),
        timeout=float(pick("timeout", 15)), verify=bool(pick("verify", True)),
        follow_redirects=bool(pick("follow_redirects", True)),
        max_redirects=int(pick("max_redirects", 10)))


def build_raw_request(prep: requests.PreparedRequest) -> str:
    lines = [f"{prep.method} {prep.path_url} HTTP/1.1"]
    host = urllib.parse.urlparse(prep.url).netloc
    if not any(k.lower() == "host" for k in prep.headers):
        lines.append(f"Host: {host}")
    lines += [f"{k}: {v}" for k, v in prep.headers.items()]
    out = "\n".join(lines) + "\n\n"
    if prep.body:
        b = prep.body if isinstance(prep.body, str) else prep.body.decode("utf-8", "replace")
        out += b[:20000]
    return out


def send_request(spec: RequestSpec) -> ResponseData:
    r = ResponseData()
    t0 = time.perf_counter()
    try:
        s = requests.Session()
        s.trust_env = False            # pas de proxy implicite via l'environnement
        s.headers.clear()              # contrôle total : rien n'est ajouté en douce
        s.max_redirects = spec.max_redirects
        headers = dict(spec.headers)
        if spec.cookies:
            ck = "; ".join(f"{k}={v}" for k, v in spec.cookies.items())
            old = next((v for k, v in headers.items() if k.lower() == "cookie"), None)
            set_header(headers, "Cookie", f"{old}; {ck}" if old else ck)
        data = spec.body.encode("utf-8") if spec.body else None
        req = requests.Request(spec.method, spec.url, headers=headers,
                               params=spec.params or None, data=data)
        prep = s.prepare_request(req)
        r.raw_request = build_raw_request(prep)
        proxies = {"http": spec.proxy, "https": spec.proxy} if spec.proxy else {}
        if not spec.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        resp = s.send(prep, proxies=proxies, timeout=spec.timeout, verify=spec.verify,
                      allow_redirects=spec.follow_redirects)
        r.elapsed = time.perf_counter() - t0
        r.status, r.reason, r.url = resp.status_code, resp.reason or "", resp.url
        r.version = {10: "1.0", 11: "1.1", 20: "2"}.get(getattr(resp.raw, "version", 11), "1.1")
        try:
            r.headers = [(k, v) for k, v in resp.raw.headers.items()]
            r.set_cookies = list(resp.raw.headers.getlist("Set-Cookie"))
        except Exception:
            r.headers = list(resp.headers.items())
        r.body = resp.content
        m = re.search(r"charset=([\w-]+)", resp.headers.get("Content-Type", ""), re.I)
        r.encoding = m.group(1) if m else "utf-8"
        r.history = [(h.status_code, h.url, h.headers.get("Location", "")) for h in resp.history]
    except Exception as e:  # noqa: BLE001 — on veut afficher n'importe quelle erreur réseau
        r.elapsed = time.perf_counter() - t0
        r.error = f"{type(e).__name__}: {e}"
    return r


# ── Assertions ──────────────────────────────────────────────────────────────
def status_match(code: int, exp) -> bool:
    for e in (exp if isinstance(exp, list) else [exp]):
        if isinstance(e, int) and code == e:
            return True
        if isinstance(e, str):
            if re.fullmatch(r"\dxx", e) and str(code)[0] == e[0]:
                return True
            if e.isdigit() and code == int(e):
                return True
    return False


def jpath(obj, path: str):
    for tok in re.findall(r"[^.\[\]]+", path):
        obj = obj[int(tok)] if isinstance(obj, list) else obj[tok]
    return obj


def parse_set_cookie(raw: str):
    parts = [p.strip() for p in raw.split(";")]
    name, _, _ = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name, attrs


def run_assert(k: str, v, r: ResponseData) -> Check:
    body = r.text
    if k == "status":
        return Check(status_match(r.status, v), f"status ∈ {v}", f"reçu {r.status}")
    if k == "status_not":
        return Check(not status_match(r.status, v), f"status ∉ {v}", f"reçu {r.status}")
    if k == "header_present":
        val = hget(r, v)
        return Check(val is not None, f"en-tête « {v} » présent", val or "absent")
    if k == "header_absent":
        val = hget(r, v)
        return Check(val is None, f"en-tête « {v} » absent", f"présent : {val}" if val else "")
    if k == "header_equals":
        val = hget(r, v["name"])
        ok = val is not None and val.strip().lower() == str(v["value"]).strip().lower()
        return Check(ok, f"{v['name']} == {v['value']}", f"reçu : {val}")
    if k == "header_matches":
        val = hget(r, v["name"])
        ok = val is not None and re.search(v["regex"], val, re.I) is not None
        return Check(ok, f"{v['name']} ~ /{v['regex']}/", f"reçu : {val}")
    if k == "header_not_matches":
        val = hget(r, v["name"])
        m = re.search(v["regex"], val, re.I) if val else None
        return Check(m is None, f"{v['name']} ≁ /{v['regex']}/", f"reçu : {val}" if m else "")
    if k == "body_contains":
        return Check(v in body, f"corps contient « {v} »")
    if k == "body_not_contains":
        return Check(v not in body, f"corps ne contient pas « {v} »")
    if k == "body_regex":
        return Check(re.search(v, body, re.S) is not None, f"corps ~ /{v}/")
    if k == "body_not_regex":
        m = re.search(v, body, re.S)
        return Check(m is None, f"corps ≁ /{v}/", f"trouvé : {m.group(0)[:80]!r}" if m else "")
    if k == "body_empty":
        return Check((len(r.body) == 0) == bool(v), "corps vide" if v else "corps non vide",
                     f"{len(r.body)} octets")
    if k == "time_lt":
        return Check(r.elapsed < float(v), f"temps < {v}s", f"{r.elapsed:.3f}s")
    if k == "json_path":
        try:
            val = jpath(json.loads(body), v["path"])
            found = True
        except (KeyError, IndexError, ValueError, TypeError):
            val, found = None, False
        if "equals" in v:
            return Check(found and val == v["equals"], f"{v['path']} == {v['equals']!r}", f"reçu : {val!r}")
        want = v.get("exists", True)
        return Check(found == bool(want), f"{v['path']} {'existe' if want else 'absent'}",
                     f"valeur : {val!r}" if found else "introuvable")
    if k == "cookie_flags":
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
    return Check(False, f"assertion inconnue « {k} »")


def evaluate(asserts: list, resp: ResponseData) -> list:
    if resp.error:
        return [Check(False, "Connexion / transport", resp.error)]
    out = []
    for a in asserts or []:
        if not isinstance(a, dict) or len(a) != 1:
            out.append(Check(False, "assertion invalide", str(a)))
            continue
        (k, v), = a.items()
        try:
            out.append(run_assert(k, v, resp))
        except Exception as e:  # noqa: BLE001
            out.append(Check(False, k, f"erreur d'évaluation : {e}"))
    return out


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
        except Exception:  # noqa: BLE001
            val = None
        if val is not None:
            vars_[name] = str(val)


def to_curl(spec: RequestSpec) -> str:
    try:
        url = requests.Request(spec.method, spec.url, params=spec.params or None).prepare().url
    except Exception:  # noqa: BLE001
        url = spec.url
    p = ["curl", "-i", "-X", spec.method]
    if not spec.verify:
        p.append("-k")
    if spec.follow_redirects:
        p.append("-L")
    if spec.proxy:
        p += ["-x", spec.proxy]
    p += ["--max-time", str(int(spec.timeout))]
    for k, v in spec.headers.items():
        p += ["-H", f"{k}: {v}"]
    if spec.cookies:
        p += ["-b", "; ".join(f"{k}={v}" for k, v in spec.cookies.items())]
    if spec.body:
        p += ["--data-raw", spec.body]
    p.append(url)
    return " ".join(shlex.quote(x) for x in p)


# ════════════════════════════════════════════════════════════════════════════
#  Thread d'exécution
# ════════════════════════════════════════════════════════════════════════════
class Runner(QThread):
    result = Signal(object)
    progress = Signal(int, int)
    done = Signal()

    def __init__(self, jobs: list, delay_ms: int = 0):
        super().__init__()
        self.jobs, self.delay_ms, self._stop = jobs, delay_ms, False
        self.runtime_vars: dict = {}

    def stop(self):
        self._stop = True

    def run(self):
        total = len(self.jobs)
        for i, job in enumerate(self.jobs, 1):
            if self._stop:
                break
            vars_ = {**job.vars, **self.runtime_vars}
            try:
                spec = job.spec or build_spec(job.test or {}, job.defaults, vars_)
                resp = send_request(spec)
            except Exception as e:  # noqa: BLE001
                resp = ResponseData(error=f"{type(e).__name__}: {e}")
            if not resp.error:
                do_capture(subst(job.capture, vars_), resp, self.runtime_vars)
            asserts = subst(job.asserts, {**vars_, **self.runtime_vars})
            self.result.emit(TestResult(job, resp, evaluate(asserts, resp)))
            self.progress.emit(i, total)
            if self.delay_ms and i < total:
                self.msleep(self.delay_ms)
        self.done.emit()


# ════════════════════════════════════════════════════════════════════════════
#  Widgets utilitaires
# ════════════════════════════════════════════════════════════════════════════
def fmt(color, bold=False):
    f = QTextCharFormat()
    f.setForeground(QColor(color))
    if bold:
        f.setFontWeight(QFont.Weight.Bold)
    return f


class CodeHighlighter(QSyntaxHighlighter):
    """Coloration légère JSON / HTML / XML."""

    def __init__(self, doc):
        super().__init__(doc)
        self.rules = [
            (re.compile(r"</?[\w:-]+|/?>"), fmt(C["cyan"])),
            (re.compile(r'"(?:\\.|[^"\\])*"'), fmt(C["ok"])),
            (re.compile(r'"(?:\\.|[^"\\])*"(?=\s*:)'), fmt(C["accent2"], True)),
            (re.compile(r"\b-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b"), fmt(C["orange"])),
            (re.compile(r"\b(?:true|false|null)\b"), fmt(C["pink"], True)),
        ]

    def highlightBlock(self, text: str):
        for rx, f in self.rules:
            for m in rx.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), f)


class KVTable(QTableWidget):
    """Tableau clé/valeur éditable avec case d'activation et ligne vide auto."""

    def __init__(self, k="Nom", v="Valeur"):
        super().__init__(0, 3)
        self.setHorizontalHeaderLabels(["", k, v])
        h = self.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
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
        chk = QTableWidgetItem()
        chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
        chk.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
        self.setItem(r, 0, chk)
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

    def to_dict(self) -> dict:
        out = {}
        for r in range(self.rowCount()):
            k = self.item(r, 1).text().strip()
            if k and self.item(r, 0).checkState() == Qt.CheckState.Checked:
                out[k] = self.item(r, 2).text()
        return out

    def set_dict(self, d: dict):
        self.blockSignals(True)
        self.setRowCount(0)
        self.blockSignals(False)
        for k, v in (d or {}).items():
            self._add_row(str(k), str(v))
        self._ensure_blank()


def make_table(headers: list, widths: list | None = None) -> QTableWidget:
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


def cell(text, color=None, bold=False, tip=None) -> QTableWidgetItem:
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


def status_color(code: int) -> str:
    if code == 0:
        return C["err"]
    if code < 200:
        return C["info"]
    if code < 300:
        return C["ok"]
    if code < 400:
        return C["info"]
    if code < 500:
        return C["warn"]
    return C["err"]


def human(n: int) -> str:
    for u in ("o", "Ko", "Mo", "Go"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "o" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} To"


def colorize_http(text: str, response: bool) -> str:
    out, in_body = [], False
    for i, line in enumerate(text.split("\n")):
        e = html.escape(line)
        if i == 0:
            if response:
                m = re.match(r"HTTP/\S+ (\d+)", line)
                col = status_color(int(m.group(1))) if m else C["text"]
            else:
                col = C["accent2"]
            out.append(f'<b style="color:{col}">{e}</b>')
        elif in_body:
            out.append(f'<span style="color:{C["text"]}">{e}</span>')
        elif line.strip() == "":
            in_body = True
            out.append("")
        else:
            name, sep, val = e.partition(":")
            nl = name.strip().lower()
            col = C["ok"] if nl in SECURITY_HEADERS else C["orange"] if nl in LEAK_HEADERS else C["cyan"]
            out.append(f'<span style="color:{col}">{name}</span>{sep}<span style="color:{C["text"]}">{val}</span>')
    return "<br>".join(out)


# ════════════════════════════════════════════════════════════════════════════
#  Visionneuse de réponse
# ════════════════════════════════════════════════════════════════════════════
class ResponseView(QWidget):
    def __init__(self):
        super().__init__()
        self.last: tuple | None = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)

        top = QHBoxLayout()
        self.badge = QLabel("—")
        self.badge.setStyleSheet(f"background:{C['panel2']};color:{C['muted']};border-radius:8px;"
                                 "padding:4px 14px;font-weight:700;font-size:14px;")
        self.time_lbl, self.size_lbl, self.url_lbl = QLabel(""), QLabel(""), QLabel("")
        for w in (self.time_lbl, self.size_lbl, self.url_lbl):
            w.setProperty("class", "muted")
        self.pretty = QCheckBox("Formater JSON")
        self.pretty.setChecked(True)
        self.pretty.toggled.connect(self._refresh_body)
        top.addWidget(self.badge)
        top.addWidget(self.time_lbl)
        top.addWidget(self.size_lbl)
        top.addWidget(self.url_lbl, 1)
        top.addWidget(self.pretty)
        lay.addLayout(top)

        self.tabs = QTabWidget()
        self.body = QPlainTextEdit(readOnly=True)
        CodeHighlighter(self.body.document())
        self.headers = make_table(["En-tête", "Valeur"], [260])
        self.cookies = make_table(["Cookie", "Valeur", "Secure", "HttpOnly", "SameSite", "Autres"],
                                  [160, 220, 70, 80, 90])
        self.raw = QTextEdit(readOnly=True)
        self.redirects = make_table(["Code", "URL", "→ Location"], [70, 380])
        self.checks = make_table(["", "Assertion", "Détail"], [34, 340])
        for w, name in ((self.body, "Corps"), (self.headers, "En-têtes"), (self.cookies, "Cookies"),
                        (self.raw, "Brut"), (self.redirects, "Redirections"),
                        (self.checks, "Assertions")):
            self.tabs.addTab(w, name)
        lay.addWidget(self.tabs, 1)

    def _body_text(self, r: ResponseData) -> str:
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
        return txt

    def _refresh_body(self):
        if self.last:
            self.body.setPlainText(self._body_text(self.last[0]))

    def show_result(self, r: ResponseData, checks: list):
        self.last = (r, checks)
        if r.error:
            txt, col = "ERREUR", C["err"]
        else:
            txt, col = f"{r.status} {r.reason}".strip(), status_color(r.status)
        self.badge.setText(txt)
        self.badge.setStyleSheet(f"background:{col};color:#12131f;border-radius:8px;"
                                 "padding:4px 14px;font-weight:700;font-size:14px;")
        self.time_lbl.setText(f"⏱ {r.elapsed * 1000:.0f} ms")
        self.size_lbl.setText(f"▣ {human(len(r.body))}")
        self.url_lbl.setText(r.url)
        self.body.setPlainText(self._body_text(r))

        # En-têtes
        self.headers.setRowCount(0)
        for k, v in r.headers:
            kl = k.lower()
            kc = C["ok"] if kl in SECURITY_HEADERS else C["orange"] if kl in LEAK_HEADERS else C["cyan"]
            vc = C["orange"] if kl in LEAK_HEADERS and re.search(r"\d", v) else C["text"]
            row = self.headers.rowCount()
            self.headers.insertRow(row)
            tip = ("En-tête de sécurité" if kl in SECURITY_HEADERS else
                   "Peut divulguer des informations sur la pile technique" if kl in LEAK_HEADERS else None)
            self.headers.setItem(row, 0, cell(k, kc, True, tip))
            self.headers.setItem(row, 1, cell(v, vc))

        # Cookies
        self.cookies.setRowCount(0)
        for raw in r.set_cookies:
            name, attrs = parse_set_cookie(raw)
            val = raw.split(";")[0].partition("=")[2]
            others = "; ".join(f"{k}={v}" if v else k for k, v in attrs.items()
                               if k not in ("secure", "httponly", "samesite"))
            row = self.cookies.rowCount()
            self.cookies.insertRow(row)
            self.cookies.setItem(row, 0, cell(name, C["accent2"], True))
            self.cookies.setItem(row, 1, cell(val))
            for col_i, flag in ((2, "secure"), (3, "httponly"), (4, "samesite")):
                present = flag in attrs
                label = ("✔ " + attrs[flag]).strip() if present and attrs[flag] else "✔" if present else "✘"
                self.cookies.setItem(row, col_i, cell(label, C["ok"] if present else C["err"], True))
            self.cookies.setItem(row, 5, cell(others, C["muted"]))

        # Brut
        raw_html = (f'<div style="color:{C["accent"]}"><b>━━━ REQUÊTE ━━━</b></div>'
                    f'{colorize_http(r.raw_request, False)}<br><br>')
        if not r.error:
            head = f"HTTP/{r.version} {r.status} {r.reason}\n" + "\n".join(f"{k}: {v}" for k, v in r.headers)
            raw_html += (f'<div style="color:{C["accent"]}"><b>━━━ RÉPONSE ━━━</b></div>'
                         f'{colorize_http(head + chr(10) * 2 + r.text[:20000], True)}')
        else:
            raw_html += f'<b style="color:{C["err"]}">{html.escape(r.error)}</b>'
        self.raw.setHtml(f'<div style="font-family:monospace;white-space:pre-wrap">{raw_html}</div>')

        # Redirections
        self.redirects.setRowCount(0)
        for code, url, loc in r.history:
            row = self.redirects.rowCount()
            self.redirects.insertRow(row)
            self.redirects.setItem(row, 0, cell(str(code), status_color(code), True))
            self.redirects.setItem(row, 1, cell(url))
            self.redirects.setItem(row, 2, cell(loc, C["cyan"]))
        self.tabs.setTabText(4, f"Redirections ({len(r.history)})" if r.history else "Redirections")

        # Assertions
        self.checks.setRowCount(0)
        for c in checks:
            row = self.checks.rowCount()
            self.checks.insertRow(row)
            self.checks.setItem(row, 0, cell("✔" if c.ok else "✘", C["ok"] if c.ok else C["err"], True))
            self.checks.setItem(row, 1, cell(c.label, C["text"] if c.ok else C["err"]))
            self.checks.setItem(row, 2, cell(c.detail, C["muted"]))
        okn = sum(c.ok for c in checks)
        self.tabs.setTabText(5, f"Assertions ({okn}/{len(checks)})" if checks else "Assertions")


# ════════════════════════════════════════════════════════════════════════════
#  Fenêtre principale
# ════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self, template_dir: Path | None = None):
        super().__init__()
        self.setWindowTitle("HTTP Debugger")
        self.resize(1500, 920)
        self.suites: list[dict] = []
        self.results: list[TestResult] = []
        self.item_map: dict = {}
        self.runner: Runner | None = None
        self.current_asserts: list = []
        self.current_sev = "info"
        self.current_capture: dict = {}
        self._build_ui()
        QShortcut(QKeySequence("Ctrl+Return"), self, activated=self.send_manual)
        QShortcut(QKeySequence("Ctrl+Enter"), self, activated=self.send_manual)
        d = template_dir or Path(__file__).resolve().parent / "templates"
        if d.is_dir():
            self.load_templates(d)

    # ── Construction de l'UI ────────────────────────────────────────────────
    def _build_ui(self):
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._build_left())
        right = QSplitter(Qt.Orientation.Vertical)
        right.addWidget(self._build_request_panel())
        right.addWidget(self._build_result_panel())
        right.setSizes([400, 520])
        split.addWidget(right)
        split.setSizes([330, 1170])
        self.setCentralWidget(split)
        self.statusBar().showMessage("Prêt — Ctrl+Entrée pour envoyer")

    def _build_left(self) -> QWidget:
        w = QWidget()
        w.setMinimumWidth(280)
        lay = QVBoxLayout(w)
        title = QLabel("TEMPLATES YAML")
        title.setProperty("class", "h")
        lay.addWidget(title)
        row = QHBoxLayout()
        self.dir_lbl = QLabel("aucun dossier")
        self.dir_lbl.setProperty("class", "muted")
        b_open = QPushButton("Ouvrir…")
        b_open.clicked.connect(self.choose_dir)
        b_reload = QPushButton("↻")
        b_reload.setToolTip("Recharger les templates")
        b_reload.setFixedWidth(36)
        b_reload.clicked.connect(lambda: self.template_dir and self.load_templates(self.template_dir))
        row.addWidget(self.dir_lbl, 1)
        row.addWidget(b_open)
        row.addWidget(b_reload)
        lay.addLayout(row)

        lay.addWidget(self._lbl("Cible (base_url)"))
        self.base_url = QLineEdit("http://localhost:8080")
        lay.addWidget(self.base_url)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.itemDoubleClicked.connect(self.load_test_into_editor)
        lay.addWidget(self.tree, 1)
        hint = QLabel("Double-clic : charger dans l'éditeur")
        hint.setProperty("class", "muted")
        lay.addWidget(hint)

        row = QHBoxLayout()
        row.addWidget(self._lbl("Délai entre tests (ms)"))
        self.delay = QSpinBox()
        self.delay.setRange(0, 60000)
        self.delay.setSingleStep(100)
        row.addWidget(self.delay)
        lay.addLayout(row)

        row = QHBoxLayout()
        self.btn_run = QPushButton("▶  Lancer (sélection / tout)")
        self.btn_run.setProperty("class", "primary")
        self.btn_run.clicked.connect(self.run_selection)
        self.btn_stop = QPushButton("■")
        self.btn_stop.setProperty("class", "danger")
        self.btn_stop.setFixedWidth(40)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(lambda: self.runner and self.runner.stop())
        row.addWidget(self.btn_run, 1)
        row.addWidget(self.btn_stop)
        lay.addLayout(row)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setValue(0)
        lay.addWidget(self.progress)
        return w

    @staticmethod
    def _lbl(text: str) -> QLabel:
        l = QLabel(text)
        l.setProperty("class", "muted")
        return l

    def _build_request_panel(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        bar = QHBoxLayout()
        self.method = QComboBox()
        self.method.setEditable(True)
        self.method.addItems(METHODS)
        self.method.setMinimumWidth(110)
        self.url = QLineEdit()
        self.url.setPlaceholderText("http://localhost:8080/api/health")
        self.url.returnPressed.connect(self.send_manual)
        self.btn_send = QPushButton("Envoyer  ➤")
        self.btn_send.setProperty("class", "primary")
        self.btn_send.clicked.connect(self.send_manual)
        b_curl = QPushButton("curl")
        b_curl.setToolTip("Copier la commande curl équivalente")
        b_curl.clicked.connect(self.copy_curl)
        b_save = QPushButton("Enregistrer en YAML")
        b_save.clicked.connect(self.save_yaml)
        self.tpl_lbl = QLabel("")
        self.tpl_lbl.setStyleSheet(f"color:{C['accent2']};")
        bar.addWidget(self.method)
        bar.addWidget(self.url, 1)
        bar.addWidget(self.btn_send)
        bar.addWidget(b_curl)
        bar.addWidget(b_save)
        lay.addLayout(bar)
        lay.addWidget(self.tpl_lbl)

        tabs = QTabWidget()
        self.params = KVTable("Paramètre", "Valeur")
        self.hdrs = KVTable("En-tête", "Valeur")
        self.hdrs.set_dict({"Accept": "*/*", "Accept-Encoding": "gzip, deflate"})
        self.cooks = KVTable("Cookie", "Valeur")

        body_w = QWidget()
        bl = QVBoxLayout(body_w)
        brow = QHBoxLayout()
        self.body_mode = QComboBox()
        self.body_mode.addItems(["Aucun", "Brut", "JSON", "Formulaire"])
        b_fmt = QPushButton("Indenter JSON")
        b_fmt.clicked.connect(self.prettify_body)
        brow.addWidget(self.body_mode)
        brow.addWidget(b_fmt)
        brow.addStretch(1)
        self.body_edit = QPlainTextEdit()
        self.body_edit.setPlaceholderText('{"jsonrpc": "2.0", "id": 1, "method": "ping"}')
        CodeHighlighter(self.body_edit.document())
        bl.addLayout(brow)
        bl.addWidget(self.body_edit, 1)

        net_w = QWidget()
        form = QFormLayout(net_w)
        self.ua = QComboBox()
        self.ua.setEditable(True)
        for name, val in USER_AGENTS.items():
            self.ua.addItem(name if not val else val[:70], val)
        self.ua.setCurrentIndex(0)
        self.ua.currentIndexChanged.connect(self._ua_preset)
        self.ua.setToolTip("Écrase l'en-tête User-Agent du tableau s'il est renseigné")
        self.referer = QLineEdit()
        self.referer.setPlaceholderText("https://example.com/page-precedente")
        self.proxy = QLineEdit()
        self.proxy.setPlaceholderText("http://127.0.0.1:8080  ou  socks5h://127.0.0.1:9050")
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(0.1, 600)
        self.timeout.setValue(15)
        self.timeout.setSuffix(" s")
        self.verify = QCheckBox("Vérifier le certificat TLS")
        self.verify.setChecked(False)
        self.follow = QCheckBox("Suivre les redirections")
        self.follow.setChecked(True)
        self.max_redir = QSpinBox()
        self.max_redir.setRange(0, 100)
        self.max_redir.setValue(10)
        form.addRow("User-Agent", self.ua)
        form.addRow("Referer", self.referer)
        form.addRow("Proxy", self.proxy)
        form.addRow("Timeout", self.timeout)
        form.addRow("", self.verify)
        form.addRow("", self.follow)
        form.addRow("Redirections max", self.max_redir)

        for wdg, name in ((self.params, "Paramètres"), (self.hdrs, "En-têtes"), (self.cooks, "Cookies"),
                          (body_w, "Corps"), (net_w, "Identité && réseau")):
            tabs.addTab(wdg, name)
        lay.addWidget(tabs, 1)
        return w

    def _build_result_panel(self) -> QWidget:
        self.rtabs = QTabWidget()
        self.view = ResponseView()
        rep = QWidget()
        rl = QVBoxLayout(rep)
        row = QHBoxLayout()
        self.summary = QLabel("Aucun résultat")
        b_export = QPushButton("Exporter JSON")
        b_export.clicked.connect(self.export_report)
        b_clear = QPushButton("Vider")
        b_clear.clicked.connect(self.clear_results)
        row.addWidget(self.summary, 1)
        row.addWidget(b_export)
        row.addWidget(b_clear)
        rl.addLayout(row)
        self.report = make_table(["Verdict", "Sév.", "Test", "HTTP", "Temps", "Détail"],
                                 [80, 80, 360, 70, 80])
        self.report.itemSelectionChanged.connect(self._report_selected)
        rl.addWidget(self.report, 1)
        self.rtabs.addTab(self.view, "Réponse")
        self.rtabs.addTab(rep, "Rapport")
        return self.rtabs

    # ── Gestion des templates ───────────────────────────────────────────────
    def choose_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Dossier de templates YAML",
                                             str(getattr(self, "template_dir", "") or Path.home()))
        if d:
            self.load_templates(Path(d))

    def load_templates(self, folder: Path):
        self.template_dir = folder
        self.dir_lbl.setText(folder.name)
        self.dir_lbl.setToolTip(str(folder))
        self.suites.clear()
        self.tree.clear()
        self.item_map.clear()
        files = sorted([*folder.glob("*.yaml"), *folder.glob("*.yml")])
        for path in files:
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                tests = data.get("tests") or []
                if not isinstance(tests, list):
                    raise ValueError("« tests » doit être une liste")
            except Exception as e:  # noqa: BLE001
                it = QTreeWidgetItem([f"⚠ {path.name}"])
                it.setForeground(0, QColor(C["err"]))
                it.setToolTip(0, str(e))
                self.tree.addTopLevelItem(it)
                continue
            si = len(self.suites)
            self.suites.append({"path": path, "data": data})
            top = QTreeWidgetItem([f"📋 {data.get('name', path.stem)}  ({len(tests)})"])
            top.setData(0, Qt.ItemDataRole.UserRole, ("suite", si))
            top.setForeground(0, QColor(C["accent2"]))
            top.setToolTip(0, data.get("description", path.name))
            self.tree.addTopLevelItem(top)
            for ti, t in enumerate(tests):
                sev = str(t.get("severity", "info")).lower()
                child = QTreeWidgetItem([f"•  {t.get('name', t.get('id', f'test {ti + 1}'))}"])
                child.setData(0, Qt.ItemDataRole.UserRole, ("test", si, ti))
                child.setForeground(0, QColor(SEV_COLOR.get(sev, C["text"])))
                child.setToolTip(0, f"[{sev}] {t.get('description', '')}".strip())
                top.addChild(child)
                self.item_map[(si, ti)] = child
            top.setExpanded(True)
        self.statusBar().showMessage(f"{len(self.suites)} suite(s) chargée(s) depuis {folder}")

    def _suite_vars(self, si: int) -> dict:
        v = dict(self.suites[si]["data"].get("variables") or {})
        if self.base_url.text().strip():
            v["base_url"] = self.base_url.text().strip()
        return v

    def _make_job(self, si: int, ti: int) -> Job:
        s = self.suites[si]["data"]
        t = s["tests"][ti]
        return Job(name=str(t.get("name", t.get("id", f"test {ti + 1}"))), suite=str(s.get("name", "")),
                   key=(si, ti), severity=str(t.get("severity", "info")).lower(), test=t,
                   defaults=s.get("defaults") or {}, vars=self._suite_vars(si),
                   asserts=t.get("assert") or [], capture=t.get("capture") or {},
                   tid=str(t.get("id", "")))

    def _selected_jobs(self) -> list:
        items = self.tree.selectedItems() or [self.tree.topLevelItem(i)
                                              for i in range(self.tree.topLevelItemCount())]
        keys: list = []
        for it in items:
            d = it.data(0, Qt.ItemDataRole.UserRole)
            if not d:
                continue
            if d[0] == "suite":
                keys += [(d[1], i) for i in range(len(self.suites[d[1]]["data"].get("tests") or []))]
            else:
                keys.append((d[1], d[2]))
        seen, jobs = set(), []
        for k in sorted(set(keys)):
            if k not in seen:
                seen.add(k)
                jobs.append(self._make_job(*k))
        return jobs

    def load_test_into_editor(self, item: QTreeWidgetItem):
        d = item.data(0, Qt.ItemDataRole.UserRole)
        if not d or d[0] != "test":
            return
        job = self._make_job(d[1], d[2])
        spec = build_spec(job.test, job.defaults, job.vars)
        self.populate_editor(spec)
        self.current_asserts, self.current_sev, self.current_capture = job.asserts, job.severity, job.capture
        self.tpl_lbl.setText(f"Template chargé : {job.name}  —  {len(job.asserts)} assertion(s) seront évaluées à l'envoi")

    def populate_editor(self, s: RequestSpec):
        self.method.setCurrentText(s.method)
        self.url.setText(s.url)
        self.params.set_dict(s.params)
        self.hdrs.set_dict(s.headers)
        self.cooks.set_dict(s.cookies)
        self.body_mode.setCurrentText(s.body_mode)
        self.body_edit.setPlainText(s.body)
        self.proxy.setText(s.proxy)
        self.timeout.setValue(s.timeout)
        self.verify.setChecked(s.verify)
        self.follow.setChecked(s.follow_redirects)
        self.max_redir.setValue(s.max_redirects)
        self.ua.setCurrentIndex(0)
        self.ua.setEditText("")
        self.referer.clear()

    # ── Éditeur → spec ──────────────────────────────────────────────────────
    def _ua_preset(self, idx: int):
        self.ua.setEditText(self.ua.itemData(idx) or "")

    def prettify_body(self):
        try:
            self.body_edit.setPlainText(json.dumps(json.loads(self.body_edit.toPlainText()),
                                                   indent=2, ensure_ascii=False))
        except ValueError as e:
            self.statusBar().showMessage(f"JSON invalide : {e}", 5000)

    def collect_spec(self) -> RequestSpec:
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
        if body and mode == "Formulaire" and not has_header(headers, "Content-Type"):
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        url = self.url.text().strip()
        if url and "://" not in url:
            url = "http://" + url
        return RequestSpec(method=self.method.currentText().strip().upper() or "GET", url=url,
                           headers=headers, params=self.params.to_dict(), cookies=self.cooks.to_dict(),
                           body=body, body_mode=mode, proxy=self.proxy.text().strip(),
                           timeout=self.timeout.value(), verify=self.verify.isChecked(),
                           follow_redirects=self.follow.isChecked(), max_redirects=self.max_redir.value())

    # ── Exécution ───────────────────────────────────────────────────────────
    def send_manual(self):
        if self.runner and self.runner.isRunning():
            return
        spec = self.collect_spec()
        if not spec.url:
            self.statusBar().showMessage("Saisissez une URL", 4000)
            return
        job = Job(name=f"{spec.method} {spec.url}", spec=spec, asserts=self.current_asserts,
                  severity=self.current_sev, capture=self.current_capture)
        self.rtabs.setCurrentIndex(0)
        self._start([job], clear=False)

    def run_selection(self):
        if self.runner and self.runner.isRunning():
            return
        jobs = self._selected_jobs()
        if not jobs:
            self.statusBar().showMessage("Aucun test à exécuter", 4000)
            return
        target = self.base_url.text().strip() or "(base_url des templates)"
        if len(jobs) > 1 and QMessageBox.question(
                self, "Confirmer", f"Exécuter {len(jobs)} test(s) contre\n{target} ?\n\n"
                "N'utilisez cette fonction que sur des serveurs dont vous êtes responsable."
        ) != QMessageBox.StandardButton.Yes:
            return
        for it in self.item_map.values():
            it.setText(0, it.text(0).replace("✔ ", "•  ").replace("✘ ", "•  "))
        self._start(jobs, clear=True)

    def _start(self, jobs: list, clear: bool):
        if clear:
            self.clear_results()
        self.progress.setMaximum(len(jobs))
        self.progress.setValue(0)
        self.btn_send.setEnabled(False)
        self.btn_run.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.runner = Runner(jobs, self.delay.value())
        self.runner.result.connect(self._on_result)
        self.runner.progress.connect(lambda i, n: self.progress.setValue(i))
        self.runner.done.connect(self._on_done)
        self.statusBar().showMessage(f"Exécution de {len(jobs)} requête(s)…")
        self.runner.start()

    def _on_done(self):
        self.btn_send.setEnabled(True)
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.statusBar().showMessage("Terminé", 4000)

    def _on_result(self, res: TestResult):
        self.results.append(res)
        verdict, col = res.verdict()
        row = self.report.rowCount()
        self.report.insertRow(row)
        r = res.resp
        detail = r.error or next((f"{c.label} — {c.detail}" for c in res.checks if not c.ok), "")
        sev = res.job.severity
        self.report.setItem(row, 0, cell(verdict, col, True))
        self.report.setItem(row, 1, cell(sev, SEV_COLOR.get(sev, C["muted"])))
        self.report.setItem(row, 2, cell(res.job.name))
        self.report.setItem(row, 3, cell(str(r.status) if r.status else "—", status_color(r.status), True))
        self.report.setItem(row, 4, cell(f"{r.elapsed * 1000:.0f} ms", C["muted"]))
        self.report.setItem(row, 5, cell(detail, C["muted"], tip=detail))
        if res.job.key in self.item_map:
            it = self.item_map[res.job.key]
            mark = "✔ " if verdict in ("PASS", "INFO") else "✘ "
            it.setText(0, it.text(0).replace("•  ", mark, 1) if "•  " in it.text(0) else mark + it.text(0)[2:])
            it.setForeground(0, QColor(C["ok"] if verdict in ("PASS", "INFO") else col))
        self.view.show_result(r, res.checks)
        self._update_summary()

    def _report_selected(self):
        rows = {i.row() for i in self.report.selectedItems()}
        if rows:
            res = self.results[min(rows)]
            self.view.show_result(res.resp, res.checks)

    def _update_summary(self):
        v = [x.verdict()[0] for x in self.results]
        n_pass, n_fail, n_err = v.count("PASS"), v.count("FAIL"), v.count("ERREUR")
        self.summary.setText(
            f'<b>{len(v)}</b> requête(s) &nbsp; <span style="color:{C["ok"]}">✔ {n_pass} PASS</span> &nbsp; '
            f'<span style="color:{C["err"]}">✘ {n_fail} FAIL</span> &nbsp; '
            f'<span style="color:{C["warn"]}">⚠ {n_err} erreur(s)</span>')
        self.rtabs.setTabText(1, f"Rapport ({n_fail + n_err} ✘)" if n_fail + n_err else "Rapport")

    def clear_results(self):
        self.results.clear()
        self.report.setRowCount(0)
        self.summary.setText("Aucun résultat")
        self.rtabs.setTabText(1, "Rapport")

    # ── Export / utilitaires ────────────────────────────────────────────────
    def copy_curl(self):
        QApplication.clipboard().setText(to_curl(self.collect_spec()))
        self.statusBar().showMessage("Commande curl copiée dans le presse-papiers", 4000)

    def save_yaml(self):
        spec = self.collect_spec()
        path, _ = QFileDialog.getSaveFileName(
            self, "Enregistrer le test", str((getattr(self, "template_dir", None) or Path.home()) / "nouveau_test.yaml"),
            "YAML (*.yaml *.yml)")
        if not path:
            return
        u = urllib.parse.urlparse(spec.url)
        req: dict = {"method": spec.method,
                     "path": (u.path or "/") + (f"?{u.query}" if u.query else "")}
        if spec.headers:
            req["headers"] = spec.headers
        if spec.params:
            req["params"] = spec.params
        if spec.cookies:
            req["cookies"] = spec.cookies
        if spec.body:
            if spec.body_mode == "JSON":
                try:
                    req["json"] = json.loads(spec.body)
                except ValueError:
                    req["body"] = spec.body
            else:
                req["body"] = spec.body
        last = self.results[-1].resp if self.results else None
        asserts = self.current_asserts or ([{"status": last.status}] if last and last.status else [])
        doc = {"name": "Test enregistré", "description": "Généré par HTTP Debugger",
               "variables": {"base_url": f"{u.scheme}://{u.netloc}" if u.netloc else "http://localhost:8080"},
               "defaults": {"timeout": spec.timeout, "verify": spec.verify,
                            **({"proxy": spec.proxy} if spec.proxy else {})},
               "tests": [{"id": "saved-001", "name": f"{spec.method} {req['path']}", "severity": "info",
                          "request": req, "assert": asserts}]}
        Path(path).write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
        self.statusBar().showMessage(f"Enregistré : {path}", 5000)

    def export_report(self):
        if not self.results:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter le rapport", "rapport.json", "JSON (*.json)")
        if not path:
            return
        out = [{"test": r.job.name, "id": r.job.tid, "suite": r.job.suite, "severity": r.job.severity,
                "verdict": r.verdict()[0], "status": r.resp.status, "elapsed_s": round(r.resp.elapsed, 4),
                "error": r.resp.error, "url": r.resp.url,
                "checks": [{"ok": c.ok, "label": c.label, "detail": c.detail} for c in r.checks]}
               for r in self.results]
        Path(path).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        self.statusBar().showMessage(f"Rapport exporté : {path}", 5000)

    def closeEvent(self, e):
        if self.runner and self.runner.isRunning():
            self.runner.stop()
            self.runner.wait(3000)
        super().closeEvent(e)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    win = MainWindow(folder)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
