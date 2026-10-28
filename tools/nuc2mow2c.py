#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nuclei2mowing.py v4 — Convertisseur récursif Nuclei → Mowing Devil / HTTP Debugger v3.

Nouveautés v4 :
  - Helpers DSL résolus : to_lower, to_upper, base64, url_encode, unix_time,
    hex_to_dec, trim, rand_text_*, rand_int(...) → littéraux.
  - Helpers DSL inconnus → placeholder <NUCLEI_DSL:...> + warning (réécriture manuelle).
  - Variables référencées mais non définies → placeholder CHANGEME_xxx + warning.
  - Matchers part=header (word & regex) mappés vers `raw_headers_regex`
    (nouvelle assertion à ajouter dans http_debugger3b.py).
  - header_equals n'est plus généré (ne matche jamais dans Mowing Devil).
  - VULN_TAGS élargi (token-spray, creds-stuffing, login-check, intrusive).
  - Mode --lint : analyse un dossier de templates déjà convertis et signale
    les problèmes sans re-convertir.

Usage :
    python nuclei2mowing.py templates/ -o out/
    python nuclei2mowing.py templates/ --check-only
    python nuclei2mowing.py templates/ -o out/ --todo TODO.md
    python nuclei2mowing.py out/ --lint
    python nuclei2mowing.py t.yaml -o out.yaml
    python nuclei2mowing.py templates/ -o out/ --jobs 4 --report r.json

Dépendances : pyyaml (obligatoire).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import random
import re
import string
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:
    sys.exit("pyyaml requis : pip install pyyaml")


# ═════════════════════════════════════════════════════════════════════════════
#  Couleurs & rendu terminal
# ═════════════════════════════════════════════════════════════════════════════

class C:
    _on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    RESET = "\033[0m" if _on else ""
    BOLD = "\033[1m" if _on else ""
    DIM = "\033[2m" if _on else ""

    RED = "\033[38;5;203m" if _on else ""
    GREEN = "\033[38;5;114m" if _on else ""
    YELLOW = "\033[38;5;221m" if _on else ""
    BLUE = "\033[38;5;75m" if _on else ""
    MAGENTA = "\033[38;5;177m" if _on else ""
    CYAN = "\033[38;5;116m" if _on else ""
    ORANGE = "\033[38;5;215m" if _on else ""
    GREY = "\033[38;5;245m" if _on else ""


def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _visible_len(s: str) -> int:
    return len(_strip_ansi(s))


def _term_width(default: int = 100) -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return default


# ═════════════════════════════════════════════════════════════════════════════
#  Barre de progression
# ═════════════════════════════════════════════════════════════════════════════

class ProgressBar:
    def __init__(self, total: int, label: str = "Conversion"):
        self.total = max(total, 1)
        self.label = label
        self.done = 0
        self.stats = {"ok": 0, "warn": 0, "err": 0, "skip": 0}
        self.t0 = time.time()
        self._last_render = 0.0
        self._current = ""

    def _fmt_time(self, s: float) -> str:
        if s < 60:
            return f"{s:.1f}s"
        m, s = divmod(int(s), 60)
        if m < 60:
            return f"{m}m{s:02d}s"
        h, m = divmod(m, 60)
        return f"{h}h{m:02d}m"

    def _bar(self, pct: float, width: int) -> str:
        filled = int(width * pct)
        colors = [C.GREEN, C.CYAN, C.BLUE, C.MAGENTA]
        full = "█" * filled
        empty = "░" * (width - filled)
        return f"{C.BOLD}{colors[min(int(pct * 4), 3)]}{full}{C.GREY}{empty}{C.RESET}"

    def render(self, force: bool = False):
        now = time.time()
        if not force and now - self._last_render < 0.05:
            return
        self._last_render = now

        pct = self.done / self.total
        elapsed = now - self.t0
        rate = self.done / elapsed if elapsed > 0 else 0.0
        eta = (self.total - self.done) / rate if rate > 0 else 0.0

        width = _term_width()
        bar_w = max(20, min(40, width - 70))

        s = self.stats
        stats_str = (
            f"{C.GREEN}✓{s['ok']}{C.RESET} "
            f"{C.YELLOW}⚠{s['warn']}{C.RESET} "
            f"{C.RED}✗{s['err']}{C.RESET} "
            f"{C.GREY}○{s['skip']}{C.RESET}"
        )

        head = f"{C.BOLD}{C.MAGENTA}{self.label:<12}{C.RESET}"
        bar = self._bar(pct, bar_w)
        count = f"{C.BOLD}{self.done:>4}{C.RESET}{C.GREY}/{self.total}{C.RESET}"
        speed = f"{C.CYAN}{rate:4.1f}/s{C.RESET}"
        eta_s = f"{C.GREY}ETA {self._fmt_time(eta)}{C.RESET}"

        cur = self._current
        avail = width - (_visible_len(head) + bar_w + _visible_len(count)
                         + _visible_len(speed) + _visible_len(eta_s)
                         + _visible_len(stats_str) + 8)
        if avail > 8 and len(cur) > avail:
            cur = "…" + cur[-(avail - 1):]
        cur_str = f"{C.GREY}{cur}{C.RESET}" if cur else ""

        line = f"\r{head} {bar} {count} {speed} {eta_s} {stats_str} {cur_str}"
        line += " " * max(0, width - _visible_len(line) - 1)
        sys.stdout.write(line)
        sys.stdout.flush()

    def bump(self, kind: str, path: str = ""):
        self.done += 1
        self.stats[kind] = self.stats.get(kind, 0) + 1
        self._current = path
        self.render()

    def finish(self):
        self.render(force=True)
        sys.stdout.write("\n")
        sys.stdout.flush()


# ═════════════════════════════════════════════════════════════════════════════
#  Variables, helpers DSL & expressions aléatoires
# ═════════════════════════════════════════════════════════════════════════════

VAR_MAP = {
    "BaseURL": "base_url",
    "RootURL": "base_url",
    "Hostname": "hostname",
    "Host": "hostname",
    "Port": "port",
    "Scheme": "scheme",
    "randstr": "canary",
    "rand_base": "canary",
    "rand_int": "rand_int",
    "rand_text_alphanumeric": "canary",
    "rand_text_alpha": "canary",
    "rand_text_numeric": "rand_int",
    "interactsh-url": "interactsh_url",
    "FQDN": "hostname",
}

NUCLEI_VAR_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")
_RAND_FN_RE = re.compile(
    r"\{\{\s*(rand_int|rand_base|rand_text_alphanumeric|rand_text_alpha|"
    r"rand_text_numeric|randstr|randstr_1)\s*(?:\(([^)]*)\))?\s*\}\}"
)
_FN_CALL_RE = re.compile(
    r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^{}()]*)\)\s*\}\}"
)


def resolve_random_vars(s: str) -> str:
    if not isinstance(s, str):
        return s

    def _gen(m: re.Match) -> str:
        fn = m.group(1)
        args = (m.group(2) or "").strip()
        if fn == "rand_int":
            parts = [p.strip() for p in args.split(",")]
            try:
                lo, hi = ((int(parts[0]), int(parts[1]))
                          if len(parts) == 2 else (0, 999999))
            except (ValueError, IndexError):
                lo, hi = 0, 999999
            return str(random.randint(lo, hi))
        if fn in ("rand_base", "rand_text_alphanumeric", "randstr", "randstr_1"):
            n = int(args) if args.isdigit() else 8
            return "".join(random.choices(string.ascii_letters + string.digits, k=n))
        if fn == "rand_text_alpha":
            n = int(args) if args.isdigit() else 8
            return "".join(random.choices(string.ascii_letters, k=n))
        if fn == "rand_text_numeric":
            n = int(args) if args.isdigit() else 8
            return "".join(random.choices(string.digits, k=n))
        return m.group(0)

    return _RAND_FN_RE.sub(_gen, s)


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


KNOWN_HELPERS = {
    "to_lower": lambda a: _strip_quotes(a).lower(),
    "to_upper": lambda a: _strip_quotes(a).upper(),
    "trim": lambda a: _strip_quotes(a),
    "url_encode": lambda a: urllib.parse.quote(_strip_quotes(a)),
    "base64": lambda a: base64.b64encode(_strip_quotes(a).encode()).decode(),
    "unix_time": lambda a: str(int(time.time())),
    "hex_to_dec": lambda a: str(int(_strip_quotes(a), 16)),
}


def resolve_helper_calls(s: str, warnings: list, tid: str) -> str:
    """Résout les helpers DSL connus ; placeholders pour les autres."""
    if not isinstance(s, str):
        return s

    def _sub(m: re.Match) -> str:
        fn = m.group(1)
        args = m.group(2).strip()

        # rand_* déjà traités par resolve_random_vars, ne pas retoucher
        if fn.startswith("rand"):
            return m.group(0)

        handler = KNOWN_HELPERS.get(fn)
        if handler:
            try:
                return handler(args)
            except Exception:
                pass

        warnings.append(
            f"[{tid}] fonction DSL non supportée : {fn}({args}) — remplacée "
            f"par placeholder à réécrire manuellement.")
        return f"<NUCLEI_DSL:{fn}({args})>"

    return _FN_CALL_RE.sub(_sub, s)


def convert_vars(s: str, warnings: list | None = None,
                 tid: str = "?") -> str:
    if not isinstance(s, str):
        return s
    s = resolve_random_vars(s)
    if warnings is not None:
        s = resolve_helper_calls(s, warnings, tid)
    return NUCLEI_VAR_RE.sub(
        lambda m: "{{" + VAR_MAP.get(m.group(1), m.group(1)) + "}}", s)


def convert_tree(obj, warnings: list | None = None, tid: str = "?"):
    if isinstance(obj, str):
        return convert_vars(obj, warnings, tid)
    if isinstance(obj, list):
        return [convert_tree(x, warnings, tid) for x in obj]
    if isinstance(obj, dict):
        return {(convert_vars(k, warnings, tid) if isinstance(k, str) else k):
                convert_tree(v, warnings, tid) for k, v in obj.items()}
    return obj


def sev_map(sev: str) -> str:
    s = str(sev or "info").lower().strip()
    return s if s in ("info", "low", "medium", "high", "critical") else "info"


def slug(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_-]+", "-", s or "").strip("-").lower()
    return s or "test"


# ═════════════════════════════════════════════════════════════════════════════
#  Détection du type de template
# ═════════════════════════════════════════════════════════════════════════════

def is_nuclei_template(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    if "id" not in doc or "info" not in doc:
        return False
    if any(k in doc for k in ("http", "requests", "network", "dns", "ssl",
                              "websocket", "headless", "file", "code",
                              "javascript", "whois")):
        return True
    if "matchers" in doc and "info" in doc:
        return True
    return False


def is_mowing_suite(doc: Any) -> bool:
    return (isinstance(doc, dict)
            and "tests" in doc
            and isinstance(doc.get("tests"), list)
            and "id" not in doc)


# ═════════════════════════════════════════════════════════════════════════════
#  Matchers
# ═════════════════════════════════════════════════════════════════════════════

def _single_value(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _header_matcher_assert(key: str, single: str) -> dict:
    """Nuclei matche toujours sur le bloc brut 'Name: value\\n...'.
    Mowing Devil ne connaît pas cette sémantique → nouvelle assertion
    `raw_headers_regex` (à ajouter côté http_debugger3b.py)."""
    if key == "regex":
        return {"raw_headers_regex": single}
    # word
    if re.match(r"^[A-Za-z0-9_\-]+\s*:\s*\S", single):
        # Forme "Header: value" → header_matches avec regex échappée
        name, _, val = single.partition(":")
        return {"header_matches":
                {"name": name.strip(), "regex": re.escape(val.strip())}}
    # Sinon matcher générique sur le bloc
    return {"raw_headers_regex": re.escape(single)}


def matchers_to_asserts(matchers: list, condition: str, warnings: list,
                        template_id: str) -> list:
    asserts: list = []

    for m in matchers or []:
        if not isinstance(m, dict):
            continue
        mtype = m.get("type")
        part = (m.get("part") or "body").lower()
        negative = bool(m.get("negative", False))

        if mtype == "status":
            codes = m.get("status") or []
            if not isinstance(codes, list):
                codes = [codes]
            if negative:
                asserts.append({"status_not": codes})
            else:
                asserts.append({"status": codes})

        elif mtype in ("word", "regex"):
            key = mtype
            values = m.get("words" if key == "word" else "regex") or []
            if not isinstance(values, list):
                values = [values]
            single = _single_value(values)
            if single is None:
                warnings.append(
                    f"[{template_id}] matcher {key} multi-valeurs ({values!r}) : "
                    f"seule la 1re est convertie.")
                continue
            single = convert_vars(str(single), warnings, template_id)

            if part in ("body", "all", ""):
                if negative:
                    asserts.append(
                        {f"body_not_{'contains' if key == 'word' else 'regex'}": single})
                else:
                    asserts.append(
                        {f"body_{'contains' if key == 'word' else 'regex'}": single})
            if part in ("header",):
                asserts.append(_header_matcher_assert(key, single))
            if part == "raw":
                warnings.append(
                    f"[{template_id}] matcher part=raw : approximé en body_regex.")
                if not negative:
                    asserts.append({"body_regex": re.escape(str(single))})

        elif mtype == "dsl":
            dsl = m.get("dsl")
            warnings.append(
                f"[{template_id}] matcher DSL non convertible : {dsl!r}")
            asserts.append({"# TODO_dsl": dsl})

        elif mtype == "size":
            warnings.append(
                f"[{template_id}] matcher size non convertible.")

        else:
            warnings.append(f"[{template_id}] matcher type={mtype!r} ignoré.")

    if (condition or "and").lower() == "or" and len(asserts) > 1:
        warnings.append(
            f"[{template_id}] matchers-condition=or : Mowing Devil évalue "
            f"toutes les assertions en AND. Sémantique non préservée.")

    return asserts


# ═════════════════════════════════════════════════════════════════════════════
#  Extractors
# ═════════════════════════════════════════════════════════════════════════════

def extractors_to_capture(extractors: list, warnings: list,
                          template_id: str) -> dict:
    cap: dict = {}
    for i, ex in enumerate(extractors or []):
        if not isinstance(ex, dict):
            continue
        etype = ex.get("type")
        base = ex.get("name") or f"ext_{i}"

        if etype == "regex":
            pats = ex.get("regex") or []
            if not isinstance(pats, list):
                pats = [pats]
            for j, pat in enumerate(pats):
                key = base if len(pats) == 1 else f"{base}_{j}"
                cap[key] = {"regex": pat}
            if ex.get("group"):
                warnings.append(
                    f"[{template_id}] extractor '{base}' utilise group="
                    f"{ex['group']} — Mowing Devil prend m.group(1) par défaut.")
        elif etype == "kval":
            kvals = ex.get("kval") or []
            if not isinstance(kvals, list):
                kvals = [kvals]
            for kv in kvals:
                if isinstance(kv, str) and ":" in kv:
                    hname = kv.split(":", 1)[0].strip()
                    cap[f"{base}_{hname}"] = {
                        "header": kv.split(":", 1)[1].strip()}
        elif etype == "json":
            paths = ex.get("json") or []
            if not isinstance(paths, list):
                paths = [paths]
            for j, p in enumerate(paths):
                cap[base if len(paths) == 1 else f"{base}_{j}"] = {"json_path": p}
        elif etype == "xpath":
            warnings.append(f"[{template_id}] extractor xpath non supporté.")
    return cap


# ═════════════════════════════════════════════════════════════════════════════
#  Requête http[] → request{}
# ═════════════════════════════════════════════════════════════════════════════

def _parse_raw_request(raw: str) -> dict | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.replace("\r\n", "\n").strip("\n")
    if not text:
        return None
    lines = text.split("\n")
    first = lines[0].strip()
    m = re.match(r"^([A-Z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?$", first)
    if not m:
        return None
    method, path = m.group(1), m.group(2)
    headers: dict = {}
    body_lines: list = []
    in_body = False
    for line in lines[1:]:
        if not in_body and line == "":
            in_body = True
            continue
        if in_body:
            body_lines.append(line)
        else:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
    body = "\n".join(body_lines).strip("\n")
    return {"method": method, "path": path, "headers": headers,
            "body": body if body else None}


def http_request_to_mowing(req: dict, warnings: list, template_id: str) -> dict | None:
    raw_block = req.get("raw")
    if raw_block:
        raws = raw_block if isinstance(raw_block, list) else [raw_block]
        if len(raws) > 1:
            warnings.append(
                f"[{template_id}] raw avec {len(raws)} requêtes chaînées : "
                f"seule la 1re est convertie.")
        parsed = _parse_raw_request(raws[0])
        if parsed is None:
            warnings.append(
                f"[{template_id}] bloc raw illisible — conversion abandonnée.")
            return None
        out = {"method": parsed["method"]}
        raw_path = convert_vars(parsed["path"], warnings, template_id)
        m = re.match(r"^\{\{base_url\}\}(.*)$", raw_path)
        if m:
            out["path"] = m.group(1) or "/"
        elif raw_path.startswith(("http://", "https://")):
            out["url"] = raw_path
        else:
            out["path"] = raw_path
        headers = {k: convert_vars(v, warnings, template_id)
                   for k, v in parsed["headers"].items() if k.lower() != "host"}
        if headers:
            out["headers"] = headers
        if parsed["body"]:
            out["body"] = convert_vars(parsed["body"], warnings, template_id)
        return out

    out: dict = {"method": str(req.get("method", "GET")).upper()}
    raw_path = req.get("path") or req.get("url")
    if not raw_path:
        return None
    if isinstance(raw_path, list):
        warnings.append(
            f"[{template_id}] requête avec {len(raw_path)} path(s) : "
            f"seul le 1er est converti.")
        raw_path = raw_path[0]
    raw_path = convert_vars(str(raw_path), warnings, template_id)
    m = re.match(r"^\{\{base_url\}\}(.*)$", raw_path)
    if m:
        out["path"] = m.group(1) or "/"
    elif raw_path.startswith(("http://", "https://")):
        out["url"] = raw_path
    else:
        out["path"] = raw_path

    if req.get("headers"):
        out["headers"] = convert_tree(req["headers"], warnings, template_id)

    if "body" in req:
        out["body"] = convert_vars(str(req["body"]), warnings, template_id)
    elif "json" in req:
        out["json"] = convert_tree(req["json"], warnings, template_id)
    elif "form" in req:
        out["form"] = convert_tree(req["form"], warnings, template_id)

    if req.get("multipart"):
        warnings.append(f"[{template_id}] multipart : converti en body brut.")

    return out


# ═════════════════════════════════════════════════════════════════════════════
#  Résultat
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ConvResult:
    src: Path
    dst: Path | None
    status: str = "skip"   # ok | warn | err | skip
    warnings: list = field(default_factory=list)
    error: str = ""
    duration: float = 0.0
    category: str = "convertible"


# ═════════════════════════════════════════════════════════════════════════════
#  Conversion du template complet
# ═════════════════════════════════════════════════════════════════════════════

VULN_TAGS = ("vuln", "default-login", "exposure", "cve", "rce", "injection",
             "xss", "sqli", "ssrf", "lfi", "rfi", "token-spray",
             "creds-stuffing", "login-check", "intrusive")

NON_HTTP_PROTOS = ("network", "dns", "ssl", "websocket", "headless",
                   "file", "code", "javascript", "whois")


def detect_undefined_vars(suite: dict, warnings: list, tid: str) -> None:
    """Ajoute des placeholders CHANGEME_xxx pour les variables référencées
    mais non définies. Cas particulier : interactsh_url → warning seul."""
    defined = set((suite.get("variables") or {}).keys())
    builtin = {"base_url", "canary", "uuid", "timestamp", "rand_int",
               "hostname", "port", "scheme"}

    referenced: set[str] = set()

    def _scan(obj):
        if isinstance(obj, str):
            for m in NUCLEI_VAR_RE.finditer(obj):
                referenced.add(m.group(1))
        elif isinstance(obj, dict):
            for v in obj.values():
                _scan(v)
        elif isinstance(obj, list):
            for v in obj:
                _scan(v)

    _scan(suite.get("tests"))
    undefined = sorted(referenced - defined - builtin)

    for var in undefined:
        if var == "interactsh_url":
            warnings.append(
                f"[{tid}] {{interactsh_url}} référencé mais aucun collaborator "
                f"Mowing Devil — fournir --var interactsh_url=https://...")
            continue
        placeholder = f"CHANGEME_{var}"
        suite["variables"][var] = placeholder
        warnings.append(
            f"[{tid}] variable '{var}' non définie → placeholder "
            f"'{placeholder}' (--var {var}=... au runtime).")


def convert_template(nuclei_doc: dict, strict: bool = False,
                     check_only: bool = False) -> tuple[dict, list, str]:
    warnings: list = []
    info = nuclei_doc.get("info") or {}
    tid = nuclei_doc.get("id") or slug(info.get("name", "template"))
    suite_name = str(info.get("name") or tid).strip()

    variables = {
        "base_url": "http://localhost:8080",
        "canary": "{{uuid}}",
    }
    for k, v in (nuclei_doc.get("variables") or {}).items():
        variables.setdefault(k, convert_tree(v, warnings, tid))

    defaults = {"read_timeout": 10, "verify": False, "follow_redirects": True}

    tests: list = []
    http_blocks = nuclei_doc.get("http") or nuclei_doc.get("requests") or []
    if not isinstance(http_blocks, list):
        http_blocks = [http_blocks]

    present_non_http = [k for k in NON_HTTP_PROTOS if k in nuclei_doc]
    if present_non_http and not http_blocks:
        warnings.append(
            f"[{tid}] protocole(s) non-HTTP ({', '.join(present_non_http)}) : "
            f"non convertible.")
        return {}, warnings, "non-convertible"

    if len(http_blocks) > 1:
        warnings.append(
            f"[{tid}] {len(http_blocks)} blocs http[] : un test par bloc, "
            f"sans chaînage.")

    base_id = slug(tid)
    sev = sev_map(info.get("severity"))
    tmpl_matchers = nuclei_doc.get("matchers") or []
    tmpl_extractors = nuclei_doc.get("extractors") or []
    tags_lower = str(info.get("tags") or "").lower()
    verdict_sem = ("vulnerability"
                   if any(t in tags_lower for t in VULN_TAGS) else "hardening")

    for idx, block in enumerate(http_blocks):
        if not isinstance(block, dict):
            continue
        test_id = f"{base_id}-{idx+1}" if len(http_blocks) > 1 else base_id

        request = http_request_to_mowing(block, warnings, test_id)
        if request is None:
            warnings.append(
                f"[{test_id}] requête non convertible — test abandonné.")
            continue

        matchers = block.get("matchers") or tmpl_matchers
        cond = (block.get("matchers-condition")
                or nuclei_doc.get("matchers-condition") or "and")
        asserts = matchers_to_asserts(matchers, cond, warnings, test_id)
        if not asserts:
            warnings.append(
                f"[{test_id}] aucun matcher convertible — test abandonné.")
            continue

        extractors = block.get("extractors") or tmpl_extractors
        capture = extractors_to_capture(extractors, warnings, test_id)

        test = {
            "id": test_id,
            "name": convert_vars(block.get("name") or f"{tid} — étape {idx+1}",
                                 warnings, test_id),
            "severity": sev,
            "verdict_semantics": verdict_sem,
            "request": request,
            "assert": asserts,
        }
        if capture:
            test["capture"] = capture
        tests.append(test)

    if not tests:
        warnings.append(
            f"[{tid}] aucun test convertible — template NON généré.")
        if strict:
            raise ValueError("aucun test convertible")
        return {}, warnings, "non-convertible"

    suite: dict = {"name": suite_name}

    meta_lines = []
    if info.get("description"):
        desc = re.sub(r"\s+", " ", str(info["description"])).strip()
        meta_lines.append(f"description: {desc[:300]}")
    for k in ("author", "reference", "tags", "classification"):
        if info.get(k):
            v = info[k]
            if isinstance(v, list):
                v = ", ".join(map(str, v))
            meta_lines.append(f"{k}: {v}")
    if meta_lines:
        suite["_nuclei_metadata"] = meta_lines

    if any(t["severity"] in ("high", "critical") for t in tests):
        suite["scope"] = {"active_testing": True, "requests_per_second": 2}

    suite["variables"] = variables
    suite["defaults"] = defaults
    suite["tests"] = tests

    # Patch C — variables non définies → placeholders
    detect_undefined_vars(suite, warnings, tid)

    if strict and warnings:
        raise ValueError("Conversion non stricte :\n  - " + "\n  - ".join(warnings))

    category = "partial" if warnings else "convertible"
    return suite, warnings, category


# ═════════════════════════════════════════════════════════════════════════════
#  Émission YAML
# ═════════════════════════════════════════════════════════════════════════════

def emit_yaml(suite: dict, src: Path | None = None) -> str:
    suite = dict(suite)
    meta = suite.pop("_nuclei_metadata", None)
    body = yaml.safe_dump(suite, sort_keys=False, allow_unicode=True,
                          default_flow_style=False, width=100)
    header = ["# Converti depuis un template Nuclei par nuclei2mowing.py v4",
              "# Format cible : Mowing Devil / HTTP Debugger v3",
              "# Vérifier manuellement les warnings émis sur stderr."]
    if src:
        header.append(f"# Source : {src.name}")
    if meta:
        header += ["#", "# Métadonnées Nuclei originales :"]
        header += [f"#   {line}" for line in meta]
    return "\n".join(header) + "\n\n" + body


# ═════════════════════════════════════════════════════════════════════════════
#  Lint — analyse un template Mowing Devil converti
# ═════════════════════════════════════════════════════════════════════════════

def lint_mowing_suite(doc: dict) -> list[str]:
    """Signale les problèmes connus dans un template Mowing Devil."""
    issues: list[str] = []
    if not isinstance(doc, dict):
        return ["racine YAML invalide (non-dict)"]

    defined = set((doc.get("variables") or {}).keys())
    builtin = {"base_url", "canary", "uuid", "timestamp", "rand_int",
               "hostname", "port", "scheme"}
    var_re = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")

    def _walk(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                _walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                _walk(v, f"{path}[{i}]")
        elif isinstance(obj, str):
            # Variables non résolues
            for m in var_re.finditer(obj):
                v = m.group(1).strip()
                base = v.split("(")[0].strip()
                if v.startswith(("repeat:", "env:", "b64:", "sha1:", "sha256:")):
                    continue
                if v in ("uuid", "timestamp"):
                    continue
                if base in builtin or base in defined:
                    continue
                issues.append(
                    f"{path} : variable non résolue {{{{ {v} }}}}")
            # Placeholders CHANGEME
            for m in re.finditer(r"CHANGEME_\w+", obj):
                issues.append(
                    f"{path} : placeholder {m.group(0)} (remplacer au runtime)")
            # Placeholders DSL
            for m in re.finditer(r"<NUCLEI_DSL:[^>]+>", obj):
                issues.append(
                    f"{path} : DSL non résolu {m.group(0)}")

    _walk(doc.get("tests") or [])

    # Vérif assertions
    for test in (doc.get("tests") or []):
        if not isinstance(test, dict):
            continue
        tname = test.get("id") or test.get("name") or "?"
        for a in (test.get("assert") or []):
            if not isinstance(a, dict) or len(a) != 1:
                issues.append(f"{tname} : assertion invalide {a!r}")
                continue
            (k, v), = a.items()
            if k == "header_equals":
                issues.append(
                    f"{tname} : header_equals ne matche jamais sur valeur "
                    f"longue — préférer header_matches")
            if k == "header_matches" and isinstance(v, dict):
                name = str(v.get("name", ""))
                if name.startswith("(") or "?" in name:
                    issues.append(
                        f"{tname} : header_matches.name semble être un "
                        f"fragment regex ({name!r}) — utiliser raw_headers_regex")
                try:
                    re.compile(str(v.get("regex", "")))
                except re.error as e:
                    issues.append(
                        f"{tname} : regex invalide dans header_matches : {e}")
            if k in ("body_regex", "body_not_regex", "raw_headers_regex"):
                try:
                    re.compile(str(v))
                except re.error as e:
                    issues.append(f"{tname} : {k} regex invalide : {e}")
            if k == "# TODO_dsl":
                issues.append(f"{tname} : matcher DSL non converti {v!r}")

    return issues


# ═════════════════════════════════════════════════════════════════════════════
#  Traitement d'un fichier
# ═════════════════════════════════════════════════════════════════════════════

def process_file(src: Path, dst: Path | None, strict: bool,
                 skip_non_nuclei: bool = True,
                 force: bool = False,
                 check_only: bool = False,
                 lint: bool = False) -> ConvResult:
    t0 = time.perf_counter()
    res = ConvResult(src=src, dst=dst)

    if not check_only and not lint and dst and dst.exists() and not force:
        res.status = "skip"
        res.error = "destination existe (--force pour écraser)"
        res.duration = time.perf_counter() - t0
        return res

    try:
        raw = yaml.safe_load(src.read_text(encoding="utf-8"))
    except Exception as e:
        res.status = "err"
        res.error = f"lecture/YAML: {e}"
        res.duration = time.perf_counter() - t0
        return res

    if not isinstance(raw, dict):
        res.status = "err"
        res.error = "racine YAML non-dict"
        res.duration = time.perf_counter() - t0
        return res

    # Mode lint
    if lint:
        if not is_mowing_suite(raw):
            res.status = "skip"
            res.error = "pas un template Mowing Devil (utiliser conversion)"
            res.duration = time.perf_counter() - t0
            return res
        issues = lint_mowing_suite(raw)
        res.warnings = issues
        res.status = "warn" if issues else "ok"
        res.category = "partial" if issues else "convertible"
        res.duration = time.perf_counter() - t0
        return res

    # Détection format
    if is_mowing_suite(raw):
        res.status = "skip"
        res.error = "déjà au format Mowing Devil"
        res.duration = time.perf_counter() - t0
        return res

    if not is_nuclei_template(raw):
        if skip_non_nuclei:
            res.status = "skip"
            res.error = "n'est pas un template Nuclei"
            res.duration = time.perf_counter() - t0
            return res
        res.warnings.append("template non-Nuclei : conversion best-effort")

    try:
        suite, warnings, category = convert_template(raw, strict=strict,
                                                     check_only=check_only)
    except ValueError as e:
        res.status = "err"
        res.error = f"strict: {e}"
        res.duration = time.perf_counter() - t0
        return res

    res.warnings = warnings
    res.category = category

    if check_only:
        if category == "convertible":
            res.status = "ok"
        elif category == "partial":
            res.status = "warn"
        else:
            res.status = "err"
            res.error = res.error or "non-convertible"
        res.duration = time.perf_counter() - t0
        return res

    if not suite:
        res.status = "skip"
        res.error = res.error or "non-convertible"
        res.duration = time.perf_counter() - t0
        return res

    text = emit_yaml(suite, src)
    if dst is None:
        sys.stdout.write(text)
    else:
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(text, encoding="utf-8")
        except Exception as e:
            res.status = "err"
            res.error = f"écriture: {e}"
            res.duration = time.perf_counter() - t0
            return res

    res.status = "warn" if warnings else "ok"
    res.duration = time.perf_counter() - t0
    return res


# ═════════════════════════════════════════════════════════════════════════════
#  Découverte récursive
# ═════════════════════════════════════════════════════════════════════════════

def discover_templates(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files = set()
    for pat in ("*.yaml", "*.yml"):
        for p in root.rglob(pat):
            if p.is_file():
                files.add(p.resolve())
    return sorted(files)


# ═════════════════════════════════════════════════════════════════════════════
#  Génération TODO.md
# ═════════════════════════════════════════════════════════════════════════════

def write_todo(path: Path, results: list[ConvResult],
               out_dir: Path | None, title: str = "Templates partiels") -> None:
    partials = [r for r in results if r.category == "partial"]
    nonconv = [r for r in results if r.category == "non-convertible"]
    errs = [r for r in results if r.status == "err"]

    lines = [f"# TODO — {title}", ""]
    lines.append(f"Généré le {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append(f"- **Partiels** : {len(partials)}")
    lines.append(f"- **Non convertibles** : {len(nonconv)}")
    lines.append(f"- **Erreurs** : {len(errs)}")
    lines.append("")

    if nonconv:
        lines.append("## Non convertibles (protocole, raw invalide, etc.)")
        lines.append("")
        for r in nonconv:
            lines.append(f"- `{r.src.name}` — {r.error or 'voir warnings'}")
            for w in r.warnings[:3]:
                lines.append(f"  - {w}")
        lines.append("")

    if partials:
        lines.append("## Partiels — réécriture manuelle recommandée")
        lines.append("")
        for r in partials:
            lines.append(f"### `{r.src.name}`")
            if out_dir:
                lines.append(f"Sortie : `{out_dir / r.src.name}`")
            for w in r.warnings:
                lines.append(f"- {w}")
            lines.append("")

    if errs:
        lines.append("## Erreurs")
        lines.append("")
        for r in errs:
            lines.append(f"- `{r.src.name}` — {r.error}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


# ═════════════════════════════════════════════════════════════════════════════
#  Orchestration
# ═════════════════════════════════════════════════════════════════════════════

def run_batch(sources: Iterable[Path], out_dir: Path | None, strict: bool,
              jobs: int, skip_non_nuclei: bool, force: bool,
              dry_run: bool, check_only: bool, lint: bool,
              todo_path: Path | None) -> dict:
    files: list[Path] = []
    for s in sources:
        files.extend(discover_templates(s))
    files = sorted(set(files))

    if dry_run:
        print(f"{C.BOLD}{C.MAGENTA}── Dry-run : {len(files)} fichier(s) ──{C.RESET}")
        for f in files:
            print(f"  {C.GREY}→{C.RESET} {f}")
        return {"files": [str(f) for f in files], "dry_run": True}

    if not files:
        print(f"{C.YELLOW}⚠ Aucun fichier YAML trouvé.{C.RESET}")
        return {"total": 0, "results": []}

    if lint:
        label = "Lint"
    elif check_only:
        label = "Check"
    else:
        label = "Conversion"
    bar = ProgressBar(len(files), label=label)
    results: list[ConvResult] = []

    mode = "lint" if lint else "check-only" if check_only else "conversion"
    print(f"{C.BOLD}{C.MAGENTA}╭─ Nuclei → Mowing Devil v4 {C.RESET}"
          f"{C.GREY}({len(files)} fichier(s), mode={mode}, jobs={jobs}){C.RESET}")
    target = ("(lint, aucune écriture)" if lint
              else "(check-only, aucune écriture)" if check_only
              else (out_dir or "(stdout)"))
    print(f"{C.MAGENTA}╰─{C.RESET} cible : {C.BOLD}{target}{C.RESET}")

    def _run_one(f: Path) -> ConvResult:
        if lint:
            return process_file(f, None, strict, skip_non_nuclei, force,
                                check_only=False, lint=True)
        if check_only:
            return process_file(f, None, strict, skip_non_nuclei, force,
                                check_only=True)
        dst = (out_dir / f.name) if out_dir else None
        return process_file(f, dst, strict, skip_non_nuclei, force)

    if jobs <= 1 or len(files) == 1:
        for f in files:
            r = _run_one(f)
            results.append(r)
            bar.bump(r.status, f.name)
    else:
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futures = {ex.submit(_run_one, f): f for f in files}
            for fut in as_completed(futures):
                f = futures[fut]
                try:
                    r = fut.result()
                except Exception as e:
                    r = ConvResult(src=f, dst=None, status="err",
                                   error=f"{type(e).__name__}: {e}")
                results.append(r)
                bar.bump(r.status, f.name)

    bar.finish()

    total = len(results)
    ok = sum(1 for r in results if r.status == "ok")
    warn = sum(1 for r in results if r.status == "warn")
    err = sum(1 for r in results if r.status == "err")
    skip = sum(1 for r in results if r.status == "skip")
    conv = sum(1 for r in results if r.category == "convertible")
    part = sum(1 for r in results if r.category == "partial")
    nonc = sum(1 for r in results if r.category == "non-convertible")

    print()
    print(f"{C.BOLD}{C.MAGENTA}╭─ Résumé{C.RESET}")
    if lint or check_only:
        print(f"{C.MAGENTA}│{C.RESET}  {C.GREEN}✓ {conv:>4}{C.RESET} "
              f"{'sans problème' if lint else 'convertible(s)'}")
        print(f"{C.MAGENTA}│{C.RESET}  {C.YELLOW}⚠ {part:>4}{C.RESET} "
              f"{'avec problèmes' if lint else 'partiel(s)'}")
        if nonc:
            print(f"{C.MAGENTA}│{C.RESET}  {C.RED}✗ {nonc:>4}{C.RESET} "
                  f"{'invalides' if lint else 'non-convertible(s)'}")
        if skip:
            print(f"{C.MAGENTA}│{C.RESET}  {C.GREY}○ {skip:>4}{C.RESET} skippé(s)")
    else:
        print(f"{C.MAGENTA}│{C.RESET}  {C.GREEN}✓ {ok:>4}{C.RESET} converti(s) sans warning")
        if warn:
            print(f"{C.MAGENTA}│{C.RESET}  {C.YELLOW}⚠ {warn:>4}{C.RESET} avec warning(s)")
        if err:
            print(f"{C.MAGENTA}│{C.RESET}  {C.RED}✗ {err:>4}{C.RESET} erreur(s)")
        if skip:
            print(f"{C.MAGENTA}│{C.RESET}  {C.GREY}○ {skip:>4}{C.RESET} skippé(s)")
    print(f"{C.MAGENTA}│{C.RESET}  {C.BOLD}{total:>4}{C.RESET} au total")

    if err and not check_only and not lint:
        print(f"\n{C.BOLD}{C.RED}Erreurs :{C.RESET}")
        for r in results:
            if r.status == "err":
                print(f"  {C.RED}✗{C.RESET} {r.src}  {C.GREY}— {r.error}{C.RESET}")

    if (warn or nonc or lint) and not check_only:
        shown = 0
        print(f"\n{C.BOLD}{C.YELLOW}Détails (premiers 25) :{C.RESET}")
        for r in results:
            if (r.status in ("warn", "err") or lint) and r.warnings:
                for w in r.warnings[:3]:
                    print(f"  {C.YELLOW}⚠{C.RESET} {C.GREY}{r.src.name}:{C.RESET} {w}")
                    shown += 1
                    if shown >= 25:
                        break
            if shown >= 25:
                break
        total_w = sum(len(r.warnings) for r in results)
        if shown < total_w:
            print(f"  {C.GREY}… et {total_w - shown} autre(s) — "
                  f"voir --report ou --todo.{C.RESET}")

    print(f"{C.MAGENTA}╰─{C.RESET}")

    if todo_path:
        write_todo(todo_path, results, out_dir,
                   title="Lint" if lint else "Templates partiels")
        print(f"{C.GREY}TODO écrit : {todo_path}{C.RESET}")

    return {
        "total": total, "ok": ok, "warn": warn, "err": err, "skip": skip,
        "convertible": conv, "partial": part, "non_convertible": nonc,
        "results": [
            {"src": str(r.src), "dst": str(r.dst) if r.dst else None,
             "status": r.status, "category": r.category,
             "duration_s": round(r.duration, 3),
             "warnings": r.warnings, "error": r.error}
            for r in results
        ],
    }


# ═════════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════════

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="nuclei2mowing",
        description="Convertisseur récursif Nuclei → Mowing Devil (v4)")
    ap.add_argument("inputs", nargs="+",
                    help="Fichier(s) ou dossier(s) d'entrée (récursif)")
    ap.add_argument("-o", "--output",
                    help="Fichier (single) ou dossier (multi) de sortie")
    ap.add_argument("--strict", action="store_true",
                    help="Échoue si la conversion n'est pas fidèle")
    ap.add_argument("--skip-non-nuclei", action="store_true", default=True,
                    help="Ignore les YAML non-Nuclei (défaut)")
    ap.add_argument("--convert-non-nuclei", dest="skip_non_nuclei",
                    action="store_false",
                    help="Convertit même les YAML non-Nuclei")
    ap.add_argument("--force", action="store_true",
                    help="Écrase les fichiers de sortie existants")
    ap.add_argument("--jobs", type=int, default=1,
                    help="Fichiers traités en parallèle (défaut: 1)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Liste les fichiers détectés sans convertir")
    ap.add_argument("--check-only", action="store_true",
                    help="Classe les templates sans écrire de sortie")
    ap.add_argument("--lint", action="store_true",
                    help="Analyse des templates Mowing Devil déjà convertis")
    ap.add_argument("--todo", metavar="FICHIER",
                    help="Génère un TODO.md des templates partiels/problématiques")
    ap.add_argument("--report", metavar="FICHIER",
                    help="Écrit un rapport JSON détaillé")
    args = ap.parse_args()

    sources = [Path(s) for s in args.inputs]
    for s in sources:
        if not s.exists():
            print(f"{C.RED}✗{C.RESET} entrée introuvable : {s}", file=sys.stderr)
            return 2

    single = len(sources) == 1 and sources[0].is_file()

    # ── Mode single fichier ────────────────────────────────────────────
    if single:
        out = Path(args.output) if args.output else None
        if out and out.is_dir():
            print(f"{C.RED}✗{C.RESET} -o doit être un fichier en mode single",
                  file=sys.stderr)
            return 2
        res = process_file(sources[0], out, args.strict,
                           args.skip_non_nuclei, args.force,
                           check_only=args.check_only, lint=args.lint)
        if res.status == "err":
            print(f"{C.RED}✗{C.RESET} {res.error}", file=sys.stderr)
            return 1
        if res.status == "skip":
            print(f"{C.GREY}○{C.RESET} {res.error}", file=sys.stderr)
            return 0
        for w in res.warnings:
            print(f"{C.YELLOW}⚠{C.RESET} {w}", file=sys.stderr)
        if args.lint:
            print(f"{C.CYAN}ℹ{C.RESET} lint : {len(res.warnings)} problème(s)")
        elif args.check_only:
            print(f"{C.CYAN}ℹ{C.RESET} catégorie : {res.category}")
        else:
            print(f"{C.GREEN}✓{C.RESET} {sources[0].name} → {out}", file=sys.stderr)

        if args.todo:
            write_todo(Path(args.todo), [res], out.parent if out else None,
                       title="Lint" if args.lint else "Templates partiels")
            print(f"{C.GREY}TODO écrit : {args.todo}{C.RESET}")
        if args.report:
            Path(args.report).write_text(json.dumps({
                "src": str(sources[0]), "dst": str(out) if out else None,
                "status": res.status, "category": res.category,
                "warnings": res.warnings, "error": res.error,
            }, indent=2, ensure_ascii=False), encoding="utf-8")
        return 0

    # ── Mode batch ─────────────────────────────────────────────────────
    out_dir = Path(args.output) if args.output else None
    if out_dir and out_dir.exists() and out_dir.is_file():
        print(f"{C.RED}✗{C.RESET} -o doit être un dossier en mode batch",
              file=sys.stderr)
        return 2

    summary = run_batch(sources, out_dir, args.strict, args.jobs,
                        args.skip_non_nuclei, args.force, args.dry_run,
                        args.check_only, args.lint,
                        Path(args.todo) if args.todo else None)

    if args.report and not args.dry_run:
        Path(args.report).write_text(
            json.dumps(summary, indent=2, ensure_ascii=False),
            encoding="utf-8")
        print(f"{C.GREY}Rapport écrit : {args.report}{C.RESET}")

    return 0 if summary.get("err", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
