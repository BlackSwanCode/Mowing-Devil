#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nuclei2mowing.py — Convertisseur récursif Nuclei → Mowing Devil / HTTP Debugger v3.

Parcourt récursivement un ou plusieurs dossiers (ou fichiers isolés), détecte
les templates Nuclei, les convertit au format de suite `tests[]` de Mowing
Devil, et affiche une progression colorée avec statistiques.

Usage :
    python nuclei2mowing.py templates/                     # → stdout (single) ou dossier_courant/out/
    python nuclei2mowing.py templates/ -o out/             # batch
    python nuclei2mowing.py t.yaml -o out.yaml             # single
    python nuclei2mowing.py templates/ -o out/ --jobs 4    # parallèle
    python nuclei2mowing.py templates/ -o out/ --strict    # échoue si perte sémantique
    python nuclei2mowing.py templates/ -o out/ --report conversion-report.json

Dépendances : pyyaml (obligatoire), rich (optionnel — fallback ANSI natif).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
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
    """Palette ANSI (désactivée automatiquement si pas de TTY ou NO_COLOR)."""
    _on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    RESET = "\033[0m" if _on else ""
    BOLD = "\033[1m" if _on else ""
    DIM = "\033[2m" if _on else ""
    ITALIC = "\033[3m" if _on else ""

    RED = "\033[38;5;203m" if _on else ""
    GREEN = "\033[38;5;114m" if _on else ""
    YELLOW = "\033[38;5;221m" if _on else ""
    BLUE = "\033[38;5;75m" if _on else ""
    MAGENTA = "\033[38;5;177m" if _on else ""
    CYAN = "\033[38;5;116m" if _on else ""
    ORANGE = "\033[38;5;215m" if _on else ""
    GREY = "\033[38;5;245m" if _on else ""
    WHITE = "\033[38;5;252m" if _on else ""
    BLACK = "\033[38;5;232m" if _on else ""

    BG_GREEN = "\033[48;5;114m" if _on else ""
    BG_BLUE = "\033[48;5;75m" if _on else ""
    BG_RED = "\033[48;5;203m" if _on else ""
    BG_YELLOW = "\033[48;5;221m" if _on else ""
    BG_MAGENTA = "\033[48;5;177m" if _on else ""
    BG_DARK = "\033[48;5;236m" if _on else ""


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
#  Barre de progression colorée
# ═════════════════════════════════════════════════════════════════════════════

class ProgressBar:
    """Barre de progression animée, avec compteurs PASS/WARN/FAIL/ERROR/SKIP."""

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
        # Dégradé : vert → cyan → bleu → magenta
        colors = [C.GREEN, C.CYAN, C.BLUE, C.MAGENTA]
        full = "█" * filled
        empty = "░" * (width - filled)
        return f"{C.BOLD}{colors[min(int(pct * 4), 3)]}{full}{C.GREY}{empty}{C.RESET}"

    def render(self, force: bool = False):
        now = time.time()
        # throttle ~20 fps pour éviter le spam
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

        # Nom du fichier courant (tronqué)
        cur = self._current
        avail = width - (_visible_len(head) + bar_w + _visible_len(count)
                         + _visible_len(speed) + _visible_len(eta_s)
                         + _visible_len(stats_str) + 8)
        if avail > 8 and len(cur) > avail:
            cur = "…" + cur[-(avail - 1):]
        cur_str = f"{C.GREY}{cur}{C.RESET}" if cur else ""

        line = f"\r{head} {bar} {count} {speed} {eta_s} {stats_str} {cur_str}"
        # Pad pour effacer reliquats
        line += " " * max(0, width - _visible_len(line) - 1)
        sys.stdout.write(line)
        sys.stdout.flush()

    def bump(self, kind: str, path: str = ""):
        """kind ∈ {ok, warn, err, skip}"""
        self.done += 1
        self.stats[kind] = self.stats.get(kind, 0) + 1
        self._current = path
        self.render()

    def finish(self):
        self.render(force=True)
        sys.stdout.write("\n")
        sys.stdout.flush()


# ═════════════════════════════════════════════════════════════════════════════
#  Helpers de conversion
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


def convert_vars(s: str) -> str:
    if not isinstance(s, str):
        return s
    return NUCLEI_VAR_RE.sub(
        lambda m: "{{" + VAR_MAP.get(m.group(1), m.group(1)) + "}}", s)


def convert_tree(obj):
    if isinstance(obj, str):
        return convert_vars(obj)
    if isinstance(obj, list):
        return [convert_tree(x) for x in obj]
    if isinstance(obj, dict):
        return {convert_vars(k) if isinstance(k, str) else k: convert_tree(v)
                for k, v in obj.items()}
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
    # Protocoles Nuclei reconnus
    if any(k in doc for k in ("http", "requests", "network", "dns", "ssl",
                              "websocket", "headless", "file", "code",
                              "javascript", "whois")):
        return True
    # Certains templates très anciens n'ont que matchers à la racine
    if "matchers" in doc and "info" in doc:
        return True
    return False


def is_mowing_suite(doc: Any) -> bool:
    """Un template déjà converti (suite Mowing Devil) ne doit pas être retraité."""
    return (isinstance(doc, dict)
            and "tests" in doc
            and isinstance(doc.get("tests"), list)
            and "id" not in doc)


# ═════════════════════════════════════════════════════════════════════════════
#  Matchers / extractors → assertions / capture
# ═════════════════════════════════════════════════════════════════════════════

def _single_value(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


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

            if part in ("body", "all", ""):
                if negative:
                    asserts.append(
                        {f"body_not_{'contains' if key == 'word' else 'regex'}": single})
                else:
                    asserts.append(
                        {f"body_{'contains' if key == 'word' else 'regex'}": single})
            if part == "header" or part == "all":
                if isinstance(single, str) and ":" in single:
                    name, _, val = single.partition(":")
                    if key == "regex":
                        asserts.append({"header_matches":
                                        {"name": name.strip(), "regex": val.strip()}})
                    else:
                        asserts.append({"header_equals":
                                        {"name": name.strip(), "value": val.strip()}})
                else:
                    warnings.append(
                        f"[{template_id}] matcher part=header non exprimable "
                        f"directement (valeur {single!r}). Réécrire manuellement.")
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

        else:
            warnings.append(f"[{template_id}] matcher type={mtype!r} ignoré.")

    if (condition or "and").lower() == "or" and len(asserts) > 1:
        warnings.append(
            f"[{template_id}] matchers-condition=or : Mowing Devil évalue "
            f"toutes les assertions en AND. Sémantique non préservée.")

    return asserts


def extractors_to_capture(extractors: list, warnings: list,
                          template_id: str) -> dict:
    cap: dict = {}
    for ex in extractors or []:
        if not isinstance(ex, dict):
            continue
        name = ex.get("name") or f"extracted_{len(cap)}"
        etype = ex.get("type")

        if etype == "regex":
            pats = ex.get("regex") or []
            if isinstance(pats, list) and pats:
                cap[name] = {"regex": pats[0]}
        elif etype == "kval":
            kvals = ex.get("kval") or []
            if isinstance(kvals, list) and kvals and ":" in kvals[0]:
                cap[name] = {"header": kvals[0].split(":", 1)[1].strip()}
        elif etype == "json":
            paths = ex.get("json") or []
            if isinstance(paths, list) and paths:
                cap[name] = {"json_path": paths[0]}
        elif etype == "xpath":
            warnings.append(f"[{template_id}] extractor xpath non supporté.")
    return cap


# ═════════════════════════════════════════════════════════════════════════════
#  Requête http[] → request{} Mowing Devil
# ═════════════════════════════════════════════════════════════════════════════

def http_request_to_mowing(req: dict, warnings: list,
                           template_id: str) -> dict:
    out: dict = {"method": str(req.get("method", "GET")).upper()}

    raw_path = req.get("path") or req.get("url") or "/"
    if isinstance(raw_path, list):
        warnings.append(
            f"[{template_id}] requête avec {len(raw_path)} path(s) : "
            f"seul le 1er est converti.")
        raw_path = raw_path[0]
    raw_path = convert_vars(raw_path)

    m = re.match(r"^\{\{base_url\}\}(.*)$", raw_path)
    if m:
        out["path"] = m.group(1) or "/"
    elif raw_path.startswith(("http://", "https://")):
        out["url"] = raw_path
    else:
        out["path"] = raw_path

    if req.get("headers"):
        out["headers"] = convert_tree(req["headers"])

    if "body" in req:
        out["body"] = convert_vars(str(req["body"]))
    elif "json" in req:
        out["json"] = convert_tree(req["json"])
    elif "form" in req:
        out["form"] = convert_tree(req["form"])

    if req.get("multipart"):
        warnings.append(f"[{template_id}] multipart : converti en body brut.")

    return out


# ═════════════════════════════════════════════════════════════════════════════
#  Conversion d'un template complet
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ConvResult:
    src: Path
    dst: Path | None
    status: str = "skip"   # ok | warn | err | skip
    warnings: list = field(default_factory=list)
    error: str = ""
    duration: float = 0.0


def convert_template(nuclei_doc: dict, strict: bool = False) -> tuple[dict, list]:
    warnings: list = []
    info = nuclei_doc.get("info") or {}
    tid = nuclei_doc.get("id") or slug(info.get("name", "template"))
    suite_name = info.get("name") or tid

    variables = {
        "base_url": "http://localhost:8080",
        "canary": "{{uuid}}",
    }
    for k, v in (nuclei_doc.get("variables") or {}).items():
        variables.setdefault(k, convert_tree(v))

    defaults = {"read_timeout": 10, "verify": False, "follow_redirects": True}

    tests: list = []
    http_blocks = nuclei_doc.get("http") or nuclei_doc.get("requests") or []
    if not isinstance(http_blocks, list):
        http_blocks = [http_blocks]

    # Protocoles non-HTTP : on avertit, on ne peut pas convertir
    non_http_protos = [k for k in ("network", "dns", "ssl", "websocket",
                                   "headless", "file", "code", "javascript",
                                   "whois")
                       if k in nuclei_doc]
    if non_http_protos and not http_blocks:
        warnings.append(
            f"[{tid}] protocole(s) non-HTTP ({', '.join(non_http_protos)}) : "
            f"non convertible vers Mowing Devil HTTP.")
        return {}, warnings

    if len(http_blocks) > 1:
        warnings.append(
            f"[{tid}] {len(http_blocks)} blocs http[] : un test par bloc, "
            f"sans chaînage (captures non propagées).")

    base_id = slug(tid)
    sev = sev_map(info.get("severity"))
    tmpl_matchers = nuclei_doc.get("matchers") or []
    tmpl_extractors = nuclei_doc.get("extractors") or []

    for idx, block in enumerate(http_blocks):
        if not isinstance(block, dict):
            continue
        test_id = f"{base_id}-{idx+1}" if len(http_blocks) > 1 else base_id

        request = http_request_to_mowing(block, warnings, test_id)
        matchers = block.get("matchers") or tmpl_matchers
        cond = (block.get("matchers-condition")
                or nuclei_doc.get("matchers-condition") or "and")
        asserts = matchers_to_asserts(matchers, cond, warnings, test_id)

        if not asserts:
            warnings.append(
                f"[{test_id}] aucun matcher convertible : ajout d'une assertion "
                f"status 200 (à ajuster).")
            asserts = [{"status": [200]}]

        extractors = block.get("extractors") or tmpl_extractors
        capture = extractors_to_capture(extractors, warnings, test_id)

        test = {
            "id": test_id,
            "name": convert_vars(block.get("name") or f"{tid} — étape {idx+1}"),
            "severity": sev,
            "request": request,
            "assert": asserts,
        }
        if capture:
            test["capture"] = capture
        tests.append(test)

    if not tests:
        warnings.append(f"[{tid}] aucun bloc http[] exploitable.")

    suite: dict = {"name": suite_name}
    if info.get("description"):
        first_line = str(info["description"]).splitlines()[0][:80]
        suite["name"] += f" — {first_line}"

    meta_lines = []
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

    if strict and warnings:
        raise ValueError("Conversion non stricte :\n  - " + "\n  - ".join(warnings))

    return suite, warnings


# ═════════════════════════════════════════════════════════════════════════════
#  Émission YAML avec header commenté
# ═════════════════════════════════════════════════════════════════════════════

def emit_yaml(suite: dict, src: Path | None = None) -> str:
    suite = dict(suite)  # copie défensive
    meta = suite.pop("_nuclei_metadata", None)

    body = yaml.safe_dump(suite, sort_keys=False, allow_unicode=True,
                          default_flow_style=False, width=100)

    header = ["# Converti depuis un template Nuclei par nuclei2mowing.py",
              "# Format cible : Mowing Devil / HTTP Debugger v3",
              "# Vérifier manuellement les warnings émis sur stderr."]
    if src:
        header.append(f"# Source : {src.name}")
    if meta:
        header += ["#", "# Métadonnées Nuclei originales :"]
        header += [f"#   {line}" for line in meta]

    return "\n".join(header) + "\n\n" + body


# ═════════════════════════════════════════════════════════════════════════════
#  Traitement d'un fichier
# ═════════════════════════════════════════════════════════════════════════════

def process_file(src: Path, dst: Path | None, strict: bool,
                 skip_non_nuclei: bool = True,
                 force: bool = False) -> ConvResult:
    t0 = time.perf_counter()
    res = ConvResult(src=src, dst=dst)

    if dst and dst.exists() and not force:
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
        res.status = "warn"
        res.warnings.append("template non-Nuclei : conversion best-effort")

    try:
        suite, warnings = convert_template(raw, strict=strict)
    except ValueError as e:
        res.status = "err"
        res.error = f"strict: {e}"
        res.duration = time.perf_counter() - t0
        return res

    if not suite:
        res.status = "skip"
        res.warnings.extend(warnings)
        res.duration = time.perf_counter() - t0
        return res

    res.warnings = warnings
    text = emit_yaml(suite, src)

    if dst is None:
        # Single file → stdout
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
#  Découverte récursive des templates
# ═════════════════════════════════════════════════════════════════════════════

def discover_templates(root: Path) -> list[Path]:
    """Parcourt récursivement, retourne tous les .yaml/.yml, triés, sans doublons."""
    if root.is_file():
        return [root]
    files = set()
    for pat in ("*.yaml", "*.yml"):
        for p in root.rglob(pat):
            if p.is_file():
                files.add(p.resolve())
    return sorted(files)


# ═════════════════════════════════════════════════════════════════════════════
#  Orchestration batch / single
# ═════════════════════════════════════════════════════════════════════════════

def run_batch(sources: Iterable[Path], out_dir: Path | None, strict: bool,
              jobs: int, skip_non_nuclei: bool, force: bool,
              dry_run: bool) -> dict:
    # 1. Découverte
    files: list[Path] = []
    for s in sources:
        files.extend(discover_templates(s))
    files = sorted(set(files))

    if dry_run:
        print(f"{C.BOLD}{C.MAGENTA}── Dry-run : {len(files)} fichier(s) détecté(s) ──{C.RESET}")
        for f in files:
            print(f"  {C.GREY}→{C.RESET} {f}")
        return {"files": [str(f) for f in files], "dry_run": True}

    if not files:
        print(f"{C.YELLOW}⚠ Aucun fichier YAML trouvé.{C.RESET}")
        return {"total": 0, "results": []}

    # 2. Conversion avec barre de progression
    bar = ProgressBar(len(files), label="Conversion")
    results: list[ConvResult] = []
    report_lines: list[str] = []

    # Affichage d'en-tête
    print(f"{C.BOLD}{C.MAGENTA}╭─ Nuclei → Mowing Devil {C.RESET}"
          f"{C.GREY}({len(files)} fichier(s), jobs={jobs}){C.RESET}")
    print(f"{C.MAGENTA}╰─{C.RESET} cible : "
          f"{C.BOLD}{out_dir or '(stdout)'}{C.RESET}")

    def _emit_warnings(r: ConvResult):
        for w in r.warnings:
            report_lines.append(f"[WARN] {r.src}: {w}")

    if jobs <= 1 or len(files) == 1:
        for f in files:
            dst = (out_dir / f.name) if out_dir else None
            r = process_file(f, dst, strict, skip_non_nuclei, force)
            results.append(r)
            _emit_warnings(r)
            if r.status == "err":
                report_lines.append(f"[ERR ] {r.src}: {r.error}")
            bar.bump(r.status, f.name)
    else:
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futures = {}
            for f in files:
                dst = (out_dir / f.name) if out_dir else None
                futures[ex.submit(process_file, f, dst, strict,
                                  skip_non_nuclei, force)] = f
            for fut in as_completed(futures):
                f = futures[fut]
                try:
                    r = fut.result()
                except Exception as e:
                    r = ConvResult(src=f, dst=None, status="err",
                                   error=f"{type(e).__name__}: {e}")
                results.append(r)
                _emit_warnings(r)
                if r.status == "err":
                    report_lines.append(f"[ERR ] {r.src}: {r.error}")
                bar.bump(r.status, f.name)

    bar.finish()

    # 3. Résumé
    total = len(results)
    ok = sum(1 for r in results if r.status == "ok")
    warn = sum(1 for r in results if r.status == "warn")
    err = sum(1 for r in results if r.status == "err")
    skip = sum(1 for r in results if r.status == "skip")

    print()
    print(f"{C.BOLD}{C.MAGENTA}╭─ Résumé{C.RESET}")
    print(f"{C.MAGENTA}│{C.RESET}  {C.GREEN}✓ {ok:>4}{C.RESET} converti(s) sans warning")
    if warn:
        print(f"{C.MAGENTA}│{C.RESET}  {C.YELLOW}⚠ {warn:>4}{C.RESET} converti(s) avec warning(s)")
    if err:
        print(f"{C.MAGENTA}│{C.RESET}  {C.RED}✗ {err:>4}{C.RESET} erreur(s)")
    if skip:
        print(f"{C.MAGENTA}│{C.RESET}  {C.GREY}○ {skip:>4}{C.RESET} skippé(s)")
    print(f"{C.MAGENTA}│{C.RESET}  {C.BOLD}{total:>4}{C.RESET} au total")

    # Détail des erreurs
    if err:
        print(f"\n{C.BOLD}{C.RED}Erreurs :{C.RESET}")
        for r in results:
            if r.status == "err":
                print(f"  {C.RED}✗{C.RESET} {r.src}  {C.GREY}— {r.error}{C.RESET}")

    # Détail des warnings (compact)
    if warn:
        print(f"\n{C.BOLD}{C.YELLOW}Warnings (premiers 20) :{C.RESET}")
        shown = 0
        for r in results:
            if r.status == "warn":
                for w in r.warnings[:2]:
                    print(f"  {C.YELLOW}⚠{C.RESET} {C.GREY}{r.src.name}:{C.RESET} {w}")
                    shown += 1
                    if shown >= 20:
                        break
            if shown >= 20:
                break
        if shown < sum(len(r.warnings) for r in results):
            rest = sum(len(r.warnings) for r in results) - shown
            print(f"  {C.GREY}… et {rest} autre(s) warning(s) — "
                  f"utilisez --report pour tout voir.{C.RESET}")

    print(f"{C.MAGENTA}╰─{C.RESET}")

    return {
        "total": total, "ok": ok, "warn": warn, "err": err, "skip": skip,
        "results": [
            {"src": str(r.src), "dst": str(r.dst) if r.dst else None,
             "status": r.status, "duration_s": round(r.duration, 3),
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
        description="Convertisseur récursif Nuclei → Mowing Devil",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage :", 1)[1] if "Usage :" in __doc__ else "")
    ap.add_argument("inputs", nargs="+",
                    help="Fichier(s) ou dossier(s) d'entrée (récursif)")
    ap.add_argument("-o", "--output",
                    help="Fichier (single) ou dossier (multi) de sortie")
    ap.add_argument("--strict", action="store_true",
                    help="Échoue si la conversion n'est pas fidèle")
    ap.add_argument("--skip-non-nuclei", action="store_true", default=True,
                    help="Ignore les YAML qui ne sont pas des templates Nuclei (défaut)")
    ap.add_argument("--convert-non-nuclei", dest="skip_non_nuclei",
                    action="store_false",
                    help="Convertit en best-effort même les YAML non-Nuclei")
    ap.add_argument("--force", action="store_true",
                    help="Écrase les fichiers de sortie existants")
    ap.add_argument("--jobs", type=int, default=1,
                    help="Nombre de fichiers traités en parallèle (défaut: 1)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Liste les fichiers détectés sans convertir")
    ap.add_argument("--report",
                    help="Écrit un rapport JSON détaillé à ce chemin")
    args = ap.parse_args()

    # Résolution des entrées
    sources = [Path(s) for s in args.inputs]
    for s in sources:
        if not s.exists():
            print(f"{C.RED}✗{C.RESET} entrée introuvable : {s}", file=sys.stderr)
            return 2

    # Détermination du mode
    single = len(sources) == 1 and sources[0].is_file()
    if single and args.output:
        out = Path(args.output)
        if out.is_dir():
            print(f"{C.RED}✗{C.RESET} -o doit être un fichier en mode single",
                  file=sys.stderr)
            return 2
        res = process_file(sources[0], out, args.strict,
                           args.skip_non_nuclei, args.force)
        if res.status == "err":
            print(f"{C.RED}✗{C.RESET} {res.error}", file=sys.stderr)
            return 1
        if res.status == "skip":
            print(f"{C.GREY}○{C.RESET} {res.error}", file=sys.stderr)
            return 0
        for w in res.warnings:
            print(f"{C.YELLOW}⚠{C.RESET} {w}", file=sys.stderr)
        print(f"{C.GREEN}✓{C.RESET} {sources[0].name} → {out}", file=sys.stderr)
        if args.report:
            Path(args.report).write_text(json.dumps(
                {"src": str(sources[0]), "dst": str(out),
                 "status": res.status, "warnings": res.warnings},
                indent=2, ensure_ascii=False), encoding="utf-8")
        return 0

    # Mode batch
    out_dir = Path(args.output) if args.output else None
    if out_dir and out_dir.exists() and out_dir.is_file():
        print(f"{C.RED}✗{C.RESET} -o doit être un dossier en mode batch",
              file=sys.stderr)
        return 2

    summary = run_batch(sources, out_dir, args.strict, args.jobs,
                        args.skip_non_nuclei, args.force, args.dry_run)

    if args.report and not args.dry_run:
        Path(args.report).write_text(
            json.dumps(summary, indent=2, ensure_ascii=False),
            encoding="utf-8")
        print(f"{C.GREY}Rapport écrit : {args.report}{C.RESET}")

    return 0 if summary.get("err", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
