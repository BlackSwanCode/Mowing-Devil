# Mowing Devil — HTTP Debugger v3c

Client HTTP/WebSocket piloté par templates YAML, avec un moteur d'assertions
façon *Nuclei* et un mode « attaque » pour le RedTeaming HTTP non destructif.
Deux interfaces pour le même moteur : une **GUI PySide6** et un **CLI** pensé
pour l'intégration CI/CD (JUnit/HTML/JSON + code de sortie).

> ⚠️ **Cadre d'usage.** Cet outil est conçu pour tester des serveurs dont vous
> êtes responsable, ou des cibles pour lesquelles vous disposez d'une
> autorisation écrite explicite (pentest sous contrat, bug bounty avec scope
> défini, labs d'entraînement comme DVWA/NodeGoat déployés localement).
> Certains templates (`98_*`, `99_*`) vont au-delà de la simple détection et
> extraient activement des données ou exécutent des payloads d'exploitation
> multi-SGBD — à n'utiliser que sur un environnement isolé et autorisé.
> L'auteur du script rappelle lui-même ce cadre dans l'en-tête du fichier
> principal.

---

## Sommaire

1. [Vue d'ensemble](#vue-densemble)
2. [Installation](#installation)
3. [Démarrage rapide](#démarrage-rapide)
4. [Architecture du dépôt](#architecture-du-dépôt)
5. [Anatomie d'un template YAML](#anatomie-dun-template-yaml)
6. [Variables & interpolation `{{...}}`](#variables--interpolation-)
7. [Référence des assertions](#référence-des-assertions)
8. [`verdict_semantics` : hardening vs vulnerability](#verdict_semantics--hardening-vs-vulnerability)
9. [Mode attaque (`mode: attack`)](#mode-attaque-mode-attack)
10. [Chaînage de requêtes (`capture`)](#chaînage-de-requêtes-capture)
11. [WebSocket](#websocket)
12. [Catalogue des templates fournis](#catalogue-des-templates-fournis)
13. [Garde-fous de sécurité](#garde-fous-de-sécurité)
14. [Rapports & intégration CI/CD](#rapports--intégration-cicd)
15. [Outils annexes (`tools/`)](#outils-annexes-tools)
16. [Exemples pratiques — DVWA & NodeGoat](#exemples-pratiques--dvwa--nodegoat)
17. [Limitations connues](#limitations-connues)
18. [Licence](#licence)

---

## Vue d'ensemble

Le projet s'articule autour de trois briques :

| Composant | Rôle |
|---|---|
| `http_debugger3c.py` | Moteur HTTP/WebSocket + GUI PySide6 + CLI. Charge des suites YAML, exécute les requêtes, évalue des assertions, exporte des rapports. |
| `templates/*.yaml` | Suites de tests déclaratives : recon, durcissement, API, GraphQL, MCP, injections, uploads, packs de conformité OWASP. |
| `tools/` | `nuc2mow2c.py` (convertisseur Nuclei → Mowing Devil) et `mowing_forge2a.py` (éditeur/validateur de templates, GUI séparée). |

Le moteur supporte trois natures de test (`kind` / `type` selon le contexte) :

- **`http`** (défaut) — requête HTTP simple + assertions.
- **`attack`** (`mode: attack`) — injecte une liste de payloads dans un
  paramètre cible et évalue des assertions de succès (`success_if`).
- **`websocket`** (`type: websocket`) — handshake WS, envoi/réception de
  frames, assertions dédiées.

Transport : `httpx` si disponible, sinon repli automatique sur `requests`
(`HAVE_HTTPX` / `HAVE_REQUESTS` dans le script). WebSocket nécessite le
paquet `websockets`. `pyyaml` est **obligatoire** pour charger les templates.

---

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` :

```
PySide6>=6.6
requests>=2.31
PyYAML>=6.0
```

Dépendances **optionnelles** détectées au runtime (le script dégrade
proprement si absentes, cf. les blocs `try/except ImportError` en tête de
fichier) :

| Paquet | Apporte |
|---|---|
| `httpx` | Transport HTTP préféré (sinon `requests` + `urllib3`) |
| `websockets` | Tests `type: websocket` (sans lui : ces tests échouent avec une erreur de transport) |
| `charset_normalizer` | Détection d'encodage de corps de réponse plus fine (sinon repli sur le `charset=` de `Content-Type`, puis `utf-8`) |
| `jsonschema` | Nécessaire uniquement pour l'assertion `json_schema` |

La GUI nécessite un environnement avec affichage (X11/Wayland/Windows/macOS).
Le mode CLI (`--cli`) fonctionne en environnement headless, y compris dans un
conteneur CI, sans serveur d'affichage.

---

## Démarrage rapide

### GUI

```bash
python3 http_debugger3c.py templates/
```

### CLI

```bash
python3 http_debugger3c.py --cli templates/ \
  --base-url http://localhost:8080 \
  --concurrency 4 \
  --fail-on high \
  --junit rapport.xml \
  --html rapport.html \
  --json rapport.json
```

Référence complète des options CLI :

| Option | Défaut | Effet |
|---|---|---|
| `--cli DOSSIER` | — | Mode CLI, charge tous les `*.yaml`/`*.yml` du dossier (non récursif) |
| `--base-url URL` | — | Surcharge la variable `{{base_url}}` de **toutes** les suites chargées |
| `--concurrency N` | `1` | Exécution séquentielle si `1`, sinon pool de threads (`ThreadPoolExecutor`) |
| `--delay MS` | `0` | Pause entre deux tests **en mode séquentiel uniquement** (ignorée si `--concurrency > 1`) |
| `--block-private` | désactivé | Refuse d'émettre une requête dont l'URL résout vers un CIDR privé (cf. [Garde-fous](#garde-fous-de-sécurité)) |
| `--fail-on {never,any,high}` | `high` | Politique du code de sortie (voir plus bas) |
| `--junit FICHIER` | — | Export JUnit XML |
| `--html FICHIER` | — | Export HTML (même gabarit que la capture d'écran de rapport) |
| `--json FICHIER` | — | Export JSON structuré |

Codes de sortie CLI :

- `--fail-on never` → toujours `0`.
- `--fail-on any` → `1` si au moins un test est `FAIL` ou `ERREUR`.
- `--fail-on high` (défaut) → `1` seulement si le test de **plus haute
  sévérité** (`SEV_ORDER` : critical > high > medium > low > info) est en
  `FAIL`/`ERREUR` **et** que sa sévérité est `high` ou `critical`. Un `FAIL`
  isolé en `medium`/`low` ne fait donc **pas** échouer le job par défaut.

---

## Architecture du dépôt

```
Mowing-Devil-main/
├── http_debugger3c.py          # Moteur + GUI + CLI (point d'entrée unique)
├── requirements.txt
├── templates/                  # Suites YAML, numérotées par thème
│   ├── 01_http_basique.yaml … 24_universal_svg_upload.yaml
│   ├── 25_owasp_top10_2021.yaml
│   ├── 26_owasp_api_top10_2023.yaml
│   ├── 27_owasp_cicd_top10.yaml
│   ├── 28_owasp_llm_top10.yaml
│   ├── 98_upload_bypass_mega.yaml
│   ├── 98b_upload_bypass_advanced.yaml
│   └── 99_sqli_oneshot_v2.yaml
└── tools/
    ├── nuc2mow2c.py             # Convertisseur Nuclei → Mowing Devil
    └── mowing_forge2a.py        # Éditeur/validateur de templates (GUI à part)
```

---

## Anatomie d'un template YAML

Structure complète d'une suite (tous les champs, avec leur portée) :

```yaml
name: "Nom affiché de la suite"

scope:                        # optionnel — métadonnée lue par la GUI
  active_testing: true        # déverrouille les tests mode:attack dans la GUI
  requests_per_second: 2      # documentaire uniquement (non enforced par le moteur)

variables:                    # fusionnées avec --base-url (CLI écrase base_url)
  base_url: "http://localhost:8080"
  foo: "bar"

env_files:                    # optionnel — fichiers .env fusionnés dans variables
  - ".env.local"

defaults:                     # appliqués à chaque test, surchargés par request:
  read_timeout: 10
  connect_timeout: 10
  verify: false
  follow_redirects: false
  max_redirects: 10
  http2: false
  retries: 0
  headers: {}
  params: {}
  cookies: {}
  proxy: ""
  auth: {user: "", password: ""}
  cert: ["client.crt", "client.key"]

matrix:                       # optionnel — duplique CHAQUE test pour chaque ligne
  - {env: "staging"}
  - {env: "prod"}

tests:
  - id: "identifiant-unique"          # requis
    name: "Libellé lisible"           # requis
    severity: high                    # critical|high|medium|low|info (défaut: info)
    mode: attack                      # omis = http ; "attack" = mode injection
    type: websocket                   # présent = test WebSocket (prioritaire sur mode)
    verdict_semantics: hardening      # "hardening" (défaut) | "vulnerability"
    skip_if: "{{some_var}}"           # test sauté si résolu à true/1/yes
    retries: 2                        # retries réseau pour CE test (surcharge defaults)
    depends_on: "autre-id"            # ⚠ champ accepté par le schéma mais NON
                                       #   interprété par le moteur actuel (voir Limitations)

    request:
      method: GET                     # GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS/TRACE/
                                       # PROPFIND/PROPPATCH/MKCOL/COPY/MOVE/LOCK/UNLOCK/PURGE
      path: "/api/users/{{own_id}}"   # concaténé à base_url (ou `url:` pour une URL absolue)
      headers: {Authorization: "Bearer {{token}}"}
      params: {q: "test"}             # query string
      cookies: {session: "{{sid}}"}
      json: {username: "x"}           # Content-Type: application/json auto + sérialisation
      form: {username: "x"}           # Content-Type: application/x-www-form-urlencoded auto
      body: "raw string"              # corps brut (prioritaire si "json"/"form" absents)
      body_file: "payload.bin"        # lit le corps depuis un fichier local
      verify: false                   # TLS : bool ou chemin de CA bundle
      follow_redirects: false
      max_redirects: 10
      http2: false
      auth: {user: "a", password: "b"}
      cert: ["client.crt", "client.key"]
      proxy: "http://127.0.0.1:8080"  # ex. router vers Burp/ZAP
      connect_timeout: 10
      read_timeout: 10
      retries: 0

    capture:                          # extraction de valeurs réutilisables ensuite
      token:
        json_path: "$.access_token"   # ou header: "Set-Cookie", regex: "(...)", cookie: "sid"

    assert:
      - status: 200
      - json_path: {path: "$.username", equals: "{{username}}"}

    attack:                           # uniquement si mode: attack (voir section dédiée)
      category: sqli_time_mysql
      target: body
      param: username
      payloads: ["payload custom {{canary}}"]   # optionnel, remplace le catalogue intégré
      success_if:
        - time_gt: 2.5
```

Notes d'implémentation importantes :

- **Fusion `defaults` → `request`** : `headers`/`params`/`cookies` sont
  **fusionnés** (le test surcharge la suite champ par champ) ; tous les
  autres réglages (`verify`, `timeout`, `retries`, …) sont du **tout ou
  rien** : la clé du test gagne si présente, sinon celle de `defaults`.
- **`json` vs `form` vs `body` vs `body_file`** : ordre de priorité exact
  dans `build_spec()` — `json` d'abord, puis `form`, puis `body_file`, puis
  `body`. Un seul est pris en compte si plusieurs sont présents.
- **`matrix`** duplique l'intégralité de la liste `tests` pour chaque ligne
  (le dict de la ligne est injecté dans les variables résolues via la clé
  interne `_matrix`), utile pour rejouer la même suite contre plusieurs
  environnements/comptes.

---

## Variables & interpolation `{{...}}`

Toute chaîne de `request`, `assert`, `attack`, `capture` passe par
`subst()`, qui résout récursivement `{{expr}}` via `_resolve()`. Table
exhaustive des expressions reconnues :

| Expression | Résultat |
|---|---|
| `{{nom_variable}}` | Valeur de `variables.nom_variable` (ou `""` si absente — **résolution silencieuse**, pas d'erreur) |
| `{{uuid}}` | `uuid.uuid4()` généré à chaque résolution |
| `{{timestamp}}` | `int(time.time() * 1000)` (millisecondes, chaîne) |
| `{{repeat:X:N}}` | Caractère `X` répété `N` fois (ex. `{{repeat:A:200000}}` pour un payload volumineux) |
| `{{env:NOM}}` | Variable d'environnement du process (`os.environ.get`, `""` si absente) |
| `{{b64:nom_var}}` | Base64 de la valeur de `variables.nom_var` |
| `{{sha1:nom_var}}` | SHA-1 hexdigest de la valeur de `variables.nom_var` |
| `{{sha256:nom_var}}` | SHA-256 hexdigest de la valeur de `variables.nom_var` |

⚠️ **Piège observé dans plusieurs templates du dépôt** (`21_php_upload_bypass.yaml`
notamment) : `{{rand_int}}` est utilisé mais **n'est pas** une expression
reconnue par `_resolve()`. Comme la résolution est silencieuse, l'expression
se résout en chaîne vide plutôt que de lever une erreur — le payload généré
n'est donc pas celui attendu. Voir [Limitations connues](#limitations-connues).

Les valeurs capturées par `capture:` (section suivante) sont injectées dans
le même espace de noms et deviennent utilisables dans les tests
**suivants** de la suite via `{{nom_capturé}}`.

---

## Référence des assertions

Chaque entrée de `assert:` est un dict à **une seule clé** (le nom de
l'assertion). Table complète extraite du registre `ASSERTIONS` du moteur :

### HTTP générique

| Assertion | Argument | Vérifie |
|---|---|---|
| `status` | `int` \| `str` \| liste | Code(s) attendu(s). Supporte `"2XX"`, `"400-499"`, `200` |
| `status_not` | idem | Négation de `status` |
| `header_present` | nom d'en-tête | L'en-tête existe (insensible à la casse) |
| `header_absent` | nom d'en-tête | L'en-tête est absent |
| `header_equals` | `{name, value}` | Égalité stricte (après `strip().lower()`) |
| `header_matches` | `{name, regex}` | Le header matche la regex (`re.I`) |
| `header_not_matches` | `{name, regex}` | Négation |
| `header_count` | `{name, equals}` | Nombre d'occurrences de l'en-tête (headers multi-valués) |
| `body_contains` | texte | Sous-chaîne présente (littéral, pas une regex) |
| `body_not_contains` | texte | Négation |
| `body_regex` | regex | `re.search(..., re.S)` sur le corps |
| `body_not_regex` | regex | Négation |
| `body_empty` | `bool` | Corps vide == valeur attendue |
| `body_hash` | `{algo, equals}` | Hash (`hashlib.new(algo)`) du corps brut |
| `time_lt` / `time_gt` | secondes | Temps total de la requête (`elapsed`) |
| `ttfb_lt` | secondes | Time-to-first-byte |
| `json_path` | `{path, equals\|type\|exists}` | Évaluation JSONPath simplifié (voir ci-dessous) |
| `json_schema` | schéma JSON Schema | Nécessite `jsonschema` (sinon échec explicite) |
| `cookie_flags` | `{name, require: [...]}` | Flags (`Secure`/`HttpOnly`/`SameSite`/...) présents sur le(s) cookie(s) ciblé(s) (`name: "*"` = tous) |
| `cookie_secure_only` | `bool` | Tous les `Set-Cookie` ont le flag `Secure` |
| `redirect_count` | `int` | Nombre de sauts dans `resp.history` |

### Nouveau en v3c — bloc d'en-têtes brut (sémantique Nuclei `part: header`)

| Assertion | Argument | Vérifie |
|---|---|---|
| `raw_headers_regex` | regex | Matche sur le bloc sérialisé `"Name: value\nName: value\n..."` (toutes les lignes concaténées), pas un header isolé |
| `raw_headers_not_regex` | regex | Négation |
| `raw_headers_contains` | texte | Sous-chaîne littérale dans le même bloc |
| `raw_headers_not_contains` | texte | Négation |

Utile pour porter fidèlement des matchers Nuclei `part: header` qui opèrent
sur le bloc d'en-têtes complet plutôt que sur une valeur nommée — c'est
précisément ce que fait `tools/nuc2mow2c.py` lors de la conversion (voir plus
bas).

### Attaque

| Assertion | Argument | Vérifie |
|---|---|---|
| `body_contains_canary` | canary | Le canary (généralement `{{canary}}`) est réfléchi tel quel dans le corps |
| `location_host_differs` | `bool` | L'en-tête `Location` pointe vers un host différent de celui de la requête (open redirect) |
| `header_injected` | nom d'en-tête | L'en-tête nommé apparaît dans la réponse (preuve de CRLF injection) |

Spécifique à `sqli_error` (câblé en dur dans `run_attack`, pas une assertion
déclarative) : à chaque payload envoyé avec `category: sqli_error`, le moteur
grep le corps de réponse contre `DB_ERROR_PATTERNS` (MySQL/PostgreSQL/MSSQL/
SQLite) et ajoute un `Check` en échec si un message d'erreur SQL apparaît,
**en plus** des `success_if` déclarés.

### WebSocket

| Assertion | Argument | Vérifie |
|---|---|---|
| `ws_connected` | `bool` | Handshake WS réussi == attendu |
| `ws_origin_accepted` | `bool` | Un `Origin` a été envoyé et le serveur a accepté/refusé la connexion en conséquence |
| `ws_frame_count_lt` | `int` | Nombre de frames reçues < N |
| `ws_close_code` | `int` | Code de fermeture WS reçu |
| `ws_message_regex` | regex | Au moins un message texte reçu matche |
| `ws_echo_ok` | — | Le dernier message envoyé est renvoyé à l'identique |
| `ws_latency_lt` | secondes | Latence max observée sur les frames reçues < N |
| `ws_subprotocol` | nom | Sous-protocole négocié == attendu |

### `json_path` en détail

Implémentation maison (`jpath()`), **pas** une lib JSONPath complète :
supporte `$.a.b`, `$.a[0]`, `$.a['clé avec espace']`, mais pas les
wildcards (`$.a[*]`), filtres (`$.a[?(@.x==1)]`) ni les requêtes récursives
(`$..a`). Trois modes :

```yaml
- json_path: {path: "$.id", equals: 42}
- json_path: {path: "$.items", type: list}   # str|int|float|bool|list|dict|null
- json_path: {path: "$.optional_field", exists: false}
```

---

## `verdict_semantics` : hardening vs vulnerability

Nouveauté v3c, portée champ par champ sur `Job` (et donc par test, pas
globale à la suite). Par défaut les templates du dépôt sont écrits en
sémantique **`hardening`** (implicite) :

- **`hardening`** (défaut) — toutes les assertions vraies ⇒ **PASS** (le
  serveur est correctement durci). C'est la lecture classique : « je
  m'attends à ce que le serveur refuse/masque X, si c'est le cas tout va
  bien ».
- **`vulnerability`** — toutes les assertions vraies ⇒ **FAIL**, affiché
  avec la couleur de sévérité du test. C'est l'inverse : les assertions
  décrivent les *preuves* qu'une vulnérabilité existe, et leur succès
  signale un problème plutôt qu'un succès.

```yaml
- id: sqli-error-based-probe
  name: "Preuve d'injection SQL par message d'erreur"
  severity: critical
  verdict_semantics: vulnerability     # succès des assertions = FAIL affiché
  request:
    method: GET
    path: "/search"
    params: {q: "'"}
  assert:
    - body_regex: "(?i)(SQL syntax|mysql_fetch|ORA-\\d{5})"
```

Sans `verdict_semantics: vulnerability`, l'exemple ci-dessus **passerait**
quand le serveur est vulnérable (la regex d'erreur SQL matche → assertion
vraie → PASS en sémantique par défaut), ce qui est contre-intuitif pour un
template de détection. C'est exactement le problème que `verdict_semantics`
corrige, et c'est le champ que `tools/nuc2mow2c.py` positionne
automatiquement à `vulnerability` pour les templates Nuclei taggés comme
intrusifs (voir plus bas).

---

## Mode attaque (`mode: attack`)

```yaml
- id: xss-q
  mode: attack
  severity: high
  request:
    method: GET
    path: "/search"
    params: {q: "test"}        # valeur de base, écrasée par chaque payload
  attack:
    category: xss
    target: query               # query | body | header
    param: q                    # nom du paramètre/header injecté
    success_if:
      - body_contains_canary: "{{canary}}"
```

Fonctionnement (`run_attack()`) :

1. Le catalogue intégré `ATTACK_PAYLOADS[category]` fournit la liste de
   payloads (ou `attack.payloads` si fourni, qui le remplace entièrement).
2. Pour **chaque** payload, le moteur clone la requête de base et injecte le
   payload dans `target`/`param`, envoie la requête, évalue `success_if`
   contre la réponse, et **accumule** tous les `Check` (un test `attack`
   peut donc produire plusieurs lignes de résultat pour un seul `id`).
3. `target: body` tente d'abord un parse JSON (remplace la clé si présente),
   puis un fallback `application/x-www-form-urlencoded`. Si aucun des deux
   ne matche, le corps original est renvoyé inchangé (injection silencieuse
   échouée — à surveiller si vos requêtes utilisent un `body` brut non
   JSON/non form-urlencoded).

Catalogue intégré (`ATTACK_PAYLOADS`) :

| `category` | Payloads | Technique |
|---|---|---|
| `xss` | `{{canary}}<img src=x onerror=alert(1)>`, `"><svg onload=alert(1)>`, `javascript:alert('{{canary}}')` | XSS réfléchi, à coupler avec `body_contains_canary` |
| `sqli_time_mysql` | `' OR SLEEP({{delay}})-- -`, `' AND SLEEP({{delay}})#` | SQLi time-based MySQL, à coupler avec `time_gt` |
| `sqli_time_pg` | `'; SELECT pg_sleep({{delay}})--`, … | SQLi time-based PostgreSQL |
| `sqli_error` | `' AND 1=CONVERT(int,@@version)--`, `' AND extractvalue(1,concat(0x7e,version()))--` | SQLi error-based (+ détection auto `DB_ERROR_PATTERNS`, voir section assertions) |
| `cmdi` | `; sleep {{delay}}`, `\| sleep {{delay}}`, `` `sleep {{delay}}` `` | Injection de commande time-based |
| `traversal` | `../../../../{{canary}}.txt`, `....//....//....//{{canary}}.txt` | Path traversal |
| `open_redirect` | `//evil.com`, `https://evil.com`, `/\evil.com` | Open redirect, à coupler avec `location_host_differs` |
| `crlf` | `%0d%0aX-Injected:{{canary}}` | CRLF injection, à coupler avec `header_injected` |

Les variables `{{canary}}` et `{{delay}}` sont résolues depuis
`variables.canary`/`variables.delay` (défauts internes : `"canary-xyz"` et
`"3"` si non définies dans la suite).

---

## Chaînage de requêtes (`capture`)

```yaml
- id: login
  request: {method: POST, path: "/api/login", json: {username: "{{username}}", password: "{{password}}"}}
  capture:
    token: {json_path: "$.access_token"}
    session_id: {cookie: "SESSIONID"}
    csrf: {regex: "name=\"csrf_token\" value=\"([^\"]+)\""}
    rate_limit_policy: {header: "X-RateLimit-Policy"}

- id: protected-with-token
  request:
    method: GET
    path: "/api/me"
    headers: {Authorization: "Bearer {{token}}"}
```

Quatre sources de capture : `json_path`, `header`, `regex` (groupe 1 si
présent, sinon tout le match), `cookie` (valeur brute du `Set-Cookie`
correspondant). Les valeurs capturées vivent dans `self.runtime_vars` de
l'`Engine` : elles persistent **pour tout le run**, y compris entre suites
différentes chargées dans le même dossier — attention aux collisions de nom
entre templates si vous combinez des suites qui capturent toutes une
variable `token`, par exemple.

---

## WebSocket

```yaml
- id: ws-echo
  type: websocket
  severity: medium
  request:
    ws:
      url: "wss://{{host}}/socket"
      origin: "https://{{host}}"
      headers: {Authorization: "Bearer {{token}}"}
      steps:
        - send: {opcode: text, payload: "ping"}
        - expect_timeout: 3
  assert:
    - ws_connected: true
    - ws_echo_ok: {}
```

Cf. `02_websocket.yaml` et `07_websocket_advanced.yaml` pour des exemples
complets (négociation de sous-protocole, séquences send/recv multiples,
mesure de latence). Nécessite le paquet `websockets` ; sans lui, `HAVE_WS`
est `False` et ces tests échouent en erreur de transport explicite plutôt
que silencieusement.

---

## Catalogue des templates fournis

| # | Fichier | Sujet |
|---|---|---|
| 01 | `01_http_basique.yaml` | Gabarit minimal HTTP |
| 02 | `02_websocket.yaml` | Gabarit minimal WebSocket |
| 03 | `03_attaque.yaml` | Mode attaque — XSS réfléchi, SQLi time-based |
| 04 | `04_recon_headers.yaml` | En-têtes de sécurité, HSTS, bannières, méthodes HTTP |
| 05 | `05_exposure_files.yaml` | Fichiers/endpoints sensibles exposés (`.env`, `.git`, Actuator, Swagger, listing de répertoire) |
| 06 | `06_cookies_sessions.yaml` | Flags cookies, JWT en cookie, open redirect, CRLF |
| 07 | `07_websocket_advanced.yaml` | WebSocket avancé |
| 08 | `08_api_json.yaml` | Robustesse JSON, mass assignment, fuite de version |
| 09 | `09_chained_auth.yaml` | Chaînage login → token → endpoint protégé |
| 10 | `10_api_bola.yaml` | BOLA (OWASP API1) |
| 11 | `11_api_graphql.yaml` | GraphQL : introspection, depth bomb, alias amplification |
| 12 | `12_api_authz_flows.yaml` | Autorisation fonctionnelle, flux métier |
| 13 | `13_mcp_http_exposure.yaml` | MCP : exposition/énumération non authentifiée |
| 14 | `14_mcp_tool_poisoning.yaml` | MCP : descriptions d'outils suspectes, homoglyphes |
| 15 | `15_mcp_injection_probes.yaml` | MCP : path traversal, command injection, SSRF via outils |
| 16 | `16_mcp_auth_audit.yaml` | MCP : audit d'authentification |
| 17 | `17_nosql_auth_bypass.yaml` | Contournement d'auth NoSQL (`$regex`, `$gt`, `$ne`) |
| 18 | `18_jwt_manipulation.yaml` | JWT `alg: none`, confusion RSA→HMAC |
| 19 | `19_ssti_polyglot.yaml` | SSTI polyglotte multi-moteurs |
| 20 | `20_prototype_pollution.yaml` | Prototype pollution Node.js (`__proto__`, `constructor`) |
| 21 | `21_php_upload_bypass.yaml` | Contournements upload PHP (extensions, `.htaccess`, polyglottes) ⚠ voir limitations |
| 22 | `22_nodejs_upload_exploits.yaml` | Exploits upload Node.js ⚠ voir limitations |
| 23 | `23_tomcat_war_deploy.yaml` | Déploiement WAR Tomcat ⚠ voir limitations |
| 24 | `24_universal_svg_upload.yaml` | Upload SVG (XXE/XSS via SVG) ⚠ voir limitations |
| 25 | `25_owasp_top10_2021.yaml` | Pack de conformité **OWASP Top 10 2021** (A01→A10) |
| 26 | `26_owasp_api_top10_2023.yaml` | Pack de conformité **OWASP API Security Top 10 2023** (API1→API10) |
| 27 | `27_owasp_cicd_top10.yaml` | Surface HTTP des **OWASP Top 10 CI/CD Security Risks** |
| 28 | `28_owasp_llm_top10.yaml` | Sondes **OWASP Top 10 for LLM Applications** |
| 98 | `98_upload_bypass_mega.yaml` | Détection exhaustive bypass upload PHP/Node.js ⚠ voir limitations |
| 98b | `98b_upload_bypass_advanced.yaml` | Variante avancée du précédent ⚠ voir limitations |
| 99 | `99_sqli_oneshot_v2.yaml` | **Extraction active** SQLi multi-SGBD (UNION/error/time/OOB, bypass WAF) — usage sensible, cf. bandeau en tête de fichier |

---

## Garde-fous de sécurité

- **Bannière d'usage** dans l'en-tête du script principal et de plusieurs
  templates (`99_*`, `98_*`) : rappel explicite de ne cibler que des
  serveurs autorisés.
- **`--block-private`** (CLI) / case à cocher équivalente (GUI) : si
  activé, toute URL dont l'host résout vers un CIDR privé/loopback/link-local
  (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`,
  `169.254.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10`, cf. `PRIVATE_NETS`)
  est refusée **avant** l'émission (`_is_private_url`).
- **Confirmation GUI pour `mode: attack`** : `_confirm_attack()` exige que
  `scope.active_testing: true` soit déclaré (au niveau suite ou test) pour
  déverrouiller l'exécution d'un test en mode attaque, puis affiche une
  boîte de dialogue de confirmation listant les catégories de payloads qui
  vont être envoyées.
  > ⚠️ **Ce garde-fou est GUI-only.** `cli_main()` ne vérifie **pas**
  > `scope.active_testing` avant d'exécuter des tests `mode: attack` — en
  > CLI, tout template chargé dans le dossier passé à `--cli` s'exécute
  > intégralement, attaques comprises. À garder en tête pour vos pipelines
  > CI/CD : ne pointez `--cli` que vers des dossiers de templates que vous
  > avez vous-même validés pour la cible.
- **Payloads non destructifs par construction** sur les templates 01-28 :
  canary-based (preuve de réflexion), time-based (preuve de délai), ou
  error-based (preuve de message d'erreur) — aucune suppression/modification
  de données. Les templates `98_*`/`99_*` sortent de ce cadre (upload actif
  de shells de preuve de concept, extraction de données réelles).

---

## Rapports & intégration CI/CD

Trois exporteurs (`results_to_junit`, `results_to_html`, `results_to_json`),
tous déclenchables simultanément en CLI. Extrait du schéma JSON :

```json
[
  {
    "test": "A06 — Version précise d'un composant serveur divulguée",
    "id": "a06-component-version-disclosure",
    "suite": "OWASP Top 10 2021 — Couverture par catégorie",
    "kind": "http",
    "severity": "low",
    "verdict_semantics": "hardening",
    "verdict": "FAIL",
    "status": 200,
    "elapsed_s": 2.413,
    "error": "",
    "url": "https://cible.example/",
    "checks": [
      {"ok": false, "label": "Server ≁ /\\d+\\.\\d+(\\.\\d+)?/", "detail": "reçu : Apache-Coyote/1.1"}
    ]
  }
]
```

Exemple GitHub Actions :

```yaml
name: http-debugger-scan
on: [workflow_dispatch]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.11"}
      - run: pip install -r requirements.txt
      - run: >
          python3 http_debugger3c.py --cli templates/
          --base-url ${{ secrets.STAGING_BASE_URL }}
          --block-private
          --fail-on high
          --junit rapport.xml --html rapport.html
      - uses: actions/upload-artifact@v4
        if: always()
        with: {name: http-debugger-report, path: "rapport.*"}
```

Astuce : combinez `27_owasp_cicd_top10.yaml` à votre propre pipeline pour
auditer la posture de sécurité de l'orchestrateur CI/CD qui exécute ce job.

---

## Outils annexes (`tools/`)

### `nuc2mow2c.py` — Convertisseur Nuclei → Mowing Devil (v4)

Convertit des templates [Nuclei](https://github.com/projectdiscovery/nuclei-templates)
(YAML) vers le format de ce dépôt.

```bash
python3 tools/nuc2mow2c.py nuclei-templates/http/   -o templates-converties/ --jobs 4
python3 tools/nuc2mow2c.py nuclei-templates/http/   --dry-run        # liste sans convertir
python3 tools/nuc2mow2c.py nuclei-templates/        --check-only     # classe sans écrire
python3 tools/nuc2mow2c.py templates-converties/    --lint           # audite des suites déjà converties
python3 tools/nuc2mow2c.py un_template.yaml -o sortie.yaml --strict
python3 tools/nuc2mow2c.py nuclei-templates/ -o out/ --todo TODO.md --report rapport.json
```

| Option | Effet |
|---|---|
| `-o / --output` | Fichier (conversion unique) ou dossier (batch) de sortie |
| `--strict` | Échec explicite si la conversion n'est pas jugée fidèle (DSL non résolu, variable non définie, etc.) |
| `--skip-non-nuclei` (défaut) / `--convert-non-nuclei` | Ignore ou force la conversion des YAML qui ne ressemblent pas à un template Nuclei |
| `--force` | Écrase les fichiers de sortie existants |
| `--jobs N` | Parallélisation du traitement par lot |
| `--dry-run` | Liste les fichiers détectés, sans écrire |
| `--check-only` | Classe les templates (convertible / partiel / ignoré) sans écrire |
| `--lint` | Analyse un dossier de templates **déjà** au format Mowing Devil |
| `--todo FICHIER` | Génère un `TODO.md` des conversions partielles à corriger à la main |
| `--report FICHIER` | Rapport JSON détaillé du batch |

Points de correspondance notables (Nuclei → Mowing Devil) :

- Matchers `part: header` (`word`/`regex`) → assertions `raw_headers_contains`
  / `raw_headers_regex` (ajoutées justement dans `http_debugger3c.py` pour
  rendre cette conversion fidèle — avant v3c, ce mapping n'existait pas).
- `header_equals` n'est **jamais généré** par le convertisseur : le
  commentaire du script note explicitement que cette assertion ne matche
  jamais de façon fiable dans Mowing Devil pour ce cas d'usage.
- Helpers DSL Nuclei (`to_lower`, `to_upper`, `base64`, `url_encode`,
  `unix_time`, `hex_to_dec`, `trim`, `rand_text_*`, `rand_int(...)`) sont
  résolus en littéraux à la conversion ; les helpers non reconnus sont
  remplacés par un placeholder `<NUCLEI_DSL:...>` accompagné d'un
  avertissement, pour correction manuelle.
- Variables référencées mais non définies dans le template source →
  placeholder `CHANGEME_xxx` + avertissement (plutôt qu'une conversion
  silencieusement incorrecte).
- Les templates Nuclei taggés intrusifs (`VULN_TAGS`, incluant notamment
  `token-spray`, `creds-stuffing`, `login-check`, `intrusive`) se voient
  attribuer `verdict_semantics: vulnerability` automatiquement.

### `mowing_forge2a.py` — Éditeur/validateur de templates

GUI PySide6 indépendante (thème « RetroFuture »), pour créer/éditer des
templates sans repasser par un éditeur de texte brut :

```bash
python3 tools/mowing_forge2a.py
```

Fonctions principales (boutons de la barre d'outils) :

- **Charger / Sauvegarder** un template YAML.
- **Valider Schéma** — vérification structurelle minimale (présence de
  `name`, `tests`, et par test de `id`/`request`/`assert`) ; ce n'est **pas**
  une validation complète contre tous les champs documentés ci-dessus
  (`defaults`, `capture`, `attack`, etc. ne sont pas vérifiés).
- **Générer Sonde OWASP LLM** — insère automatiquement dans le template en
  cours un test de prompt injection prêt à l'emploi (`{{chat_path}}` +
  `{{canary}}`), sur le même principe que les tests `llm01-*` de
  `28_owasp_llm_top10.yaml`.
- **Injection Chaos Mémétique** — fonctionnalité expérimentale/« easter
  egg » qui ajoute des variables et commentaires arbitraires (thème
  « Caen-Profonde » / MTT-2075) à la suite ainsi qu'une assertion
  `header_present: X-Memetic-Shield` sur un test choisi au hasard ; purement
  cosmétique, sans effet sur le moteur de test — à ignorer ou retirer selon
  vos conventions d'équipe.

---

## Exemples pratiques — DVWA & NodeGoat

Ces deux cibles sont les projets d'entraînement officiels respectivement de
l'écosystème PHP ([DVWA](https://github.com/digininja/DVWA)) et de l'OWASP
pour Node.js ([OWASP NodeGoat](https://github.com/OWASP/NodeGoat)). À
déployer **localement**, jamais testées en ligne sans autorisation.

### DVWA

```bash
docker run --rm -it -p 4280:80 vulnerables/web-dvwa
```

Après connexion initiale (`admin` / `password`) et réglage du niveau de
sécurité sur *low* (`DVWA Security` → `Low` → `Submit`), le cookie de
session (`PHPSESSID`) et le cookie anti-CSRF (`security=low`) doivent être
transmis à chaque requête :

```yaml
name: "DVWA — Low security, sondes ciblées"
variables:
  base_url: "http://localhost:4280"
  canary: "{{uuid}}"
defaults:
  verify: false
  cookies:
    PHPSESSID: "VOTRE_SESSION_APRES_LOGIN"
    security: "low"

tests:
  - id: dvwa-sqli-get
    name: "DVWA — SQLi GET (vulnerabilities/sqli)"
    mode: attack
    severity: critical
    request:
      method: GET
      path: "/vulnerabilities/sqli/"
      params: {id: "1", Submit: "Submit"}
    attack:
      category: sqli_error
      target: query
      param: id
      success_if:
        - body_regex: "(?i)(First name|Surname)"   # preuve indirecte : plus de résultats que prévu

  - id: dvwa-xss-reflected
    name: "DVWA — XSS réfléchi (vulnerabilities/xss_r)"
    mode: attack
    severity: high
    request:
      method: GET
      path: "/vulnerabilities/xss_r/"
      params: {name: "test"}
    attack:
      category: xss
      target: query
      param: name
      success_if:
        - body_contains_canary: "{{canary}}"

  - id: dvwa-cmdi
    name: "DVWA — Injection de commande (vulnerabilities/exec)"
    mode: attack
    severity: critical
    request:
      method: POST
      path: "/vulnerabilities/exec/"
      form: {ip: "127.0.0.1", Submit: "Submit"}
    attack:
      category: cmdi
      target: body
      param: ip
      success_if:
        - time_gt: 2.5

  - id: dvwa-brute-no-lockout
    name: "DVWA — Pas de verrouillage après échecs répétés (vulnerabilities/brute)"
    severity: medium
    request:
      method: GET
      path: "/vulnerabilities/brute/"
      params: {username: "admin", password: "wrong-{{canary}}", Login: "Login"}
    assert:
      - status: 200
      - body_not_regex: "(?i)(account locked|too many attempts)"
```

```bash
python3 http_debugger3c.py --cli templates-dvwa/ --base-url http://localhost:4280 --fail-on any
```

> Les endpoints `vulnerabilities/upload/` de DVWA correspondent au cas
> `multipart/form-data` **actuellement non supporté** par le moteur (voir
> [Limitations connues](#limitations-connues)) — n'attendez pas de résultat
> exploitable avec `21_php_upload_bypass.yaml` tel quel contre DVWA sans
> correctif préalable.

### NodeGoat

```bash
git clone https://github.com/OWASP/NodeGoat.git && cd NodeGoat
docker-compose up        # expose l'app sur http://localhost:4000 par défaut
```

NodeGoat illustre volontairement une injection NoSQL MongoDB sur le
formulaire de connexion (`/login`), exploitable avec le même principe que
`17_nosql_auth_bypass.yaml` :

```yaml
name: "NodeGoat — Contournement d'authentification NoSQL"
variables:
  base_url: "http://localhost:4000"
defaults:
  verify: false
  follow_redirects: false

tests:
  - id: nodegoat-nosql-ne-bypass
    name: "NodeGoat — Bypass login via opérateur $ne"
    severity: critical
    request:
      method: POST
      path: "/login"
      form:
        userName: "admin"
        password[$ne]: "1"
    assert:
      - status: [302, 200]
      - header_matches: {name: "Location", regex: "(?i)(dashboard|allocations)"}

  - id: nodegoat-profile-mass-assignment
    name: "NodeGoat — Mass assignment sur le profil utilisateur"
    severity: high
    request:
      method: POST
      path: "/profile"
      json: {firstName: "pentest", lastName: "user", isAdmin: true}
      headers: {Authorization: "Bearer {{token}}"}
    assert:
      - status_not: 200
```

```bash
python3 http_debugger3c.py --cli templates-nodegoat/ --base-url http://localhost:4000 --fail-on any
```

> Le payload `password[$ne]: "1"` doit être adapté à la sérialisation
> `application/x-www-form-urlencoded` effectivement attendue par Express
> (`body-parser`/`qs`) côté NodeGoat — vérifiez le rendu exact du corps
> envoyé (`--proxy` vers Burp/ZAP pour inspection, cf. `request.proxy` dans
> le schéma) avant de conclure à un faux négatif.

---

## Limitations connues

Constats faits en inspectant `http_debugger3c.py` et les templates fournis,
listés pour éviter les faux positifs/négatifs silencieux :

1. **`multipart`/`form_data` non implémentés dans le moteur.**
   `build_spec()` ne gère que `json`, `form` (urlencodé), `body_file` et
   `body` brut — il n'existe **aucune** branche traitant une clé
   `multipart:` (liste utilisée par `21`, `22`, `23`, `24`) ni `form_data:`
   (dict utilisé par `98`, `98b`). Conséquence : ces six templates
   construisent actuellement une requête **sans corps** (`body = b""`),
   et toute assertion qui suppose un upload réellement envoyé donnera un
   résultat non représentatif. À corriger en ajoutant une branche
   `multipart`/`form_data` dans `build_spec()` (construction manuelle d'un
   corps `multipart/form-data` avec boundary) avant d'utiliser ces
   templates en conditions réelles.
2. **`{{rand_int}}` n'est pas une expression résolue.** Seules `repeat:`,
   `env:`, `b64:`, `sha1:`, `sha256:`, `uuid`, `timestamp` sont reconnues
   par `_resolve()`. `{{rand_int}}` (présent dans `21_php_upload_bypass.yaml`)
   se résout silencieusement en chaîne vide.
3. **`depends_on` est un champ mort.** Déclaré dans le dataclass `Job` mais
   jamais lu dans `run_job()`/`cli_main()`/le chargement GUI — l'écrire dans
   un template n'a aujourd'hui aucun effet sur l'ordre ou la condition
   d'exécution.
4. **`scope.requests_per_second` est documentaire.** Aucune limitation de
   débit n'est appliquée par l'`Engine` ; seul `--delay`/`delay_ms` (pause
   fixe entre deux tests, et uniquement en exécution séquentielle) influence
   réellement le rythme d'envoi.
5. **Le garde-fou `scope.active_testing` ne s'applique qu'à la GUI**, pas au
   CLI (détaillé dans [Garde-fous de sécurité](#garde-fous-de-sécurité)).
6. **`json_path` est une implémentation simplifiée**, sans wildcards ni
   filtres — ne pas attendre un comportement JSONPath RFC complet.
7. **Détection CORS par absence de preuve** (`25`/`26`, tests CORS) : ces
   templates vérifient qu'un `Origin` hostile n'est *pas* reflété ; un proxy
   ou WAF intermédiaire qui normalise les en-têtes peut masquer une
   vulnérabilité réelle côté application (faux négatif) — à confirmer
   manuellement en cas de doute.

---

## Licence

Non spécifiée dans l'archive fournie — à ajouter (`LICENSE`) avant diffusion
publique du dépôt si ce n'est pas déjà fait en amont.
