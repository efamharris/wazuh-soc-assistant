"""Privacy layer: pseudonymises internal data before it reaches Claude,
reverses it for the analyst, and checks what is sent to Shodan.
Standard library only."""
import ipaddress, json, os, re, sqlite3, time

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "pseudo.db")

_DEFAULT = {
    "own_public_ranges": [],
    "sensitive_terms": [],
    "full_log": "smart",
    "max_field_chars": 1500,
    "keep_values": ["root", "system", "local service", "network service", "-", "unknown"],
}
try:
    with open(os.path.join(BASE, "privacy_config.json"), encoding="utf-8") as f:
        CFG = {**_DEFAULT, **json.load(f)}
except FileNotFoundError:
    CFG = dict(_DEFAULT)

OWN_NETS = [ipaddress.ip_network(x, strict=False) for x in CFG["own_public_ranges"]]
TERMS_RE = (re.compile("|".join(re.escape(t) for t in sorted(CFG["sensitive_terms"], key=len, reverse=True)), re.I)
            if CFG["sensitive_terms"] else None)
KEEP = {v.lower() for v in CFG["keep_values"]}
MAXLEN = int(CFG["max_field_chars"])

DROP_KEYS = {"password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "authorization",
             "private_key", "privatekey", "access_token", "refresh_token", "client_secret"}
if CFG["full_log"] == "drop":
    DROP_KEYS.add("full_log")
HOST_KEYS = {"hostname", "host", "agent_name", "agent.name", "manager.name", "computer",
             "computername", "computer_name", "workstationname"}
USER_KEYS = {"user", "username", "srcuser", "dstuser", "targetusername", "subjectusername",
             "account", "accountname"}
PREFIX = {"IP": "INT_IP", "HOST": "HOST", "USER": "USER", "MAIL": "MAIL", "ORG": "ORG"}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TOKEN_RE = re.compile(r"\b(INT_IP|HOST|USER|MAIL|ORG)_(\d{4,})\b")
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED_JWT]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{12,}=*"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization)\b(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"),
     r"\1\2[REDACTED]"),
]

# ---------- placeholder database ----------
def _q(sql, args=()):
    c = sqlite3.connect(DB, timeout=10)
    try:
        try:
            os.chmod(DB, 0o600)
        except OSError:
            pass
        c.execute("CREATE TABLE IF NOT EXISTS map(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                  "kind TEXT, original TEXT UNIQUE, ts REAL)")
        with c:
            return c.execute(sql, args).fetchall()
    finally:
        c.close()

def _token_for(kind, original):
    now = time.time()
    _q("INSERT OR IGNORE INTO map(kind,original,ts) VALUES(?,?,?)", (kind, original, now))
    _q("UPDATE map SET ts=? WHERE original=?", (now, original))
    rid, k = _q("SELECT id, kind FROM map WHERE original=?", (original,))[0]
    return "%s_%04d" % (PREFIX[k], rid)

def purge_mapping(cutoff):
    _q("DELETE FROM map WHERE ts < ?", (cutoff,))

def _in_own(addr):
    return any(addr in n for n in OWN_NETS if n.version == addr.version)

# ---------- scrubbing ----------
class Scrubber:
    def __init__(self):
        self.known = {}
        for original, rid, kind in _q("SELECT original, id, kind FROM map WHERE kind IN ('HOST','USER')"):
            self.known[original] = "%s_%04d" % (PREFIX[kind], rid)
        self.known_re = None
        self._rebuild()

    def _rebuild(self):
        if self.known:
            alts = "|".join(re.escape(o) for o in sorted(self.known, key=len, reverse=True))
            self.known_re = re.compile(r"(?<![A-Za-z0-9_.@-])(?:%s)(?![A-Za-z0-9_@-])" % alts)
        else:
            self.known_re = None

    def _register(self, kind, value):
        v = value.strip()
        if (len(v) < 3 or v.isdigit() or v.lower() in KEEP or IP_RE.fullmatch(v)
                or TOKEN_RE.search(v) or "[REDACTED" in v):
            return
        self.known[v] = _token_for(kind, v)

    def _ip(self, m):
        ip = m.group(0)
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if a.is_loopback or a.is_unspecified or a.is_multicast:
            return ip
        if (not a.is_global) or _in_own(a):
            return _token_for("IP", ip)
        return ip

    def text(self, s, limit=False):
        for pat, rep in SECRET_PATTERNS:
            s = pat.sub(rep, s)
        s = EMAIL_RE.sub(lambda m: _token_for("MAIL", m.group(0)), s)
        s = IP_RE.sub(self._ip, s)
        if TERMS_RE:
            s = TERMS_RE.sub(lambda m: _token_for("ORG", m.group(0)), s)
        if self.known_re is not None:
            s = self.known_re.sub(lambda m: self.known[m.group(0)], s)
        if limit and len(s) > MAXLEN:
            s = s[:MAXLEN] + "...[truncated]"
        return s

    def _drop(self, o):
        if isinstance(o, dict):
            return {k: ("[REDACTED]" if isinstance(k, str) and k.lower() in DROP_KEYS else self._drop(v))
                    for k, v in o.items()}
        if isinstance(o, list):
            return [self._drop(x) for x in o]
        return o

    def _collect(self, o, parent=""):
        if isinstance(o, dict):
            for k, v in o.items():
                kl = k.lower() if isinstance(k, str) else ""
                if isinstance(v, str):
                    if kl in HOST_KEYS or (kl == "name" and parent in ("agent", "manager")):
                        self._register("HOST", v)
                    elif kl in USER_KEYS:
                        self._register("USER", v)
                else:
                    self._collect(v, kl)
        elif isinstance(o, list):
            for x in o:
                self._collect(x, parent)

    def _apply(self, o):
        if isinstance(o, dict):
            return {(self.text(k) if isinstance(k, str) else k): self._apply(v) for k, v in o.items()}
        if isinstance(o, list):
            return [self._apply(x) for x in o]
        if isinstance(o, str):
            return self.text(o, limit=True)
        return o

    def obj(self, o):
        o = self._drop(o)
        self._collect(o)
        self._rebuild()
        return self._apply(o)

    def blob(self, s):
        st = s.strip()
        if st[:1] in ("{", "["):
            try:
                return json.dumps(self.obj(json.loads(st)), ensure_ascii=False, separators=(",", ":"))
            except ValueError:
                pass
        return self.text(s)

def tokenise_text(s):
    return Scrubber().text(s) if isinstance(s, str) and s else s

def scrub_response(msg):
    s = Scrubber()
    r = msg.get("result")
    if isinstance(r, dict):
        if isinstance(r.get("content"), list):
            for item in r["content"]:
                if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                    item["text"] = s.blob(item["text"])
        if "structuredContent" in r:
            r["structuredContent"] = s.obj(r["structuredContent"])
    e = msg.get("error")
    if isinstance(e, dict) and isinstance(e.get("message"), str):
        e["message"] = s.text(e["message"])

# ---------- reversing placeholders ----------
def detokenise_text(s):
    if not isinstance(s, str) or not s:
        return s
    ids = {int(m.group(2)) for m in TOKEN_RE.finditer(s)}
    if not ids:
        return s
    rows = dict(_q("SELECT id, original FROM map WHERE id IN (%s)" % ",".join("?" * len(ids)), tuple(ids)))
    return TOKEN_RE.sub(lambda m: rows.get(int(m.group(2)), m.group(0)), s)

def detokenise_obj(o):
    if isinstance(o, dict):
        return {k: detokenise_obj(v) for k, v in o.items()}
    if isinstance(o, list):
        return [detokenise_obj(x) for x in o]
    return detokenise_text(o) if isinstance(o, str) else o

# ---------- Shodan outbound check ----------
def _strings(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(k, str):
                yield k
            yield from _strings(v)
    elif isinstance(o, list):
        for x in o:
            yield from _strings(x)
    elif isinstance(o, str):
        yield o

def outbound_problem(args):
    for s in _strings(args):
        t = TOKEN_RE.search(s)
        if t:
            return "the request contains an internal placeholder (%s)" % t.group(0)
        for m in IP_RE.finditer(s):
            try:
                a = ipaddress.ip_address(m.group(0))
            except ValueError:
                continue
            if not a.is_global:
                return "%s is not a public IP address" % a
            if _in_own(a):
                return "%s is inside your organisation's own IP ranges" % a
        if TERMS_RE and TERMS_RE.search(s):
            return "the request mentions a protected organisation term"
    return None

try:
    import privacy_plus  # noqa: F401
except ImportError:
    pass
