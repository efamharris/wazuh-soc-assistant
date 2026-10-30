"""Extra log scrubbing and a 'smart' full_log mode. Loaded automatically by privacy.py."""
import ipaddress, re
import privacy

DASH_IP_RE = re.compile(r"\bip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\b", re.I)
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
HOME_RE = re.compile(r"(?i)(/home/|/Users/|\\Users\\)([A-Za-z0-9._-]{2,})")
FQDN_RE = re.compile(r"\b(?:[A-Za-z0-9_-]+\.)+(?:local|internal|lan|corp|intranet|home|localdomain)\b", re.I)
URL_CRED_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")
FLAG_RE = re.compile(r"(?i)(--(?:password|passwd|pass|token|secret|api-key)\s+)(\S+)")
COOKIE_RE = re.compile(r"(?i)\b((?:set-)?cookie\s*[=:]\s*)([^\r\n\"]+)")
KV_RE = re.compile(r"(?i)\b(passphrase|credentials?|client_secret|access_token|refresh_token|session_?id|jsessionid|phpsessid|x-api-key)\b(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)")
SKIP_HOME = {"public", "default", "shared", "all"}

_orig_text = privacy.Scrubber.text
_orig_obj = privacy.Scrubber.obj

def _dip(m):
    ip = ".".join(m.group(i) for i in range(1, 5))
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return m.group(0)
    if a.is_loopback or a.is_unspecified or a.is_multicast:
        return m.group(0)
    if (not a.is_global) or privacy._in_own(a):
        return privacy._token_for("IP", ip)
    return m.group(0)

def _home(m):
    name = m.group(2)
    if name.lower() in SKIP_HOME or name.lower() in privacy.KEEP:
        return m.group(0)
    return m.group(1) + privacy._token_for("USER", name)

def _fqdn(m):
    v = m.group(0)
    if privacy.TOKEN_RE.search(v):
        return v
    return privacy._token_for("HOST", v)

def text(self, s, limit=False):
    s = URL_CRED_RE.sub(r"\1[REDACTED]@", s)
    s = FLAG_RE.sub(r"\1[REDACTED]", s)
    s = COOKIE_RE.sub(r"\1[REDACTED]", s)
    s = KV_RE.sub(r"\1\2[REDACTED]", s)
    s = privacy.EMAIL_RE.sub(lambda m: privacy._token_for("MAIL", m.group(0)), s)
    s = DASH_IP_RE.sub(_dip, s)
    s = MAC_RE.sub("[REDACTED_MAC]", s)
    s = HOME_RE.sub(_home, s)
    s = FQDN_RE.sub(_fqdn, s)
    return _orig_text(self, s, limit)

def _smart(o):
    if privacy.CFG.get("full_log") != "smart":
        return o
    if isinstance(o, dict):
        has = isinstance(o.get("data"), dict) and bool(o.get("data"))
        return {k: ("[full_log withheld: the decoded fields in this alert hold the same event]"
                    if has and isinstance(k, str) and k.lower() == "full_log" else _smart(v))
                for k, v in o.items()}
    if isinstance(o, list):
        return [_smart(x) for x in o]
    return o

def obj(self, o):
    return _orig_obj(self, _smart(o))

privacy.Scrubber.text = text
privacy.Scrubber.obj = obj
