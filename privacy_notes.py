"""Builds the one-line note describing what the privacy filter changed."""
import collections, json, os, re

BASE = os.path.dirname(os.path.abspath(__file__))
AUDIT = os.path.join(BASE, "audit.log")
TOKEN_RE = re.compile(r"\b(INT_IP|HOST|USER|MAIL|ORG)_(\d{4,})\b")
LABEL = {"INT_IP": "internal IP", "HOST": "hostname", "USER": "username",
         "MAIL": "email address", "ORG": "organisation name"}

def _n(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")

def summary(since, answer=""):
    toks, secrets, withheld, truncated, blocked = set(), 0, 0, 0, 0
    try:
        with open(AUDIT, encoding="utf-8") as f:
            lines = collections.deque(f, maxlen=2000)
    except OSError:
        lines = []
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("epoch", 0) < since:
            continue
        if e.get("event") == "scrubbed":
            toks.update(e.get("tokens", []))
            secrets += e.get("redactions", 0)
            withheld += e.get("withheld", 0)
            truncated += e.get("truncated", 0)
        if e.get("decision") == "blocked":
            blocked += 1
    parts = []
    if toks:
        counts = collections.Counter(t.rsplit("_", 1)[0] for t in toks)
        bits = [_n(n, LABEL[k]) for k, n in counts.items() if k in LABEL]
        parts.append("Masked in the data Claude read (real values shown above): " + ", ".join(bits))
    left = {m.group(0) for m in TOKEN_RE.finditer(answer or "")}
    if left:
        parts.append(_n(len(left), "placeholder") + " could not be restored because the mapping expired")
    if secrets:
        parts.append(_n(secrets, "secret/credential") + " removed (not recoverable, check the Wazuh dashboard)")
    if withheld:
        parts.append(_n(withheld, "raw log") + " withheld (decoded fields used instead)")
    if truncated:
        parts.append(_n(truncated, "long field") + " shortened")
    if blocked:
        parts.append(_n(blocked, "Shodan lookup") + " blocked (private data)")
    return ("Privacy filter: " + "; ".join(parts) + ".") if parts else ""
