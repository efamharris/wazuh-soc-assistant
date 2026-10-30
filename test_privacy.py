import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import privacy

def make():
    return {"_source": {
        "agent": {"name": "web-prod-01"},
        "rule": {"description": "sshd: authentication failed"},
        "data": {"srcip": "8.8.8.8", "srcuser": "alice"},
        "full_log": ("Oct 15 10:00:01 web-prod-01 sshd[123]: Failed password for alice from 10.0.0.5 port 22 ssh2 "
                     "url=https://bob:not-a-real-secret@db.corp.local/app token=example-placeholder cmd=\"tool --password not-a-real-secret\" "
                     "path=/home/carol/.ssh/id_rsa mac=aa:bb:cc:dd:ee:ff host=ip-10-1-2-3.ec2.internal mail=dave@example.com")}}

LEAKS = ["10.0.0.5", "not-a-real-secret", "example-placeholder", "carol", "bob", "aa:bb:cc:dd:ee:ff",
         "10-1-2-3", "dave@example.com", "db.corp.local", "alice", "web-prod-01"]

bad = False
for mode in ("sanitise", "smart"):
    privacy.CFG["full_log"] = mode
    out = json.dumps(privacy.Scrubber().obj(make()), indent=2)
    found = [x for x in LEAKS if x in out]
    print("=" * 14, mode, "=" * 14)
    print(out)
    print("RESULT:", "LEAKED " + str(found) if found else "clean, nothing sensitive found")
    bad = bad or bool(found)

privacy.TERMS_RE = re.compile("acme-corp", re.I)
masked = privacy.Scrubber().text("Login from 10.0.0.5 by bob@acme-corp.com on the Acme-Corp portal, password=example-secret")
restored = privacy.detokenise_text(masked)
print("=" * 14, "round trip", "=" * 14)
print("To Claude:", masked)
print("Restored :", restored)
ok = ("10.0.0.5" not in masked and "Acme-Corp" not in masked and "not-a-real-secret" not in masked
      and "10.0.0.5" in restored and "Acme-Corp" in restored and "not-a-real-secret" not in restored)
print("ROUND TRIP:", "ok" if ok else "FAILED")
sys.exit(1 if (bad or not ok) else 0)
