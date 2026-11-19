#!/usr/bin/env python3
"""Privacy proxy for the Shodan MCP server over stdio.
Usage: privacy_proxy.py shodan <real server command> [args...]"""
import json, os, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import privacy

if len(sys.argv) < 3 or sys.argv[1] != "shodan":
    sys.exit("Usage: privacy_proxy.py shodan <command> [args...]")
MODE, CMD = sys.argv[1], sys.argv[2:]
AUDIT = os.path.join(privacy.BASE, "audit.log")
sys.stdin.reconfigure(encoding="utf-8")
sys.stdout.reconfigure(encoding="utf-8")
LOCK = threading.Lock()

def audit(**kw):
    kw.update(ts=time.strftime("%Y-%m-%dT%H:%M:%S"), epoch=time.time(), server=MODE)
    try:
        with open(AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps(kw, ensure_ascii=False) + "\n")
    except Exception:
        pass

def emit(msg):
    with LOCK:
        sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
        sys.stdout.flush()

def error_result(req_id, text):
    return {"jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": True}}

child = subprocess.Popen(CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         text=True, encoding="utf-8", bufsize=1)

def from_child():
    for line in child.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        emit(msg)
    os._exit(child.wait())

def to_child():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            params = msg.get("params") or {}
            args = params.get("arguments") or {}
            tool = params.get("name")
            reason = privacy.outbound_problem(args)
            audit(tool=tool, arguments=args, decision="blocked" if reason else "allowed", reason=reason)
            if reason:
                if "id" in msg:
                    emit(error_result(msg["id"], "Blocked by privacy policy: %s. Internal and "
                                                  "placeholder values must never be sent to Shodan." % reason))
                continue
        try:
            child.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
            child.stdin.flush()
        except (BrokenPipeError, OSError):
            break
    try:
        child.stdin.close()
    except Exception:
        pass

threading.Thread(target=from_child, daemon=True).start()
to_child()
try:
    child.wait(timeout=10)
except subprocess.TimeoutExpired:
    child.kill()
