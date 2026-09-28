#!/usr/bin/env python3
"""Pull Oregon veto findings live from api.oregonlegislature.gov and seal them as a
gatepost/v1 evidence pack.

usage: seal_veto_findings.py --key PRIVATE.pem OUT_DIR [--session-id ID]

Generate the key once, offline, and keep it off anything synced:
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ~/.gatepost/op_key.pem
Publish the printed key_id somewhere you control (site, email signature) before
sending a pack; recipients pin it with verify.py --expect-key.
"""
import datetime as dt, json, os, sys, urllib.parse, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gp_writer import Chain, public_key

API = "https://api.oregonlegislature.gov/odata/odataservice.svc/"
COLUMNS = ["seq", "schema", "jurisdiction", "session", "measure", "finding", "severity",
           "field", "field_value", "history_action", "history_action_date",
           "current_location", "source_query", "retrieved_at", "prev_hash"]

def q(entity, flt, sel):
    url = API + entity + "?" + urllib.parse.urlencode(
        {"$filter": flt, "$select": sel, "$format": "json"}, quote_via=urllib.parse.quote)
    return url, json.load(urllib.request.urlopen(url, timeout=120))["value"]

def now(): return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def findings():
    retrieved = now()
    vq, vetoes = q("MeasureHistoryActions", "substringof('Governor vetoed',ActionText)",
                   "SessionKey,MeasurePrefix,MeasureNumber,ActionText,ActionDate")
    out = []
    for a in sorted(vetoes, key=lambda a: (a["ActionDate"], a["SessionKey"], a["MeasurePrefix"], a["MeasureNumber"])):
        mq, m = q("Measures", f"SessionKey eq '{a['SessionKey']}' and MeasurePrefix eq '{a['MeasurePrefix']}' "
                  f"and MeasureNumber eq {a['MeasureNumber']}", "Vetoed,CurrentLocation")
        m = m[0]
        overridden = m["CurrentLocation"] == "Chapter Number Assigned"
        if m["Vetoed"]:
            finding, sev = "consistent", "none"
        elif overridden:
            finding, sev = "not_applicable_overridden_into_law", "none"
        else:
            finding, sev = "field_history_contradiction", "high"
        out.append({"jurisdiction": "or_legislature", "session": a["SessionKey"],
                    "measure": f"{a['MeasurePrefix']} {a['MeasureNumber']}", "finding": finding,
                    "severity": sev, "field": "Measures.Vetoed", "field_value": "true" if m["Vetoed"] else "false",
                    "history_action": a["ActionText"].strip(), "history_action_date": a["ActionDate"][:10],
                    "current_location": m["CurrentLocation"], "source_query": mq, "retrieved_at": retrieved})
    return out, vq

def main():
    a = sys.argv[1:]
    key = a[a.index("--key") + 1]
    sid = a[a.index("--session-id") + 1] if "--session-id" in a else "veto-check-" + now()[:10]
    outdir = next(x for x in a if not x.startswith("--") and x not in (key, sid))
    rows, vq = findings()
    c = Chain(COLUMNS, schema_name="proc_track/finding/v1")
    pub = public_key(key)
    c.add_key(pub, effective_from="2026-01-01T00:00:00Z")
    for r in rows: c.append(r)
    c.sign_head(key, sid, now())
    n = lambda f: sum(1 for r in rows if r["finding"] == f)
    c.export(outdir, extra_manifest={
        "title": "Oregon Legislature: Measures.Vetoed vs recorded 'Governor vetoed.' actions",
        "summary": {"measures_with_veto_action": str(len(rows)),
                    "field_history_contradiction": str(n("field_history_contradiction")),
                    "consistent": str(n("consistent")),
                    "overridden_into_law": str(n("not_applicable_overridden_into_law"))},
        "veto_query": vq})
    print(f"sealed {len(rows)} rows -> {outdir}\nkey_id {pub['key_id']}  (publish this; recipients pin it)")

if __name__ == "__main__":
    main()
