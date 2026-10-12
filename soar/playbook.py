"""Tiny playbook engine: YAML steps -> extract, enrich, score, decide, act. Actions are simulated
(written to an audit log) and destructive ones need `approve: true` or run in dry-run."""
import json, time
from pathlib import Path
import yaml
from .iocs import extract
from .enrich import VirusTotal, AbuseIPDB, URLhaus

PROVIDERS = {"virustotal": VirusTotal, "abuseipdb": AbuseIPDB, "urlhaus": URLhaus}


def ioc_score(kind, value, intel, w):
    s, why = 0, []
    vt = intel.get("virustotal")
    if vt and vt["malicious"] >= w["vt_min_engines"]:
        s += min(60, vt["malicious"] * 4); why.append(f"VT {vt['malicious']}/{vt['total']}" + (f" ({vt['label']})" if vt.get("label") else ""))
    ab = intel.get("abuseipdb")
    if ab and ab["confidence"] >= w["abuse_min_conf"]:
        s += ab["confidence"] * w["abuse_weight"]; why.append(f"AbuseIPDB {ab['confidence']}% / {ab['reports']} reports")
    uh = intel.get("urlhaus")
    if uh and uh.get("listed"):
        s += 30; why.append(f"URLhaus listed ({uh['url_count']} urls, tags {uh['tags']})")
    return min(100, round(s)), why


def run(alert, pb, live=False, approve=False, providers=None):
    t0 = time.time()
    providers = providers or {n: PROVIDERS[n](live) for n in pb["enrich"]["providers"]}
    case = {"alert_id": alert["id"], "title": alert["title"], "playbook": pb["name"], "iocs": {}, "actions": [], "audit": []}
    def audit(msg): case["audit"].append(msg)
    iocs = extract(json.dumps(alert))
    audit(f"extracted {sum(len(v) for k, v in iocs.items() if k != 'ipv4_internal')} external IOCs; internal hosts {iocs['ipv4_internal']}")
    for kind in pb["enrich"]["kinds"]:
        for v in iocs.get(kind, []):
            intel = {n: p.lookup(kind, v) for n, p in providers.items()}
            intel = {k: x for k, x in intel.items() if x}
            sc, why = ioc_score(kind, v, intel, pb["scoring"])
            case["iocs"][v] = {"kind": kind, "score": sc, "why": why, "intel": intel}
    top = max((x["score"] for x in case["iocs"].values()), default=0)
    case["max_ioc_score"] = top
    d = pb["decide"]
    verdict = "malicious" if top >= d["malicious"] else "suspicious" if top >= d["suspicious"] else "benign"
    case["verdict"] = verdict
    for act in pb["actions"].get(verdict, []):
        targets = [v for v, x in case["iocs"].items() if x["score"] >= d["suspicious"] and x["kind"] in act.get("kinds", [x["kind"]])] if act.get("per_ioc") else [alert.get(act.get("field", ""), alert["id"])]
        for tgt in targets:
            destructive = act.get("destructive", False)
            status = "executed(simulated)" if (not destructive or approve) else "pending_approval"
            case["actions"].append({"action": act["type"], "target": tgt, "status": status})
    case["seconds"] = round(time.time() - t0, 3)
    case["lookups"] = sum(p.calls for p in providers.values())
    return case


def render(case):
    L = [f"## Case {case['alert_id']}: {case['title']}", f"**Verdict:** {case['verdict'].upper()} (max IOC score {case['max_ioc_score']})", "",
         "| IOC | Type | Score | Evidence |", "|---|---|---|---|"]
    for v, x in sorted(case["iocs"].items(), key=lambda kv: -kv[1]["score"]):
        L.append(f"| `{v.replace('http', 'hxxp').replace('.', '[.]')}` | {x['kind']} | {x['score']} | {'; '.join(x['why']) or 'no hits'} |")
    L += ["", "**Actions:**"] + [f"- {a['action']} -> `{a['target']}`: {a['status']}" for a in case["actions"]] + ["", "**Audit:** " + " | ".join(case["audit"]), ""]
    return "\n".join(L)


def main():
    import argparse
    ap = argparse.ArgumentParser(); ap.add_argument("--playbook", default="playbooks/ioc_triage.yml")
    ap.add_argument("--alerts", default="alerts/sample_alerts.jsonl"); ap.add_argument("--live", action="store_true")
    ap.add_argument("--approve", action="store_true", help="execute destructive (simulated) actions"); ap.add_argument("-o", "--out", default="results")
    a = ap.parse_args()
    pb = yaml.safe_load(open(a.playbook)); out = Path(a.out); out.mkdir(exist_ok=True)
    provs = {n: PROVIDERS[n](a.live) for n in pb["enrich"]["providers"]}
    alerts = [json.loads(l) for l in open(a.alerts)]
    cases = [run(al, pb, a.live, a.approve, provs) for al in alerts]
    correct = sum(c["verdict"] == al.get("expected") for c, al in zip(cases, alerts))
    (out / "cases.md").write_text("# SOAR mini: case reports\n\n" + "\n".join(render(c) for c in cases))
    json.dump(cases, open(out / "cases.json", "w"), indent=2)
    for c, al in zip(cases, alerts):
        print(f"{c['alert_id']:8s} verdict={c['verdict']:10s} expected={al.get('expected'):10s} score={c['max_ioc_score']:3d} actions={[x['action'] + ':' + x['status'] for x in c['actions']]}")
    print(f"verdict accuracy {correct}/{len(alerts)}; API lookups {sum(p.calls for p in provs.values())}; mode={'live' if a.live else 'offline-fixtures'}")


if __name__ == "__main__":
    main()
