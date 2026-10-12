import json, yaml
from pathlib import Path
from soar.iocs import extract
from soar.playbook import run
from soar.enrich import VirusTotal

ROOT = Path(__file__).resolve().parents[1]
PB = yaml.safe_load(open(ROOT / "playbooks/ioc_triage.yml"))
ALERTS = [json.loads(l) for l in open(ROOT / "alerts/sample_alerts.jsonl")]


def test_refang_and_filters():
    i = extract("go hxxps://evil[.]top/x and 10.0.0.5 and 8.8.8.8 and https://www.microsoft.com/a")
    assert "https://evil.top/x" in i["url"] and "evil.top" in i["domain"]
    assert "10.0.0.5" in i["ipv4_internal"] and i["ipv4"] == ["8.8.8.8"]
    assert "www.microsoft.com" not in i["domain"]


def test_sha256_not_double_counted_as_md5():
    h = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert extract(h)["md5"] == [] and extract(h)["sha256"] == [h]


def test_verdicts_match_expected():
    for al in ALERTS:
        assert run(al, PB)["verdict"] == al["expected"], al["id"]


def test_destructive_actions_need_approval():
    c = run(ALERTS[0], PB)
    assert {a["status"] for a in c["actions"] if a["action"] in ("isolate_host", "block_ioc_on_firewall")} == {"pending_approval"}
    c2 = run(ALERTS[0], PB, approve=True)
    assert all(a["status"].startswith("executed") for a in c2["actions"])


def test_single_engine_hit_is_not_malicious():
    c = run(ALERTS[2], PB)
    assert c["iocs"]["203.0.113.15"]["score"] < PB["decide"]["suspicious"]


def test_cache_prevents_duplicate_lookups():
    vt = VirusTotal()
    vt.lookup("ipv4", "198.51.100.66"); vt.lookup("ipv4", "198.51.100.66")
    assert vt.calls == 1
