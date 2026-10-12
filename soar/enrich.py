"""Enrichment providers. Offline mode replays fixtures shaped like the real API responses
(VirusTotal v3, AbuseIPDB v2 /check, URLhaus /v1/host). Live mode calls the APIs if keys are set.
Results are cached in-process so one IOC is never looked up twice per run."""
import json, os, urllib.parse, urllib.request
from pathlib import Path

FIX = Path(__file__).resolve().parents[1] / "fixtures"


class Provider:
    name = "base"
    def __init__(self, live=False):
        self.live, self.cache, self.calls = live, {}, 0

    def lookup(self, kind, value):
        k = (kind, value)
        if k not in self.cache:
            self.calls += 1
            raw = self._live(kind, value) if self.live else self._offline(kind, value)
            self.cache[k] = self.normalise(kind, raw) if raw else None
        return self.cache[k]

    def _offline(self, kind, value):
        p = FIX / self.name / f"{value.replace('/', '_').replace(':', '_')}.json"
        return json.loads(p.read_text()) if p.exists() else None


class VirusTotal(Provider):
    name = "virustotal"
    PATH = {"ipv4": "ip_addresses", "domain": "domains", "sha256": "files", "md5": "files"}
    def _live(self, kind, value):
        if kind not in self.PATH: return None
        req = urllib.request.Request(f"https://www.virustotal.com/api/v3/{self.PATH[kind]}/{value}", headers={"x-apikey": os.environ["VT_API_KEY"]})
        try: return json.load(urllib.request.urlopen(req, timeout=15))
        except Exception: return None
    def normalise(self, kind, raw):
        st = raw["data"]["attributes"]["last_analysis_stats"]
        total = sum(st.values()) or 1
        return {"malicious": st.get("malicious", 0), "total": total, "ratio": round(st.get("malicious", 0) / total, 3),
                "label": raw["data"]["attributes"].get("popular_threat_classification", {}).get("suggested_threat_label")}


class AbuseIPDB(Provider):
    name = "abuseipdb"
    def _live(self, kind, value):
        if kind != "ipv4": return None
        req = urllib.request.Request("https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90}),
                                     headers={"Key": os.environ["ABUSEIPDB_API_KEY"], "Accept": "application/json"})
        try: return json.load(urllib.request.urlopen(req, timeout=15))
        except Exception: return None
    def normalise(self, kind, raw):
        d = raw["data"]
        return {"confidence": d["abuseConfidenceScore"], "reports": d["totalReports"], "country": d.get("countryCode"), "isp": d.get("isp")}


class URLhaus(Provider):
    name = "urlhaus"
    def _live(self, kind, value):
        if kind not in ("domain", "ipv4"): return None
        data = urllib.parse.urlencode({"host": value}).encode()
        req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/host/", data=data, headers={"Auth-Key": os.environ.get("URLHAUS_AUTH_KEY", "")})
        try: return json.load(urllib.request.urlopen(req, timeout=15))
        except Exception: return None
    def normalise(self, kind, raw):
        if raw.get("query_status") != "ok": return {"listed": False}
        return {"listed": True, "url_count": int(raw.get("url_count", 0)), "tags": sorted({t for u in raw.get("urls", []) for t in (u.get("tags") or [])})}
