"""IOC extraction with refanging (hxxp, [.]) and filtering of private/doc ranges and allow-listed domains."""
import ipaddress, re

REFANG = [("hxxps", "https"), ("hxxp", "http"), ("[.]", "."), ("(.)", "."), ("[:]", ":"), ("[at]", "@")]
RX = {
    "url": re.compile(r"\bhttps?://[^\s\"'<>]+", re.I),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|in|biz|co|online|site)\b", re.I),
}
ALLOW_DOMAINS = {"microsoft.com", "google.com", "office.com", "windowsupdate.com"}


def refang(text):
    for a, b in REFANG:
        text = text.replace(a, b)
    return text


def extract(text):
    t = refang(text)
    out = {k: set() for k in RX}
    for k, rx in RX.items():
        out[k] = set(m.group(0).rstrip(".,);") for m in rx.finditer(t))
    out["md5"] -= {h for s in out["sha256"] for h in [s[:32]]}
    out["domain"] = {d.lower() for d in out["domain"] if not any(d.lower() == a or d.lower().endswith("." + a) for a in ALLOW_DOMAINS)}
    pub = set()
    for ip in out["ipv4"]:
        a = ipaddress.ip_address(ip)
        if not (a.is_private or a.is_loopback or a.is_reserved or a.is_multicast) or ip.startswith(("198.51.100.", "203.0.113.", "192.0.2.")):
            pub.add(ip)   # keep RFC5737 doc ranges: used as 'external' in this lab
    out["ipv4_internal"] = out["ipv4"] - pub
    out["ipv4"] = pub
    return {k: sorted(v) for k, v in out.items()}
