# SOAR mini: case reports

## Case A-1001: EDR: outbound to known C2
**Verdict:** MALICIOUS (max IOC score 100)

| IOC | Type | Score | Evidence |
|---|---|---|---|
| `198[.]51[.]100[.]66` | ipv4 | 100 | VT 14/90 (trojan.qakbot); AbuseIPDB 100% / 812 reports; URLhaus listed (23 urls, tags ['exe', 'qakbot']) |

**Actions:**
- block_ioc_on_firewall -> `198.51.100.66`: pending_approval
- isolate_host -> `WS-FIN-07`: pending_approval
- open_ticket_P2 -> `A-1001`: executed(simulated)

**Audit:** extracted 1 external IOCs; internal hosts ['10.20.1.7']

## Case A-1002: Phishing report from user
**Verdict:** MALICIOUS (max IOC score 66)

| IOC | Type | Score | Evidence |
|---|---|---|---|
| `invoice-update[.]top` | domain | 66 | VT 9/90 (phishing); URLhaus listed (4 urls, tags ['phishing']) |
| `hxxps://invoice-update[.]top/pay` | url | 0 | no hits |
| `hxxps://www[.]microsoft[.]com/logo[.]png` | url | 0 | no hits |

**Actions:**
- block_ioc_on_firewall -> `invoice-update.top`: pending_approval
- isolate_host -> `WS-HR-02`: pending_approval
- open_ticket_P2 -> `A-1002`: executed(simulated)

**Audit:** extracted 3 external IOCs; internal hosts []

## Case A-1003: Firewall: inbound probe
**Verdict:** BENIGN (max IOC score 0)

| IOC | Type | Score | Evidence |
|---|---|---|---|
| `203[.]0[.]113[.]15` | ipv4 | 0 | no hits |

**Actions:**
- close_as_false_positive -> `A-1003`: executed(simulated)

**Audit:** extracted 1 external IOCs; internal hosts ['10.0.0.4']

## Case A-1004: AV: file quarantined
**Verdict:** MALICIOUS (max IOC score 60)

| IOC | Type | Score | Evidence |
|---|---|---|---|
| `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` | sha256 | 60 | VT 41/72 (ransomware.lockbit) |

**Actions:**
- isolate_host -> `WS-ENG-11`: pending_approval
- open_ticket_P2 -> `A-1004`: executed(simulated)

**Audit:** extracted 1 external IOCs; internal hosts []

## Case A-1005: WAF: repeated 404s
**Verdict:** SUSPICIOUS (max IOC score 27)

| IOC | Type | Score | Evidence |
|---|---|---|---|
| `203[.]0[.]113[.]77` | ipv4 | 27 | AbuseIPDB 45% / 30 reports |
| `cdn[.]example-assets[.]com` | domain | 0 | no hits |

**Actions:**
- open_ticket_P3 -> `A-1005`: executed(simulated)
- add_to_watchlist -> `203.0.113.77`: executed(simulated)

**Audit:** extracted 2 external IOCs; internal hosts []

## Case A-1006: DNS: new domain lookup
**Verdict:** BENIGN (max IOC score 0)

| IOC | Type | Score | Evidence |
|---|---|---|---|
| `unseen-domain-xyz[.]online` | domain | 0 | no hits |

**Actions:**
- close_as_false_positive -> `A-1006`: executed(simulated)

**Audit:** extracted 1 external IOCs; internal hosts []
