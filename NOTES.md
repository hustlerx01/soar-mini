# Interview talking points: soar-mini

1. **What SOAR saves.** Six alerts needed 27 lookups. By hand that's about 30 minutes, here it's under a second. The audit trail also records *why* each case was closed.
2. **Human in the loop.** Block and isolate are `destructive: true`, so they stay `pending_approval` unless an analyst passes `--approve`. A test enforces this. Auto-isolating a CFO's laptop on one VT hit is how SOAR loses trust.
3. **Scoring choices.** VT needs ≥3 engines because 1-2 engine hits are mostly noise (A-1003). AbuseIPDB gets a confidence threshold. URLhaus listing is a strong signal because its entries are curated malware URLs.
4. **The tuning story.** v1 auto-closed a scanner (A-1005). I changed one weight, then admitted that tuning on my own labels inflates accuracy. Next step: a held-out set.
5. **Absence of evidence.** A-1006 (new domain, no intel) gets closed as benign, which is a known gap. Newly registered domains are a top phishing indicator. Fix: RDAP domain age plus a rule that "unknown ≠ benign".
6. **Engineering.** Refanging, filtering private/allow-listed IOCs, de-duplicating sha256 vs md5 substrings, a per-run cache, API keys only from env vars, and offline fixtures so CI never needs secrets.
