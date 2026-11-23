# Providers

## VirusTotal API v3
- Endpoint: `GET https://www.virustotal.com/api/v3/files/{sha256}` header `x-apikey`.
- Public API quota: 4 requests/min, 500/day (engine sleeps 15.5 s between lookups, max 25 per hunt).
- Used fields: `last_analysis_stats`, `meaningful_name`, `popular_threat_classification.suggested_threat_label`.
- 404 = unknown to VT (not "clean").
- Terms: public API is for non-commercial use; check VT ToS for your use case.

## MalwareBazaar (abuse.ch)
- Endpoint: `POST https://mb-api.abuse.ch/api/v1/` form `query=get_info&hash=<sha256>`, header `Auth-Key`
  (abuse.ch now requires a free Auth-Key for API access).
- `query_status`: `ok` (known malware sample), `hash_not_found`, `illegal_hash`.

## Offline sources (bulk import, no API calls at hunt time)
| Source | Content | Import |
|---|---|---|
| MalwareBazaar recent CSV | SHA-256 | `update_iocs.py --kind sha256 --from-file full.csv` |
| ThreatFox IOC export | domains, IP:port | `--kind domains` / `--kind ips` |
| URLhaus | malware URLs/hosts | `--kind domains` |
| loldrivers.io | vulnerable driver names/hashes | `--kind vuln_drivers` |

Verify current endpoints/quotas on provider docs before relying on them; they change.
