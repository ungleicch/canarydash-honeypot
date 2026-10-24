# Final summary (project ended 2026-10-23)

**Collection period:** 2026-10-14 20:51 PDT → 2026-10-23 16:16 PDT. OpenCanary ran the whole time; Cowrie (SSH/Telnet) from 2026-10-14 ~23:20 PDT.
**Status:** ended. Services stopped 2026-10-23 16:16 PDT, final copy taken, Azure VM/storage removed, hosted dashboard taken offline. This repo is the complete, final, static archive.

## Totals
- Events: 9,899,436
- Cowrie sessions: 428,996 (405,429 Telnet, 23,567 SSH)
- Unique IPs: 1,417 (Cowrie), 3,284 (OpenCanary)
- Download attempts: 205,453, failed 62,646, unique files 81

## Top 5
- Countries by Cowrie sessions: Pakistan (204,876), China (129,436), The Netherlands (19,965), Ukraine (19,148), Argentina (18,857)
- Credentials tried: `ximo / ` (44,387), `root / xc3511` (16,339), `root / Zte521` (16,106), `admin / admin` (13,892), `root / 888888` (13,581)
- OpenCanary services: Port scan (568,013), Redis 6379 (517,365), VNC 5900 (266,736), RDP 3389 (150,942), MySQL 3306 (28,651)

`docs/TOP10_FINDINGS.md` was written on Oct 21 from the first 7 days; its numbers cover only that period. The dashboard (`dashboard/site/stats.json`) has the final numbers.
