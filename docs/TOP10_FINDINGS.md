# Top 10 findings (final, 2026-10-14 to 2026-10-23)

> **Terms:** a *session* is one connection to the fake SSH/Telnet login (Cowrie). A *credential* is the username/password a bot tried. An *ASN* is the network operator that owns an IP. *HASSH* is a fingerprint of an SSH client's settings. More terms are in `GLOSSARY.md`.

Source: `dashboard/site/stats.json`, built from this repo's final logs (9,899,436 events; see `dashboard/build_stats.py`). Collection: 2026-10-14 20:51 PT to 2026-10-23 16:16 PT. Cowrie from 2026-10-14 ~23:20 PT.

1. **One Telnet botnet makes up most of the traffic.** Of 428,996 Cowrie sessions, 405,429 (94.5%) were Telnet and only 23,567 were SSH. 1,417 IPs reached Cowrie and 3,284 reached OpenCanary.
2. **A few residential networks in Pakistan and China do most of it.** By sessions, Pakistan leads with 204,876 (52 IPs) and China follows with 129,436 (155 IPs); the US has only 2,721 despite 291 IPs. The top networks are AS9541 Cyber Internet Services, Pakistan (175,327 sessions from 31 IPs) and AS4837 China Unicom (114,292 from 31 IPs).
3. **The "ximo" with blank password campaign.** `ximo` with an empty password is the top credential, tried 44,387 times by 49 IPs.
4. **The credentials are IoT and router factory defaults, not human passwords.** Next come root/xc3511 (16,339, a Xiongmai DVR default), root/Zte521 (16,106), admin/admin (13,892, from the most IPs: 295), root/888888 (13,581), root/070admin (10,201), root/samsung (8,526) and root/user (8,466).
5. **Mirai-style droppers were scripted the same way tens of thousands of times.** The most common command chain (`start; enable; config terminal; system; linuxshell; su; sh; ...cd to a writable dir; /bin/busybox ...`) ran 46,722 times from a single IP; `uname -s -v -n -r -m` (19,433 times, 22 IPs) is the most common recon command.
6. **205,453 malware download attempts but only 81 unique files.** 62,646 attempts failed. Three hashes dominate: 12013662… (105,467 downloads, 46 IPs), 4293c1d8… (43,460, 32 IPs) and f6c97b1e… (33,269, 18 IPs). Payloads were mostly fetched from the attackers' own IPs on high ports, which points to infected devices serving the next victim.
7. **The "mdrfckr" SSH key backdoor** (detail measured through Oct 21): 69 IPs ran `rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys`, mostly from cloud hosts.
8. **SSH is mostly a Go scanner** (detail measured through Oct 21): 96% of SSH client banners were `SSH-2.0-Go`, and one HASSH fingerprint covered most key exchanges from just 24 IPs.
9. **Volume grew almost every day, and most IPs are new each day.** Daily sessions went 10,337 (Oct 15) → 23,897 (Oct 18) → 46,768 (Oct 19) → 66,626 (Oct 20) → 94,160 (Oct 21) → 100,259 (Oct 22) → 72,924 (Oct 23, stopped 16:16). Every day 160–230 Cowrie IPs were new versus 50–66 repeats.
10. **OpenCanary shows what Cowrie can't.** Port scans (568,013 events, 2,194 IPs), Redis 6379 (517,365, 368 IPs), VNC 5900 (266,736, 247 IPs), RDP 3389 (150,942, 517 IPs, the most-scanned real service by IP count) and MySQL 3306 (28,651). Only 689 IPs hit both OpenCanary and Cowrie. The step-up in the OpenCanary line from 2026-10-21 00:00 PT is attacker-side: VNC 5900 hits jumped from ~0 to 8,000–9,000 per hour, led by 164.68.102.175, 84.46.252.220 and 84.46.250.47 (~11,000 hits each overall). The VNC service had been enabled and unchanged since Oct 15.

Bonus: time of day. Cowrie sessions peak around midnight PT (00:00: 22,509) and bottom out at 9 AM PT (11,329).

## Method and caveats
- Counts come from a read-only SQLite index of the raw logs; times are PT. Duplicate rotated logs are de-duplicated.
- **Gaps:** Cowrie recorded nothing from Oct 16 ~10:20 AM to Oct 17 ~4 PM PT (about 30 hours), and from Oct 17 evening to Oct 19 morning it hung 21 times for ~30 minutes each until the watchdog restarted it. See `DATA_GAPS_AND_ISSUES.md`.
- Geo and ASN data come from offline DB-IP Lite. Country is by IP and doesn't mean the attacker is there.
- Cowrie accepts most logins, so "successful logins" means the bot got in to Cowrie, not to a real device. Malware labels such as Mirai or Xiongmai are inferred from default creds and the busybox pattern, not checked on VirusTotal.
