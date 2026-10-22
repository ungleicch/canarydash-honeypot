# Adaptive Cowrie personas

When an IP logs into Cowrie (SSH 22 / Telnet 23), the honeypot picks a fake device
based on what that IP did before, so Mirai-style bots think they found a match and
download their payload (captured, never executed, 10 MB cap).

## Personas
| id | Looks like | When chosen |
|----|------------|-------------|
| iot-arm | Hi3518 ARM camera/DVR, BusyBox, armv7l | busybox, PBOC, .b/.k/.f, enable/system/shell, router default passwords |
| iot-mips | OpenWrt MIPS router | same IoT signals plus mips strings |
| linux-server | Ubuntu web-prod-02 x86_64 | default / unknown / human-like |
| miner | GPU-ish x86 Linux | xmrig, nvidia-smi, stratum, etc. |

## Files on the VM
- `/opt/cowrie/personas/personas.json` — persona definitions
- `/opt/cowrie/personas/ip_profiles.json` — per-IP map (`pinned: true` locks a choice)
- `/opt/cowrie/personas/profiler.py` — cron every 5 minutes
- `/opt/cowrie/personas/honeyfs/{iot-arm,iot-mips,miner}/` — cpuinfo/hostname overlays
- Cowrie patches: `persona_loader.py`, `shell/realm.py`, `shell/server.py`, `commands/uname.py`, `commands/busybox.py`, `shell/protocol.py` (backups `*.bak-persona`)

## Brazil bot
`191.98.239.177` is **pinned** to `iot-arm`. Soft rate limit (6 TCP + 6 UDP new conns/hour) is **unchanged**.

## Dashboard
Sessions emit `cowrie.session.params` with `persona=<id>` and `arch=...`.
