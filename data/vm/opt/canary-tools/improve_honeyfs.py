#!/usr/bin/env python3
"""Beef up Cowrie honeyfs + cmdoutput for a small Ubuntu web server persona. Preserves logs."""
import json, os, pickle, shutil, time
from pathlib import Path

ROOT = Path("/opt/cowrie/cowrie")
HF = ROOT / "etc/honeyfs"
CFG = ROOT / "etc/cowrie.cfg"
PICKLE = ROOT / "src/cowrie/data/fs.pickle"
CMDOUT = ROOT / "src/cowrie/data/cmdoutput.json"
TXT = ROOT / "src/cowrie/data/txtcmds"
NOW = int(time.time())
# A_NAME=0 A_TYPE=1 A_UID=2 A_GID=3 A_SIZE=4 A_MODE=5 A_CTIME=6 A_CONTENTS=7 A_TARGET=8 A_REALFILE=9
T_LINK, T_DIR, T_FILE = 0, 1, 2

def backup(p: Path):
    b = Path(str(p) + ".bak-pre-honeyfs")
    if p.exists() and not b.exists():
        shutil.copy2(p, b)

def write(rel, text, mode=0o644):
    p = HF / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text if text.endswith("\n") else text + "\n")
    os.chmod(p, mode)
    return p

def find(fs, path):
    n = fs
    for part in path.strip("/").split("/"):
        if not part: continue
        kids = n[7] if isinstance(n[7], list) else []
        hit = next((c for c in kids if c[0] == part), None)
        if hit is None: return None
        n = hit
    return n

def ensure_dir(fs, path, uid=0, gid=0, mode=0o40755):
    parts = [p for p in path.strip("/").split("/") if p]
    n = fs
    cur = "/"
    for part in parts:
        kids = n[7]
        hit = next((c for c in kids if c[0] == part), None)
        if hit is None:
            hit = [part, T_DIR, uid, gid, 4096, mode, NOW, [], None, None]
            kids.append(hit)
        n = hit
        cur = cur.rstrip("/") + "/" + part
    return n

def ensure_file(fs, path, size, uid=0, gid=0, mode=0o100644):
    parent = "/" + "/".join(path.strip("/").split("/")[:-1])
    name = path.strip("/").split("/")[-1]
    d = ensure_dir(fs, parent) if parent != "/" else fs
    kids = d[7]
    hit = next((c for c in kids if c[0] == name), None)
    if hit is None:
        hit = [name, T_FILE, uid, gid, size, mode, NOW, None, None, None]
        kids.append(hit)
    else:
        hit[1] = T_FILE; hit[4] = size; hit[5] = mode
    return hit

def ensure_link(fs, path, target):
    parent = "/" + "/".join(path.strip("/").split("/")[:-1])
    name = path.strip("/").split("/")[-1]
    d = ensure_dir(fs, parent) if parent != "/" else fs
    kids = d[7]
    hit = next((c for c in kids if c[0] == name), None)
    if hit is None:
        hit = [name, T_LINK, 0, 0, len(target), 0o120777, NOW, None, target, None]
        kids.append(hit)
    else:
        hit[1] = T_LINK; hit[8] = target; hit[4] = len(target)
    return hit

# --- honeyfs file contents ---
passwd = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:104:1::/var/cache/pollinate:/bin/false
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
syslog:x:106:112::/home/syslog:/usr/sbin/nologin
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
tss:x:109:115:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:110:116::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:111:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
deploy:x:1000:1000:Deploy User,,,:/home/deploy:/bin/bash
mysql:x:113:120:MySQL Server,,,:/nonexistent:/bin/false
nginx:x:114:121:nginx user,,,:/nonexistent:/usr/sbin/nologin
"""

group = """root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,deploy
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:deploy
floppy:x:25:
tape:x:26:
sudo:x:27:deploy
audio:x:29:deploy
dip:x:30:deploy
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:deploy
sasl:x:45:
plugdev:x:46:deploy
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
messagebus:x:105:
systemd-timesync:x:106:
ssh:x:111:
syslog:x:112:
uuidd:x:113:
tcpdump:x:114:
tss:x:115:
landscape:x:116:
fwupd-refresh:x:117:
netdev:x:118:deploy
lxd:x:119:deploy
mysql:x:120:
nginx:x:121:
deploy:x:1000:
"""

shadow = """root:*:19800:0:99999:7:::
daemon:*:19800:0:99999:7:::
bin:*:19800:0:99999:7:::
sys:*:19800:0:99999:7:::
sync:*:19800:0:99999:7:::
games:*:19800:0:99999:7:::
man:*:19800:0:99999:7:::
lp:*:19800:0:99999:7:::
mail:*:19800:0:99999:7:::
news:*:19800:0:99999:7:::
uucp:*:19800:0:99999:7:::
proxy:*:19800:0:99999:7:::
www-data:*:19800:0:99999:7:::
backup:*:19800:0:99999:7:::
list:*:19800:0:99999:7:::
irc:*:19800:0:99999:7:::
_apt:*:19800:0:99999:7:::
nobody:*:19800:0:99999:7:::
systemd-network:*:19800:0:99999:7:::
systemd-resolve:*:19800:0:99999:7:::
messagebus:*:19800:0:99999:7:::
systemd-timesync:*:19800:0:99999:7:::
pollinate:*:19800:0:99999:7:::
sshd:*:19800:0:99999:7:::
syslog:*:19800:0:99999:7:::
uuidd:*:19800:0:99999:7:::
tcpdump:*:19800:0:99999:7:::
tss:*:19800:0:99999:7:::
landscape:*:19800:0:99999:7:::
fwupd-refresh:*:19800:0:99999:7:::
usbmux:*:19800:0:99999:7:::
deploy:$6$rounds=5000$webprod02salt$X8kQ9mZ1nR0pL3vB6cD2eF4gH7jK9mN1qS3tU5wY7zA9bC1dE3fG5hI7jK9lM0nO2pQ4rS6tU8vW0xY2z:/19800:0:99999:7:::
mysql:*:19800:0:99999:7:::
nginx:*:19800:0:99999:7:::
"""

os_release = PRETTY_NAME=Ubuntu 22.04.5 LTS
