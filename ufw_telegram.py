#!/usr/bin/env python3
import subprocess
import re
import requests
import sys
import os
import socket
import threading
import time
import ipaddress
from collections import Counter, defaultdict

# --- YAPILANDIRMA (/etc/ufw-telegram.conf -> systemd EnvironmentFile) ---
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
CHAT_ID = os.environ.get("CHAT_ID", "")


def env_bool(name, default):
    return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def env_list(name, default=""):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


# Varsayılan: sadece BLOCK bildirilir, ALLOW bildirilmez.
NOTIFY_ACTIONS = {a.upper() for a in env_list("NOTIFY_ACTIONS", "BLOCK")}
CRITICAL_PORTS = set(env_list("CRITICAL_PORTS", "22,23,3389,445,3306,5432,6379,27017,5900"))
ONLY_CRITICAL = env_bool("ONLY_CRITICAL", False)
IGNORE_PORTS = set(env_list("IGNORE_PORTS", "53,5353,1900,137,138,67,68"))
INBOUND_ONLY = env_bool("INBOUND_ONLY", True)
IGNORE_BROADCAST = env_bool("IGNORE_BROADCAST", True)
IGNORE_PRIVATE_SRC = env_bool("IGNORE_PRIVATE_SRC", False)
DEDUP_SECONDS = env_int("DEDUP_SECONDS", 60)
RATE_LIMIT_PER_MIN = env_int("RATE_LIMIT_PER_MIN", 20)
SCAN_DETECT = env_bool("SCAN_DETECT", True)
SCAN_PORTS = env_int("SCAN_PORTS", 10)
SCAN_WINDOW = env_int("SCAN_WINDOW", 60)
SHOW_HOSTNAME = env_bool("SHOW_HOSTNAME", True)
SUMMARY_HOURS = env_int("SUMMARY_HOURS", 0)

# Telegram'ın kendi aralıkları: botun mesajı loglanıp tekrar mesaj üretmesin (geri besleme döngüsü)
IGNORE_NETS = []
for _n in env_list("IGNORE_CIDRS", "149.154.160.0/20,91.108.4.0/22,91.108.8.0/22,"
                                   "91.108.12.0/22,91.108.16.0/22,91.108.56.0/22,185.76.151.0/24"):
    try:
        IGNORE_NETS.append(ipaddress.ip_network(_n, strict=False))
    except ValueError:
        print(f"Geçersiz IGNORE_CIDRS girdisi atlandı: {_n}", file=sys.stderr)
# ------------------------------------------------------------------------

if not TELEGRAM_TOKEN or not CHAT_ID:
    sys.exit("TELEGRAM_TOKEN ve CHAT_ID tanımlı değil (/etc/ufw-telegram.conf)")

API_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
HOST = socket.gethostname()

lock = threading.Lock()
last_sent = {}                      # dedup anahtarı -> son gönderim zamanı
repeat_count = defaultdict(int)     # dedup anahtarı -> bastırılan tekrar sayısı
scan_hits = defaultdict(dict)       # src -> {port: zaman}
scan_flagged = {}                   # src -> uyarı zamanı
sent_times = []                     # son 60 sn içinde gönderilenler
suppressed = 0
stats = Counter()
top_src = Counter()


def send_telegram(message):
    try:
        payload = {"chat_id": CHAT_ID, "text": message, "parse_mode": "Markdown"}
        response = requests.post(API_URL, json=payload, timeout=5)
        if response.status_code != 200:
            print(f"Telegram hatası: {response.text}", file=sys.stderr)
    except Exception as e:
        print(f"Bağlantı hatası: {e}", file=sys.stderr)


def rate_limited_send(message):
    """Dakika başına en fazla RATE_LIMIT_PER_MIN mesaj; fazlası sayılıp özetlenir."""
    global suppressed
    now = time.time()
    with lock:
        sent_times[:] = [t for t in sent_times if now - t < 60]
        if RATE_LIMIT_PER_MIN > 0 and len(sent_times) >= RATE_LIMIT_PER_MIN:
            suppressed += 1
            return
        note = suppressed
        suppressed = 0
        sent_times.append(now)
    if note:
        send_telegram(f"⚠️ *Hız sınırı:* {note} olay bastırıldı.")
    send_telegram(message)


def in_ignored_net(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in IGNORE_NETS if n.version == addr.version)


def is_broadcast_or_multicast(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_multicast or ip == "255.255.255.255" or ip.endswith(".255")


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def check_scan(src, dpt):
    """Aynı kaynaktan SCAN_WINDOW içinde SCAN_PORTS farklı porta BLOCK -> tarama uyarısı."""
    now = time.time()
    with lock:
        hits = scan_hits[src]
        hits[dpt] = now
        for p in [p for p, t in hits.items() if now - t > SCAN_WINDOW]:
            del hits[p]
        if len(hits) >= SCAN_PORTS and now - scan_flagged.get(src, 0) > SCAN_WINDOW:
            scan_flagged[src] = now
            count = len(hits)
            hits.clear()
            return count
    return 0


def recently_flagged(src):
    with lock:
        return time.time() - scan_flagged.get(src, 0) <= SCAN_WINDOW


def prune():
    now = time.time()
    with lock:
        for k in [k for k, t in last_sent.items() if now - t > max(DEDUP_SECONDS, 1) * 5]:
            last_sent.pop(k, None)
            repeat_count.pop(k, None)
        for s in [s for s, t in scan_flagged.items() if now - t > SCAN_WINDOW * 5]:
            scan_flagged.pop(s, None)
        for s in [s for s, h in scan_hits.items() if not h]:
            scan_hits.pop(s, None)


def host_line():
    return f"• *Sunucu:* `{HOST}`\n" if SHOW_HOSTNAME else ""


def parse_and_send(line):
    # Örnek: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.50 DST=192.168.1.100 PROTO=TCP SPT=4321 DPT=22
    action_match = re.search(r'\[UFW\s+(BLOCK|ALLOW)\]', line)
    if not action_match:
        return

    action = action_match.group(1)

    src = re.search(r'SRC=([^\s]+)', line)
    dst = re.search(r'DST=([^\s]+)', line)
    proto = re.search(r'PROTO=([^\s]+)', line)
    dpt = re.search(r'DPT=(\d+)', line)
    spt = re.search(r'SPT=(\d+)', line)
    out_if = re.search(r'OUT=(\S*)', line)

    src_ip = src.group(1) if src else "Bilinmiyor"
    dst_ip = dst.group(1) if dst else "Bilinmiyor"
    protocol = proto.group(1) if proto else "Bilinmiyor"
    dest_port = dpt.group(1) if dpt else "-"
    src_port = spt.group(1) if spt else "-"

    # --- Gürültü filtreleri ---
    if INBOUND_ONLY and out_if and out_if.group(1):
        return  # giden/yönlendirilen trafik
    if in_ignored_net(src_ip) or in_ignored_net(dst_ip):
        return
    if dest_port in IGNORE_PORTS:
        return
    if IGNORE_BROADCAST and is_broadcast_or_multicast(dst_ip):
        return
    if IGNORE_PRIVATE_SRC and is_private(src_ip):
        return

    critical = dest_port in CRITICAL_PORTS

    with lock:
        stats[action] += 1
        if critical:
            stats["CRITICAL"] += 1
        top_src[src_ip] += 1

    # --- Port tarama tespiti (sadece BLOCK) ---
    if SCAN_DETECT and action == "BLOCK" and dest_port != "-":
        n = check_scan(src_ip, dest_port)
        if n:
            rate_limited_send(
                "🚨 *PORT TARAMASI ŞÜPHESİ*\n\n"
                f"{host_line()}"
                f"• *Kaynak IP:* `{src_ip}`\n"
                f"• *{SCAN_WINDOW} sn içinde:* {n} farklı port\n"
                f"• *Hedef IP:* `{dst_ip}`"
            )
            return
        if recently_flagged(src_ip):
            return  # tarama uyarısı zaten gitti, tek tek bildirme

    # --- Bildirim kuralları ---
    if action not in NOTIFY_ACTIONS:
        return
    if ONLY_CRITICAL and not critical:
        return

    # --- Tekrar bastırma ---
    key = (action, src_ip, dst_ip, dest_port, protocol)
    now = time.time()
    with lock:
        if DEDUP_SECONDS > 0 and now - last_sent.get(key, 0) < DEDUP_SECONDS:
            repeat_count[key] += 1
            return
        last_sent[key] = now
        repeats = repeat_count.pop(key, 0)

    if critical:
        title, emoji = "KRİTİK PORT HAREKETİ", "🚨"
    elif action == "BLOCK":
        title, emoji = "Engellenen Bağlantı", "🛑"
    else:
        title, emoji = "İzin Verilen Bağlantı", "✅"

    msg = (
        f"{emoji} *{title}*\n\n"
        f"{host_line()}"
        f"• *Aksiyon:* {action}\n"
        f"• *Kaynak IP:* `{src_ip}`\n"
        f"• *Hedef Port:* `{dest_port}` ({protocol})\n"
        f"• *Kaynak Port:* `{src_port}`\n"
        f"• *Hedef IP:* `{dst_ip}`"
    )
    if repeats:
        msg += f"\n• *Önceki tekrar:* +{repeats}"
    rate_limited_send(msg)


def summary_loop():
    interval = SUMMARY_HOURS * 3600
    while True:
        time.sleep(interval)
        with lock:
            snap, tops = dict(stats), top_src.most_common(5)
            stats.clear()
            top_src.clear()
        lines = "\n".join(f"  `{ip}` — {c}" for ip, c in tops) or "  -"
        send_telegram(
            f"📊 *UFW Özeti ({SUMMARY_HOURS} sa)* — `{HOST}`\n\n"
            f"• BLOCK: {snap.get('BLOCK', 0)}\n"
            f"• ALLOW: {snap.get('ALLOW', 0)}\n"
            f"• Kritik port: {snap.get('CRITICAL', 0)}\n"
            f"• En aktif kaynaklar:\n{lines}"
        )


def prune_loop():
    while True:
        time.sleep(300)
        prune()


def main():
    threading.Thread(target=prune_loop, daemon=True).start()
    if SUMMARY_HOURS > 0:
        threading.Thread(target=summary_loop, daemon=True).start()

    # Kali/Systemd uyumlu canlı journalctl takibi
    cmd = ["journalctl", "-k", "-f", "-n", "0", "-o", "cat"]

    # stdout=PIPE ile log akışını yakalıyoruz
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    try:
        # Satır gelene kadar blokta bekler (CPU harcamaz)
        for line in process.stdout:
            parse_and_send(line.strip())
    except KeyboardInterrupt:
        process.terminate()


if __name__ == "__main__":
    main()
