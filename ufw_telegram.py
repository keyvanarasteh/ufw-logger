#!/usr/bin/env python3
import subprocess
import re
import requests
import sys
import os

# --- YAPILANDIRMA (/etc/ufw-telegram.conf -> systemd EnvironmentFile) ---
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
CHAT_ID = os.environ.get("CHAT_ID", "")
# ------------------------------------------------------------------------

if not TELEGRAM_TOKEN or not CHAT_ID:
    sys.exit("TELEGRAM_TOKEN ve CHAT_ID tanımlı değil (/etc/ufw-telegram.conf)")

API_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

def send_telegram(message):
    try:
        payload = {"chat_id": CHAT_ID, "text": message, "parse_mode": "Markdown"}
        response = requests.post(API_URL, json=payload, timeout=5)
        if response.status_code != 200:
            print(f"Telegram hatası: {response.text}", file=sys.stderr)
    except Exception as e:
        print(f"Bağlantı hatası: {e}", file=sys.stderr)

def parse_and_send(line):
    # Regex ile log satırındaki önemli verileri ayrıştırıyoruz
    # Örnek: UFW BLOCK: SRC=192.168.1.50 DST=192.168.1.100 PROTO=TCP SPT=4321 DPT=22
    action_match = re.search(r'\[UFW\s+(BLOCK|ALLOW)\]', line)
    if not action_match:
        return

    action = action_match.group(1)
    
    src = re.search(r'SRC=([^\s]+)', line)
    dst = re.search(r'DST=([^\s]+)', line)
    proto = re.search(r'PROTO=([^\s]+)', line)
    dpt = re.search(r'DPT=(\d+)', line)
    spt = re.search(r'SPT=(\d+)', line)

    src_ip = src.group(1) if src else "Bilinmiyor"
    dst_ip = dst.group(1) if dst else "Bilinmiyor"
    protocol = proto.group(1) if proto else "Bilinmiyor"
    dest_port = dpt.group(1) if dpt else "Bilinmiyor"
    src_port = spt.group(1) if spt else "Bilinmiyor"

    # Telegram'a gidecek mesaj formatı
    status_emoji = "🛑" if action == "BLOCK" else "✅"
    msg = (
        f"{status_emoji} *UFW Hareketi Tespit Edildi!*\n\n"
        f"• *Aksiyon:* {action}\n"
        f"• *Kaynak IP:* `{src_ip}`\n"
        f"• *Hedef Port:* `{dest_port}` ({protocol})\n"
        f"• *Kaynak Port:* `{src_port}`\n"
        f"• *Hedef IP:* `{dst_ip}`"
    )
    send_telegram(msg)

def main():
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
