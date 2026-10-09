# UFW Telegram Logger

UFW güvenlik duvarının `[UFW BLOCK]` / `[UFW ALLOW]` kernel loglarını gerçek zamanlı olarak Telegram'a bildirir.

Python betiği `journalctl -k -f` çıktısını okur; satır gelene kadar blokta bekler, bu yüzden boştayken CPU harcamaz. Bash döngüsü + `grep`/`awk` yaklaşımına göre yoğun log akışında (`full` seviyesi) çok daha hafiftir.

## Dosyalar

| Dosya | Açıklama |
|---|---|
| `setup.sh` | [gum](https://github.com/charmbracelet/gum) arayüzlü kurulum / yönetim aracı |
| `ufw_telegram.py` | Log takip ve Telegram bildirim betiği |
| `ufw-telegram.service` | systemd servis tanımı |

## Gereksinimler

- systemd tabanlı Linux (Kali, Debian, Ubuntu...)
- `ufw`, `python3`, `python3-requests`, `curl`
- Telegram bot token'ı ([@BotFather](https://t.me/BotFather)) ve chat ID'si ([@userinfobot](https://t.me/userinfobot))

`setup.sh` eksik paketleri ve `gum`'ı (apt/pacman/dnf/brew) otomatik kurabilir.

## Hızlı Kurulum

```bash
chmod +x setup.sh
./setup.sh
```

Root değilseniz betik kendini `sudo` ile yeniden başlatır. Menüden **Kur / Güncelle**'yi seçin; sihirbaz şunları yapar:

1. Bağımlılıkları kontrol eder, eksikleri kurar
2. UFW'nin aktif olduğunu ve loglamanın açık olduğunu doğrular (kapalıysa seviye seçtirir)
3. `ufw_telegram.py` → `/usr/local/bin/`, servis dosyası → `/etc/systemd/system/`
4. Token ve Chat ID'yi sorar, test mesajı gönderir, `/etc/ufw-telegram.conf` dosyasına yazar (izin `600`)
5. Servisi etkinleştirir ve başlatır

Menüde ayrıca: yapılandırma, durum, test mesajı, servis logları, başlat/durdur ve kaldırma seçenekleri vardır.

## Elle Kurulum

```bash
sudo install -m 755 ufw_telegram.py /usr/local/bin/ufw_telegram.py
sudo install -m 644 ufw-telegram.service /etc/systemd/system/ufw-telegram.service

# Yapılandırma (token koda değil, root-only dosyaya yazılır)
sudo install -m 600 /dev/null /etc/ufw-telegram.conf
printf 'TELEGRAM_TOKEN=123456:ABC...\nCHAT_ID=123456789\n' | sudo tee /etc/ufw-telegram.conf >/dev/null

sudo ufw logging low            # loglama kapalıysa
sudo systemctl daemon-reload
sudo systemctl enable --now ufw-telegram.service
```

## Kontrol

```bash
sudo systemctl status ufw-telegram.service
sudo journalctl -u ufw-telegram.service -f
```

## Notlar

- `ufw logging full` çok yüksek hacimli log üretir ve her satır bir Telegram mesajıdır; Telegram'ın hız sınırına takılabilirsiniz. Genellikle `low` veya `medium` yeterlidir.
- Token `/etc/ufw-telegram.conf` içinde saklanır; bu dosyayı paylaşmayın veya repoya eklemeyin.
- Kaldırmak için `./setup.sh` → **Kaldır**.

## Bildirim profilleri ve filtreler

`sudo ./setup.sh` → **Bildirim profili & filtreler**. Varsayılan: sadece `BLOCK` bildirilir, `ALLOW` bildirilmez.

| Profil | Davranış |
|---|---|
| 🛑 Engelleme uyarıları | Sadece BLOCK, tekrar birleştirme, tarama tespiti |
| 🚨 Kritik uyarılar | Sadece kritik portlar (22, 3389, 445, DB...) için BLOCK ve ALLOW |
| ☑ Kontrol listesi | ALLOW, sadece gelen trafik, gürültü/broadcast filtresi, özel IP yoksayma, tekrar birleştirme, hız sınırı, port tarama tespiti, sunucu adı, günlük özet |

Ayarlar `/etc/ufw-telegram.conf` içinde tutulur (`NOTIFY_ACTIONS`, `ONLY_CRITICAL`, `CRITICAL_PORTS`, `IGNORE_PORTS`, `INBOUND_ONLY`, `DEDUP_SECONDS`, `RATE_LIMIT_PER_MIN`, `SCAN_DETECT`, `SUMMARY_HOURS` ...). Telegram IP aralıkları her zaman yoksayılır; böylece botun kendi trafiği bildirim döngüsü oluşturmaz.
