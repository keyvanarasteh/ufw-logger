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

## Kural seti denetimi ve sıralama optimizasyonu

`ufw_audit.py`, kural setini üç açıdan denetler. Menüden: `sudo ./setup.sh` → **Kural seti denetimi & optimizasyon**; doğrudan: `sudo ufw_audit.py`.

**1. Sıralama performansı.** Güvenlik duvarı kuralları yukarıdan aşağıya okunur ve ilk eşleşen kural kazanır. Araç, iptables paket sayaçlarından her kuralın isabetini okur ve şunu hesaplar:

```
toplam kontrol = Σ isabet × (o kurala kadar değerlendirilen kural sayısı)
               + varsayılan politikaya düşen paket × zincir uzunluğu
```

Ardından bu değeri en aza indiren sırayı bulur. Kural: **eşleşme kümeleri kesişen iki kuralın göreli sırası asla değişmez.** Bu sayede her paketin ilk eşleştiği kural, dolayısıyla izin/ret kararı aynı kalır; yalnızca kontrol sayısı düşer. Küçük ve orta kural setlerinde çözüm kesin optimumdur (dinamik programlama), çok büyük setlerde sezgisel yöntem kullanılır ve rapor bunu belirtir. Verim eşikleri simülatördekiyle aynıdır: ≥ %95 mükemmel, ≥ %70 gelişebilir, altı verimsiz.

**2. Çakışan ve etkisiz kurallar.**

| Kod | Anlamı |
|---|---|
| `GOLGELEME` | Kural, önceki kurallar yüzünden hiç eşleşmiyor (ör. `allow 22` sonrası `deny 22 from IP`) |
| `KISMI-ETKISIZ` | DENY kuralının bir kısmına önce izin veriliyor (ör. `allow 22` sonrası `deny from IP`); düzeltme komutu önerilir |
| `GEREKSIZ` | Başka bir kural aynı kararı zaten veriyor, silinebilir |
| `KORELASYON` | Kısmen kesişen, sıraya bağımlı kurallar |

**3. Güvenlik ve yapı.** Varsayılan politika, dünyaya açık hassas portlar (veritabanı, RDP, SMB...), limitsiz SSH, her şeye izin veren kural, yüksek log seviyesi, CIDR olarak birleştirilebilecek kurallar, ESTABLISHED hızlı yolunun konumu.

```bash
sudo ufw_audit.py                    # rapor
sudo ufw_audit.py --sample 300       # sayaçları 5 dakikalık pencerede ölç
sudo ufw_audit.py --apply            # önerilen sırayı uygula (yedek alır, hata olursa geri alır)
sudo ufw_audit.py --notify           # özeti Telegram'a gönder
sudo ufw_audit.py --json             # makine tarafından okunabilir çıktı
sudo ufw_audit.py --exit-code        # kritik=2, uyarı=1 (CI / izleme için)
ufw_audit.py --iptables-save dump.txt   # UFW'siz sunucu: iptables-save -c çıktısını analiz et
```

Günlük otomatik denetim menüden açılır (`ufw-telegram-audit.timer`); yalnızca bulgular değiştiğinde Telegram'a bildirir.

Sınırlar:

- `--apply` yalnızca karar değiştirmeyen yeniden sıralamayı uygular. Güvenlik bulguları niyet gerektirir, otomatik düzeltilmez.
- Sayaçlar `ufw reload` ve yeniden başlatmada sıfırlanır. 1000 paketin altında sıralama önerisi verilmez (`--min-packets`).
- UFW'de kurulu bağlantılar kullanıcı kurallarından önce kabul edilir; kullanıcı kuralları esas olarak yeni bağlantıları görür. Kazanç, yeni bağlantı oranı yüksek (ör. tarama/DDoS altındaki) sunucularda belirgindir.
- `-m recent`, `-m set`, `--icmp-type` gibi modellenmeyen eşleşmeler temkinli ele alınır: bu kurallar başkasını gölgeleyemez, ama sıra kilidi oluşturur.
- Sonuçları uygulamadan önce bir uzman gözden geçirmelidir.

Testler: `python3 -m unittest discover -s tests`
