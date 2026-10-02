Here are your files: 
Bu iş için Python kullanmak en performanslı ve sağlıklı yöntemdir. Bash ile döngü kurup grep veya awk çalıştırmak, yüksek log akışlarında (full seviyesindeyken) CPU'yu gereksiz yorar.
Yazdığım Python betiği, Linux çekirdeğinin select (I/O multiplexing) mekanizmasını kullanır. Bu sayede işlemciyi hiç yormadan, sadece yeni bir log satırı geldiği anda uyanır, veriyi süzüp Telegram'a gönderir ve hemen uykuya döner. Kali Linux'taki modern journalctl mimarisiyle tam uyumludur.
## Kurulum Adımları
Oluşturulan dosyaları sistemine entegre etmek için şu adımları takip edebilirsin:
1. Betik Dosyasını Düzenle ve Taşı:
Öncelikle ufw_telegram.py dosyasını açıp en üstteki TELEGRAM_TOKEN ve CHAT_ID alanlarına kendi Telegram bot bilgilerini yazmalısın. Ardından terminalde şu komutları çalıştır:

# Betiği sistemin çalıştırılabilir dizinine taşıyalım
sudo mv ufw_telegram.py /usr/local/bin/ufw_telegram.py
# Çalıştırma izni verelim
sudo chmod +x /usr/local/bin/ufw_telegram.py

2. Servis Dosyasını Tanımla:
Sistem arka planında (arka planda bir daemon olarak) sürekli çalışması için servis dosyasını taşıyalım:

sudo mv ufw-telegram.service /etc/systemd/system/ufw-telegram.service

3. Servisi Başlat ve Etkinleştir:
Sistem yöneticisine yeni servisi tanıtıp bilgisayar her açıldığında otomatik başlamasını sağlayalım:

# Sistem servis listesini yenile
sudo systemctl daemon-reload
# Servisi başlat
sudo systemctl start ufw-telegram.service
# Bilgisayar açılışına ekle
sudo systemctl enable ufw-telegram.service

## Durumu Nasıl Kontrol Edersin?
Yazdığın servisin şu an sorunsuz çalışıp çalışmadığını görmek için bu komutu kullanabilirsin:

sudo systemctl status ufw-telegram.service
