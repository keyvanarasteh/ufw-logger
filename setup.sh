#!/usr/bin/env bash
# UFW Telegram Logger - etkileşimli kurulum / yönetim aracı (gum arayüzü)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DST="/usr/local/bin/ufw_telegram.py"
SVC_NAME="ufw-telegram.service"
SVC_DST="/etc/systemd/system/${SVC_NAME}"
CONF="/etc/ufw-telegram.conf"
AUDIT_DST="/usr/local/bin/ufw_audit.py"
AUDIT_SVC="ufw-telegram-audit.service"
AUDIT_TIMER="ufw-telegram-audit.timer"

# ---------- Yardımcılar ----------
die() { echo "HATA: $*" >&2; exit 1; }

# Root değilsek sudo ile yeniden başlat
if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null || die "root yetkisi gerekli (sudo bulunamadı)"
    exec sudo -E bash "$0" "$@"
fi

# ---------- gum kontrolü / kurulumu ----------
install_gum() {
    echo "gum bulunamadı, kuruluyor..."
    if command -v apt-get >/dev/null; then
        apt-get update -qq && apt-get install -y gum 2>/dev/null && return 0
        # Depoda yoksa Charm deposunu ekle
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://repo.charm.sh/apt/gpg.key | gpg --dearmor -o /etc/apt/keyrings/charm.gpg \
            && echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" \
                > /etc/apt/sources.list.d/charm.list \
            && apt-get update -qq && apt-get install -y gum && return 0
    elif command -v pacman >/dev/null; then
        pacman -S --noconfirm gum && return 0
    elif command -v dnf >/dev/null; then
        dnf install -y gum && return 0
    elif command -v brew >/dev/null; then
        brew install gum && return 0
    fi
    return 1
}

command -v gum >/dev/null || install_gum || die "gum kurulamadı: https://github.com/charmbracelet/gum"

# ---------- Arayüz ----------
ACCENT=212
header() {
    clear
    gum style --border double --border-foreground "$ACCENT" --padding "0 2" --margin "1 0" \
        --bold "🛡️  UFW → Telegram Logger" "Kurulum ve Yönetim"
}
ok()   { gum style --foreground 42  "✔ $*"; }
warn() { gum style --foreground 214 "! $*"; }
err()  { gum style --foreground 196 "✘ $*"; }
spin() { local title=$1; shift; gum spin --spinner dot --title "$title" --show-error -- "$@"; }
pause() { gum input --placeholder "Devam etmek için Enter..." >/dev/null || true; }

# ---------- Kontroller ----------
pkg_install() {
    if command -v apt-get >/dev/null; then apt-get install -y "$@"
    elif command -v pacman >/dev/null; then pacman -S --noconfirm "$@"
    elif command -v dnf >/dev/null; then dnf install -y "$@"
    else return 1; fi
}

check_deps() {
    local missing=()
    command -v python3 >/dev/null     || missing+=(python3)
    command -v journalctl >/dev/null  || { err "journalctl/systemd bulunamadı, desteklenmeyen sistem."; return 1; }
    command -v ufw >/dev/null         || missing+=(ufw)
    command -v curl >/dev/null        || missing+=(curl)
    python3 -c "import requests" 2>/dev/null || {
        if command -v apt-get >/dev/null; then missing+=(python3-requests); else missing+=(python3-requests); fi
    }

    if ((${#missing[@]})); then
        warn "Eksik paketler: ${missing[*]}"
        gum confirm "Şimdi kurulsun mu?" || return 1
        spin "Paketler kuruluyor..." pkg_install "${missing[@]}" || { err "Kurulum başarısız"; return 1; }
    fi
    ok "Bağımlılıklar tamam"
}

ufw_logging_level() { ufw status verbose 2>/dev/null | awk -F': ' '/^Logging/{print $2}'; }

check_ufw() {
    if ! ufw status 2>/dev/null | grep -q "Status: active"; then
        warn "UFW aktif değil."
        gum confirm "UFW etkinleştirilsin mi? (SSH bağlantınızı kesmemek için önce izin kuralınızı ekleyin)" \
            && { ufw enable && ok "UFW etkinleştirildi"; }
    else
        ok "UFW aktif"
    fi

    local lvl; lvl=$(ufw_logging_level)
    if [[ -z "$lvl" || "$lvl" == off* ]]; then
        warn "UFW loglama kapalı; bildirim için gerekli."
        local choice
        choice=$(gum choose --header "Loglama seviyesi:" low medium high full) || return 0
        ufw logging "$choice" && ok "Loglama: $choice"
    else
        ok "UFW loglama: $lvl"
    fi
}

# ---------- Telegram ----------
tg_test() {
    local token=$1 chat=$2 text=${3:-"✅ UFW Telegram Logger test mesajı"}
    curl -fsS -m 10 "https://api.telegram.org/bot${token}/sendMessage" \
        --data-urlencode "chat_id=${chat}" --data-urlencode "text=${text}" -o /dev/null
}

configure() {
    header
    gum style "Telegram bot bilgileri (@BotFather'dan token, @userinfobot'tan chat id alabilirsiniz)."
    local token chat
    token=$(gum input --password --prompt "Bot token › " --placeholder "123456:ABC...") || return 1
    chat=$(gum input --prompt "Chat ID   › " --placeholder "123456789") || return 1
    [[ -n "$token" && -n "$chat" ]] || { err "Token ve Chat ID boş olamaz"; pause; return 1; }

    if spin "Telegram bağlantısı test ediliyor..." bash -c "$(declare -f tg_test); tg_test '$token' '$chat'"; then
        ok "Test mesajı gönderildi"
    else
        err "Test mesajı gönderilemedi (token/chat id veya ağ hatalı)"
        gum confirm "Yine de kaydedilsin mi?" || { pause; return 1; }
    fi

    conf_set TELEGRAM_TOKEN "$token"
    conf_set CHAT_ID "$chat"
    ensure_filter_defaults
    ok "Yapılandırma kaydedildi: $CONF (600)"

    restart_if_active
    pause
}

# ---------- Bildirim profilleri / filtreler ----------
# Yapılandırma dosyasında tek bir anahtarı güncelle (yoksa ekle); diğerlerini korur.
conf_set() {
    local key=$1 val=$2
    ( umask 077; touch "$CONF" )
    if grep -q "^${key}=" "$CONF"; then
        sed -i "s|^${key}=.*|${key}=${val//|/\\|}|" "$CONF"
    else
        printf '%s=%s\n' "$key" "$val" >> "$CONF"
    fi
    chmod 600 "$CONF"; chown root:root "$CONF"
}

conf_get() { [[ -f "$CONF" ]] && grep "^$1=" "$CONF" | head -1 | cut -d= -f2-; }

restart_if_active() {
    if systemctl is-active --quiet "$SVC_NAME"; then
        spin "Servis yeniden başlatılıyor..." systemctl restart "$SVC_NAME" && ok "Servis yeniden başlatıldı"
    fi
}

CRIT_PORTS_DEFAULT="22,23,3389,445,3306,5432,6379,27017,5900"
NOISE_PORTS_DEFAULT="53,5353,1900,137,138,67,68"

# Ortak filtre ayarları (tüm profillerde)
profile_base() {
    conf_set CRITICAL_PORTS "$CRIT_PORTS_DEFAULT"
    conf_set IGNORE_PORTS "$NOISE_PORTS_DEFAULT"
    conf_set INBOUND_ONLY 1
    conf_set IGNORE_BROADCAST 1
    conf_set IGNORE_PRIVATE_SRC 0
    conf_set SHOW_HOSTNAME 1
    conf_set SUMMARY_HOURS 0
}

profile_block() {      # Engelleme uyarıları: sadece BLOCK, ALLOW yok
    profile_base
    conf_set NOTIFY_ACTIONS BLOCK
    conf_set ONLY_CRITICAL 0
    conf_set DEDUP_SECONDS 60
    conf_set RATE_LIMIT_PER_MIN 20
    conf_set SCAN_DETECT 1
}

profile_critical() {   # Kritik uyarılar: sadece kritik portlar (BLOCK ve ALLOW)
    profile_base
    conf_set NOTIFY_ACTIONS BLOCK,ALLOW
    conf_set ONLY_CRITICAL 1
    conf_set DEDUP_SECONDS 30
    conf_set RATE_LIMIT_PER_MIN 10
    conf_set SCAN_DETECT 1
}

# Yapılandırmada filtre ayarı yoksa varsayılan (sadece BLOCK) uygula
ensure_filter_defaults() {
    [[ -n "$(conf_get NOTIFY_ACTIONS)" ]] || profile_block
}

profile_checklist() {  # Profesyonel log sistemi kontrol listesi
    local items=(
        "ALLOW (izin verilen) olayları da bildir"
        "Sadece gelen trafik (giden/forward hariç)"
        "Sadece kritik portlar (SSH / RDP / SMB / DB)"
        "Gürültüyü yoksay (DNS / mDNS / SSDP / NetBIOS / DHCP)"
        "Broadcast / multicast trafiğini yoksay"
        "Yerel ağ (özel IP) kaynaklarını yoksay"
        "Tekrar eden olayları birleştir (60 sn)"
        "Hız sınırı (dakikada en fazla 20 mesaj)"
        "Port tarama tespiti (60 sn'de 10+ port)"
        "Mesajlara sunucu adını ekle"
        "Günlük özet raporu (24 saatte bir)"
    )
    local cur_actions cur_inb cur_crit cur_dedup cur_rate cur_scan cur_host cur_sum cur_priv cur_bc cur_noise
    cur_actions=$(conf_get NOTIFY_ACTIONS); cur_inb=$(conf_get INBOUND_ONLY)
    cur_crit=$(conf_get ONLY_CRITICAL);     cur_dedup=$(conf_get DEDUP_SECONDS)
    cur_rate=$(conf_get RATE_LIMIT_PER_MIN); cur_scan=$(conf_get SCAN_DETECT)
    cur_host=$(conf_get SHOW_HOSTNAME);     cur_sum=$(conf_get SUMMARY_HOURS)
    cur_priv=$(conf_get IGNORE_PRIVATE_SRC); cur_bc=$(conf_get IGNORE_BROADCAST)
    cur_noise=$(conf_get IGNORE_PORTS)

    # Mevcut duruma göre önceden işaretle (yoksa güvenli varsayılanlar)
    local sel=()
    [[ "$cur_actions" == *ALLOW* ]]                  && sel+=("${items[0]}")
    [[ "${cur_inb:-1}" == 1 ]]                       && sel+=("${items[1]}")
    [[ "${cur_crit:-0}" == 1 ]]                      && sel+=("${items[2]}")
    [[ -n "${cur_noise-$NOISE_PORTS_DEFAULT}" ]]     && sel+=("${items[3]}")
    [[ "${cur_bc:-1}" == 1 ]]                        && sel+=("${items[4]}")
    [[ "${cur_priv:-0}" == 1 ]]                      && sel+=("${items[5]}")
    [[ "${cur_dedup:-60}" -gt 0 ]]                   && sel+=("${items[6]}")
    [[ "${cur_rate:-20}" -gt 0 ]]                    && sel+=("${items[7]}")
    [[ "${cur_scan:-1}" == 1 ]]                      && sel+=("${items[8]}")
    [[ "${cur_host:-1}" == 1 ]]                      && sel+=("${items[9]}")
    [[ "${cur_sum:-0}" -gt 0 ]]                      && sel+=("${items[10]}")

    local selected_csv; selected_csv=$(IFS=,; echo "${sel[*]}")
    local picked
    picked=$(gum choose --no-limit --height 14 --selected="$selected_csv" \
        --header "Kontrol listesi (Space: işaretle, Enter: onayla):" "${items[@]}") || return 1

    has() { grep -qxF "$1" <<<"$picked"; }
    local v
    has "${items[0]}"  && conf_set NOTIFY_ACTIONS BLOCK,ALLOW || conf_set NOTIFY_ACTIONS BLOCK
    has "${items[1]}"  && v=1 || v=0; conf_set INBOUND_ONLY $v
    has "${items[2]}"  && v=1 || v=0; conf_set ONLY_CRITICAL $v
    has "${items[3]}"  && conf_set IGNORE_PORTS "$NOISE_PORTS_DEFAULT" || conf_set IGNORE_PORTS ""
    has "${items[4]}"  && v=1 || v=0; conf_set IGNORE_BROADCAST $v
    has "${items[5]}"  && v=1 || v=0; conf_set IGNORE_PRIVATE_SRC $v
    has "${items[6]}"  && conf_set DEDUP_SECONDS 60 || conf_set DEDUP_SECONDS 0
    has "${items[7]}"  && conf_set RATE_LIMIT_PER_MIN 20 || conf_set RATE_LIMIT_PER_MIN 0
    has "${items[8]}"  && v=1 || v=0; conf_set SCAN_DETECT $v
    has "${items[9]}"  && v=1 || v=0; conf_set SHOW_HOSTNAME $v
    has "${items[10]}" && conf_set SUMMARY_HOURS 24 || conf_set SUMMARY_HOURS 0
    conf_set CRITICAL_PORTS "${CRIT_PORTS_DEFAULT}"
}

edit_critical_ports() {
    local cur; cur=$(conf_get CRITICAL_PORTS)
    local new
    new=$(gum input --prompt "Kritik portlar › " --value "${cur:-$CRIT_PORTS_DEFAULT}" \
        --placeholder "22,3389,445") || return 0
    new=${new// /}
    [[ "$new" =~ ^[0-9]+(,[0-9]+)*$ ]] && conf_set CRITICAL_PORTS "$new" || err "Geçersiz port listesi, değiştirilmedi"
}

show_profile() {
    local k
    for k in NOTIFY_ACTIONS ONLY_CRITICAL CRITICAL_PORTS INBOUND_ONLY IGNORE_PORTS IGNORE_BROADCAST \
             IGNORE_PRIVATE_SRC DEDUP_SECONDS RATE_LIMIT_PER_MIN SCAN_DETECT SHOW_HOSTNAME SUMMARY_HOURS; do
        printf '%-20s %s\n' "$k" "$(conf_get "$k")"
    done
}

filters_menu() {
    [[ -f "$CONF" ]] || { header; err "Önce Token & Chat ID yapılandırın"; pause; return; }
    ensure_filter_defaults
    while true; do
        header
        gum style --foreground 244 "Varsayılan: sadece BLOCK bildirilir, ALLOW bildirilmez."
        local choice
        choice=$(gum choose --cursor "▸ " --header "Bildirim profili:" \
            "🛑 Engelleme uyarıları (sadece BLOCK)" \
            "🚨 Kritik uyarılar (sadece kritik portlar)" \
            "☑  Profesyonel log kontrol listesi (özel)" \
            "Kritik port listesini düzenle" \
            "Mevcut ayarları göster" \
            "← Geri") || return
        case "$choice" in
            "🛑"*) profile_block;    ok "Engelleme uyarıları profili uygulandı"; restart_if_active; pause ;;
            "🚨"*) profile_critical; ok "Kritik uyarılar profili uygulandı";     restart_if_active; pause ;;
            "☑"*)  profile_checklist && { ok "Kontrol listesi uygulandı"; restart_if_active; }; pause ;;
            "Kritik port"*) edit_critical_ports; restart_if_active; pause ;;
            "Mevcut"*) header; show_profile; pause ;;
            *) return ;;
        esac
    done
}

# ---------- Kurulum ----------
install_all() {
    header
    local f
    for f in ufw_telegram.py ufw_audit.py "$SVC_NAME" "$AUDIT_SVC" "$AUDIT_TIMER"; do
        [[ -f "$SCRIPT_DIR/$f" ]] || { err "$f bu dizinde bulunamadı"; pause; return 1; }
    done

    check_deps || { pause; return 1; }
    check_ufw

    spin "Dosyalar kopyalanıyor..." bash -c "
        install -m 755 '$SCRIPT_DIR/ufw_telegram.py' '$BIN_DST' &&
        install -m 755 '$SCRIPT_DIR/ufw_audit.py' '$AUDIT_DST' &&
        install -m 644 '$SCRIPT_DIR/ufw-telegram.service' '$SVC_DST' &&
        install -m 644 '$SCRIPT_DIR/$AUDIT_SVC' '/etc/systemd/system/$AUDIT_SVC' &&
        install -m 644 '$SCRIPT_DIR/$AUDIT_TIMER' '/etc/systemd/system/$AUDIT_TIMER'" \
        && ok "Dosyalar yerleştirildi" || { err "Kopyalama başarısız"; pause; return 1; }

    if [[ -f "$CONF" ]] && ! gum confirm "Mevcut yapılandırma var. Yeniden yapılandırılsın mı?"; then
        ok "Mevcut yapılandırma korundu"
    else
        configure
    fi
    [[ -f "$CONF" ]] || { err "Yapılandırma yok, servis başlatılmadı"; pause; return 1; }

    spin "Servis etkinleştiriliyor..." bash -c "
        systemctl daemon-reload && systemctl enable '$SVC_NAME' && systemctl restart '$SVC_NAME'"
    sleep 1
    if systemctl is-active --quiet "$SVC_NAME"; then
        ok "Servis çalışıyor"
    else
        err "Servis başlamadı"; journalctl -u "$SVC_NAME" -n 15 --no-pager
    fi
    pause
}

uninstall_all() {
    header
    gum confirm --default=No "Servis ve dosyalar kaldırılsın mı?" || return 0
    systemctl disable --now "$SVC_NAME" "$AUDIT_TIMER" 2>/dev/null
    rm -f "$SVC_DST" "$BIN_DST" "$AUDIT_DST" "/etc/systemd/system/$AUDIT_SVC" "/etc/systemd/system/$AUDIT_TIMER"
    rm -rf /var/lib/ufw-telegram
    systemctl daemon-reload
    gum confirm --default=No "Yapılandırma ($CONF, token içerir) de silinsin mi?" && rm -f "$CONF"
    ok "Kaldırıldı"; pause
}

status() {
    header
    local f
    for f in "$BIN_DST" "$AUDIT_DST" "$SVC_DST" "$CONF"; do
        [[ -e "$f" ]] && ok "$f" || err "$f yok"
    done
    systemctl is-enabled --quiet "$SVC_NAME" 2>/dev/null && ok "Açılışta başlar: evet" || warn "Açılışta başlar: hayır"
    systemctl is-active --quiet "$SVC_NAME" 2>/dev/null && ok "Servis: çalışıyor" || err "Servis: çalışmıyor"
    systemctl is-active --quiet "$AUDIT_TIMER" 2>/dev/null && ok "Günlük kural denetimi: açık" || warn "Günlük kural denetimi: kapalı"
    command -v ufw >/dev/null && echo "UFW: $(ufw status | head -1) | Loglama: $(ufw_logging_level)"
    echo
    systemctl status "$SVC_NAME" --no-pager -n 10 2>/dev/null | head -20
    pause
}

send_test() {
    header
    [[ -f "$CONF" ]] || { err "Önce yapılandırın"; pause; return; }
    # shellcheck disable=SC1090
    set -a; source "$CONF"; set +a
    spin "Test mesajı gönderiliyor..." bash -c "$(declare -f tg_test); tg_test '$TELEGRAM_TOKEN' '$CHAT_ID'" \
        && ok "Gönderildi" || err "Gönderilemedi"
    pause
}

view_logs() {
    header
    journalctl -u "$SVC_NAME" -n 50 --no-pager | gum pager
}

# ---------- Kural seti denetimi ----------
# Depodaki sürüm varsa onu, yoksa kurulu olanı kullan
audit_bin() {
    if [[ -f "$SCRIPT_DIR/ufw_audit.py" ]]; then echo "$SCRIPT_DIR/ufw_audit.py"
    elif [[ -f "$AUDIT_DST" ]]; then echo "$AUDIT_DST"
    else return 1; fi
}

audit_run() { python3 "$(audit_bin)" "$@"; }

audit_apply() {
    header
    audit_run --no-color | sed -n '/^SIRALAMA PERFORMANSI/,$p'
    echo
    gum style --foreground 244 \
        "Yalnızca kesişmeyen kurallar yer değiştirir: hiçbir paketin izin/ret kararı değişmez." \
        "Kural dosyaları yedeklenir, UFW yeniden yüklenir; hata olursa otomatik geri alınır." \
        "Güvenlik bulguları (KISMI-ETKISIZ, GOLGELEME vb.) otomatik düzeltilmez; onları siz karara bağlayın."
    gum confirm --default=No "Önerilen sıra uygulansın mı?" || return 0
    audit_run --quiet --apply --yes
    pause
}

audit_timer_toggle() {
    [[ -f "/etc/systemd/system/$AUDIT_TIMER" ]] || { err "Önce 'Kur / Güncelle' çalıştırın"; pause; return; }
    if systemctl is-active --quiet "$AUDIT_TIMER"; then
        systemctl disable --now "$AUDIT_TIMER" && warn "Günlük denetim kapatıldı"
    else
        systemctl daemon-reload
        systemctl enable --now "$AUDIT_TIMER" && ok "Günlük denetim açıldı (bulgular değişirse Telegram'a bildirilir)"
    fi
    pause
}

audit_menu() {
    audit_bin >/dev/null || { header; err "ufw_audit.py bulunamadı"; pause; return; }
    while true; do
        header
        gum style --foreground 244 "Sıralama performansı, çakışan/etkisiz kurallar ve güvenlik denetimi."
        local choice secs
        choice=$(gum choose --cursor "▸ " --header "Kural seti denetimi:" \
            "Denetimi çalıştır" \
            "Ayrıntılı rapor (tüm notlar)" \
            "Trafiği örnekle ve analiz et" \
            "Önerilen sırayı uygula" \
            "Raporu Telegram'a gönder" \
            "Günlük otomatik denetim (aç / kapat)" \
            "← Geri") || return
        case "$choice" in
            "Denetimi"*)   audit_run --no-color | gum pager ;;
            "Ayrıntılı"*)  audit_run --no-color --verbose | gum pager ;;
            "Trafiği"*)
                secs=$(gum input --prompt "Süre (sn) › " --value 60) || continue
                [[ "$secs" =~ ^[0-9]+$ ]] || { err "Geçersiz süre"; pause; continue; }
                # Kısa pencerede paket az olur: eşik düşük tutulur, sonucu buna göre yorumlayın
                audit_run --no-color --sample "$secs" --min-packets 100 | gum pager ;;
            "Önerilen"*)   audit_apply ;;
            "Raporu"*)     audit_run --quiet --notify && ok "Gönderildi" || err "Gönderilemedi"; pause ;;
            "Günlük"*)     audit_timer_toggle ;;
            *) return ;;
        esac
    done
}

# ---------- Menü ----------
main_menu() {
    while true; do
        header
        local choice
        choice=$(gum choose --cursor "▸ " --header "Bir işlem seçin:" \
            "Kur / Güncelle" "Yapılandır (Token & Chat ID)" "Bildirim profili & filtreler" \
            "Kural seti denetimi & optimizasyon" "Durum" \
            "Test mesajı gönder" "Servis logları" "Başlat / Durdur" "Kaldır" "Çıkış") || exit 0
        case "$choice" in
            "Kur / Güncelle")               install_all ;;
            "Yapılandır (Token & Chat ID)") configure ;;
            "Bildirim profili & filtreler") filters_menu ;;
            "Kural seti denetimi & optimizasyon") audit_menu ;;
            "Durum")                        status ;;
            "Test mesajı gönder")           send_test ;;
            "Servis logları")               view_logs ;;
            "Başlat / Durdur")
                if systemctl is-active --quiet "$SVC_NAME"; then systemctl stop "$SVC_NAME"; warn "Durduruldu"
                else systemctl start "$SVC_NAME"; ok "Başlatıldı"; fi
                sleep 1 ;;
            "Kaldır")                       uninstall_all ;;
            *)                              exit 0 ;;
        esac
    done
}

main_menu
