#!/usr/bin/env bash
# UFW Telegram Logger - etkileşimli kurulum / yönetim aracı (gum arayüzü)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DST="/usr/local/bin/ufw_telegram.py"
SVC_NAME="ufw-telegram.service"
SVC_DST="/etc/systemd/system/${SVC_NAME}"
CONF="/etc/ufw-telegram.conf"

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

    umask 077
    printf 'TELEGRAM_TOKEN=%s\nCHAT_ID=%s\n' "$token" "$chat" > "$CONF"
    chmod 600 "$CONF"; chown root:root "$CONF"
    ok "Yapılandırma kaydedildi: $CONF (600)"

    if systemctl is-active --quiet "$SVC_NAME"; then
        spin "Servis yeniden başlatılıyor..." systemctl restart "$SVC_NAME" && ok "Servis yeniden başlatıldı"
    fi
    pause
}

# ---------- Kurulum ----------
install_all() {
    header
    [[ -f "$SCRIPT_DIR/ufw_telegram.py" && -f "$SCRIPT_DIR/ufw-telegram.service" ]] \
        || { err "ufw_telegram.py / ufw-telegram.service bu dizinde bulunamadı"; pause; return 1; }

    check_deps || { pause; return 1; }
    check_ufw

    spin "Dosyalar kopyalanıyor..." bash -c "
        install -m 755 '$SCRIPT_DIR/ufw_telegram.py' '$BIN_DST' &&
        install -m 644 '$SCRIPT_DIR/ufw-telegram.service' '$SVC_DST'" \
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
    systemctl disable --now "$SVC_NAME" 2>/dev/null
    rm -f "$SVC_DST" "$BIN_DST"
    systemctl daemon-reload
    gum confirm --default=No "Yapılandırma ($CONF, token içerir) de silinsin mi?" && rm -f "$CONF"
    ok "Kaldırıldı"; pause
}

status() {
    header
    local f
    for f in "$BIN_DST" "$SVC_DST" "$CONF"; do
        [[ -e "$f" ]] && ok "$f" || err "$f yok"
    done
    systemctl is-enabled --quiet "$SVC_NAME" 2>/dev/null && ok "Açılışta başlar: evet" || warn "Açılışta başlar: hayır"
    systemctl is-active --quiet "$SVC_NAME" 2>/dev/null && ok "Servis: çalışıyor" || err "Servis: çalışmıyor"
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

# ---------- Menü ----------
main_menu() {
    while true; do
        header
        local choice
        choice=$(gum choose --cursor "▸ " --header "Bir işlem seçin:" \
            "Kur / Güncelle" "Yapılandır (Token & Chat ID)" "Durum" \
            "Test mesajı gönder" "Servis logları" "Başlat / Durdur" "Kaldır" "Çıkış") || exit 0
        case "$choice" in
            "Kur / Güncelle")               install_all ;;
            "Yapılandır (Token & Chat ID)") configure ;;
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
