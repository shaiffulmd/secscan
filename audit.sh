#!/usr/bin/env bash
# ==============================================================================
#  SecScan Server Audit — semakan keselamatan untuk pelayan Ubuntu/Debian
# ------------------------------------------------------------------------------
#  Guna:
#     sudo bash audit.sh                 # terminal + laporan HTML
#     sudo bash audit.sh --no-html       # terminal sahaja
#     sudo bash audit.sh -o /path.html   # tetapkan lokasi laporan
#     bash audit.sh --help               # semua pilihan & kod keluar
#
#  Skrip ini READ-ONLY: ia hanya membaca konfigurasi dan tidak mengubah apa-apa
#  pada sistem. Jalankan sebagai root/sudo untuk keputusan paling lengkap.
# ==============================================================================

set -u -o pipefail

# ---------- Tetapan ----------
SCRIPT_VERSION="1.1.0"
HTML_OUT=""
MAKE_HTML=1
USE_COLOR=1

usage() {
  cat <<'USAGE'
SecScan Server Audit — semakan keselamatan read-only untuk Ubuntu/Debian

Penggunaan:
  sudo bash audit.sh [pilihan]

Pilihan:
  -o, --output FAIL   Simpan laporan HTML ke FAIL
      --no-html       Jangan jana laporan HTML
      --no-color      Matikan warna terminal
      --version       Papar versi
  -h, --help          Papar bantuan

Kod keluar:
  0  Tiada amaran/kritikal    1  Ada amaran
  2  Ada penemuan kritikal    64 Penggunaan tidak sah
  73 Laporan HTML tidak dapat dicipta
USAGE
}

die_usage() {
  printf 'Ralat: %s\n\n' "$1" >&2
  usage >&2
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-html)      MAKE_HTML=0 ;;
    --no-color)     USE_COLOR=0 ;;
    --version)      printf 'SecScan Server Audit %s\n' "$SCRIPT_VERSION"; exit 0 ;;
    -o=*|--output=*)
      HTML_OUT="${1#*=}"
      [ -n "$HTML_OUT" ] || die_usage "$1 memerlukan nama fail" ;;
    -o|--output)
      [ "$#" -ge 2 ] || die_usage "$1 memerlukan nama fail"
      [ -n "$2" ] || die_usage "$1 memerlukan nama fail"
      [[ "$2" != -* ]] || die_usage "$1 memerlukan nama fail sebelum pilihan seterusnya"
      HTML_OUT="$2"; shift ;;
    -h|--help)      usage; exit 0 ;;
    --)             shift; [ "$#" -eq 0 ] || die_usage "Argumen kedudukan tidak disokong: $1"; break ;;
    -*)             die_usage "Pilihan tidak dikenali: $1" ;;
    *)              die_usage "Argumen kedudukan tidak disokong: $1" ;;
  esac
  shift
done

SHORT_HOST="$(hostname -s 2>/dev/null || printf 'server')"
SAFE_HOST="$(printf '%s' "$SHORT_HOST" | tr -c '[:alnum:]._-' '_')"
[ -n "$SAFE_HOST" ] || SAFE_HOST="server"
if [ "$MAKE_HTML" -eq 0 ]; then
  [ -z "$HTML_OUT" ] || die_usage "--output tidak boleh digabungkan dengan --no-html"
else
  [ -z "$HTML_OUT" ] && HTML_OUT="secscan-audit-${SAFE_HOST}-$(date +%Y%m%d-%H%M%S).html"
  [ "$HTML_OUT" != "-" ] || die_usage "Gunakan nama fail untuk --output; output terminal menggunakan stdout"
fi

# ---------- Warna terminal ----------
if [ -t 1 ] && [ "$USE_COLOR" -eq 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[38;5;167m'; C_GRN=$'\033[38;5;71m'
  C_YEL=$'\033[38;5;179m'; C_BLU=$'\033[38;5;74m'; C_CLAY=$'\033[38;5;173m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CLAY=""
fi

# ---------- Kaunter & simpanan keputusan ----------
N_CRIT=0; N_WARN=0; N_INFO=0; N_PASS=0
REPORT_ERROR=0
declare -a ROW_SEVS=() ROW_CATS=() ROW_TITLES=() ROW_DETAILS=() ROW_RECS=()
HTML_TMP=""

cleanup() {
  [ -z "${HTML_TMP:-}" ] || rm -f -- "$HTML_TMP"
}
trap cleanup EXIT

now_iso() { date '+%Y-%m-%d %H:%M:%S %Z'; }

# Rekod satu penemuan
record() {
  local sev="$1" cat="$2" title="$3" detail="$4" rec="$5"
  case "$sev" in
    critical) N_CRIT=$((N_CRIT+1)) ;;
    warning)  N_WARN=$((N_WARN+1)) ;;
    pass)     N_PASS=$((N_PASS+1)) ;;
    *)        N_INFO=$((N_INFO+1)) ;;
  esac
  ROW_SEVS+=("$sev")
  ROW_CATS+=("$cat")
  ROW_TITLES+=("$title")
  ROW_DETAILS+=("$detail")
  ROW_RECS+=("$rec")

  local tag color
  case "$sev" in
    critical) tag="KRITIKAL"; color="$C_RED" ;;
    warning)  tag="AMARAN  "; color="$C_YEL" ;;
    pass)     tag="LULUS   "; color="$C_GRN" ;;
    *)        tag="INFO    "; color="$C_BLU" ;;
  esac
  printf '  %s%s%s  %s%s%s\n' "$color" "$tag" "$C_RESET" "$C_BOLD" "$title" "$C_RESET"
  [ -n "$detail" ] && printf '            %s%s%s\n' "$C_DIM" "$detail" "$C_RESET"
  [ -n "$rec" ] && printf '            %s→ %s%s\n' "$C_CLAY" "$rec" "$C_RESET"
  return 0
}

section() { printf '\n%s%s══ %s%s\n' "$C_BOLD" "$C_CLAY" "$1" "$C_RESET"; }
has() { command -v "$1" >/dev/null 2>&1; }
service_is_active() { has systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }

# ==============================================================================
#  Header
# ==============================================================================
OS_NAME="$(if [ -r /etc/os-release ]; then . /etc/os-release; fi; printf '%s' "${PRETTY_NAME:-Unknown OS}")"
KERNEL="$(uname -r)"
HOSTN="$(hostname -f 2>/dev/null || hostname)"
IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1

printf '%s%s' "$C_BOLD" "$C_CLAY"
cat <<'BANNER'
   ____             ____
  / ___|  ___  ___/ ___|  ___ __ _ _ __
  \___ \ / _ \/ __\___ \ / __/ _` | '_ \
   ___) |  __/ (__ ___) | (_| (_| | | | |
  |____/ \___|\___|____/ \___\__,_|_| |_|
BANNER
printf '%s' "$C_RESET"
printf '  %sServer Security Audit v%s%s\n' "$C_DIM" "$SCRIPT_VERSION" "$C_RESET"
printf '  Host   : %s\n' "$HOSTN"
printf '  OS     : %s (kernel %s)\n' "$OS_NAME" "$KERNEL"
printf '  Masa   : %s\n' "$(now_iso)"
if [ "$IS_ROOT" -eq 0 ]; then
  printf '  %s⚠ Tidak dijalankan sebagai root — sesetengah semakan mungkin tidak lengkap.%s\n' "$C_YEL" "$C_RESET"
fi

# ==============================================================================
#  1. Kemas kini sistem
# ==============================================================================
section "Kemas kini & patch"
if has apt-get; then
  APT_SIM="$(LC_ALL=C apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null)" || APT_SIM=""
  if [ -z "$APT_SIM" ]; then
    record info "Kemas kini" "Status pakej tidak dapat disemak" "Simulasi apt gagal atau cache pakej tidak tersedia." "Jalankan 'sudo apt update', kemudian audit semula."
    UPD=0; SEC=0
  else
    UPD="$(printf '%s\n' "$APT_SIM" | awk '/^Inst /{n++} END{print n+0}')"
    SEC="$(printf '%s\n' "$APT_SIM" | awk 'BEGIN{IGNORECASE=1} /^Inst / && /security/{n++} END{print n+0}')"
  fi
  if [ -n "$APT_SIM" ] && [ "$UPD" -eq 0 ]; then
    record pass "Kemas kini" "Sistem terkini" "Tiada pakej menunggu kemas kini." ""
  elif [ "$SEC" -gt 0 ]; then
    record critical "Kemas kini" "$SEC kemas kini keselamatan tertunggak" "$UPD pakej boleh dikemas kini ($SEC berkaitan keselamatan)." "Jalankan: sudo apt update && sudo apt upgrade. Pertimbang unattended-upgrades."
  elif [ "$UPD" -gt 0 ]; then
    record warning "Kemas kini" "$UPD pakej belum dikemas kini" "Tiada yang dikelaskan keselamatan, tetapi elok dikemas kini." "Jalankan: sudo apt update && sudo apt upgrade."
  fi
  if dpkg -l 2>/dev/null | grep '^ii  unattended-upgrades' >/dev/null; then
    if has apt-config && apt-config dump 2>/dev/null | grep -E 'APT::Periodic::Unattended-Upgrade "?1"?;' >/dev/null; then
      record pass "Kemas kini" "Kemas kini automatik aktif" "unattended-upgrades dipasang dan dijadualkan." ""
    else
      record warning "Kemas kini" "unattended-upgrades belum diaktifkan" "Pakej dipasang tetapi jadual automatik tidak dapat disahkan." "Jalankan: sudo dpkg-reconfigure unattended-upgrades."
    fi
  else
    record warning "Kemas kini" "Tiada kemas kini automatik" "unattended-upgrades tidak dipasang." "Pasang: sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades."
  fi
  if [ -f /var/run/reboot-required ]; then
    record warning "Kemas kini" "Reboot diperlukan" "Kernel/pustaka dikemas kini tetapi belum aktif." "Jadualkan reboot: sudo reboot."
  fi
else
  record info "Kemas kini" "Pengurus pakej bukan apt" "Semakan kemas kini dilangkau." "Semak manual mengikut distro anda."
fi

# ==============================================================================
#  2. Firewall
# ==============================================================================
section "Firewall"
if has ufw && ufw status 2>/dev/null | grep -i '^Status: active' >/dev/null; then
  record pass "Firewall" "UFW aktif" "Firewall UFW sedang berjalan." ""
elif has firewall-cmd && firewall-cmd --state 2>/dev/null | grep -i '^running' >/dev/null; then
  record pass "Firewall" "firewalld aktif" "firewalld sedang berjalan." ""
elif has nft && nft list ruleset 2>/dev/null | grep -E 'hook[[:space:]]+input|type[[:space:]]+filter' >/dev/null; then
  record info "Firewall" "Peraturan nftables dikesan" "Ruleset dengan rantaian input/filter dikesan; keberkesanan polisinya perlu disemak." "Sahkan polisi lalai dan ruleset: sudo nft list ruleset."
elif has iptables && iptables -S 2>/dev/null | grep -E '^-P (INPUT|FORWARD) (DROP|REJECT)|^-A (INPUT|FORWARD) .+ -j (DROP|REJECT)' >/dev/null; then
  record info "Firewall" "Peraturan iptables dikesan" "Polisi atau peraturan sekatan input dikesan; liputan penuh perlu disemak." "Sahkan ruleset: sudo iptables -S."
elif [ "$IS_ROOT" -eq 0 ]; then
  record warning "Firewall" "Status firewall tidak dapat disahkan" "Audit tanpa root mungkin tidak boleh membaca ruleset nftables/iptables." "Jalankan semula dengan sudo."
elif has ufw; then
  record critical "Firewall" "UFW tidak aktif" "UFW dipasang tetapi tidak dihidupkan, dan tiada ruleset lain dikesan." "Hidupkan: sudo ufw enable (pastikan port SSH dibenarkan dahulu)."
elif has firewall-cmd; then
  record critical "Firewall" "firewalld tidak aktif" "firewalld dipasang tetapi tidak berjalan, dan tiada ruleset lain dikesan." "Hidupkan: sudo systemctl enable --now firewalld."
else
  record critical "Firewall" "Tiada firewall dikesan" "Tiada UFW, firewalld, atau peraturan iptables menyekat." "Pasang & konfigur UFW: sudo apt install ufw && sudo ufw default deny incoming && sudo ufw allow OpenSSH && sudo ufw enable."
fi

# ==============================================================================
#  3. SSH
# ==============================================================================
section "Konfigurasi SSH"
SSHD=/etc/ssh/sshd_config
SSH_EFFECTIVE=""
if [ -r "$SSHD" ] && has sshd; then
  SSH_EFFECTIVE="$(sshd -T -C "user=root,host=${HOSTN},addr=127.0.0.1" 2>/dev/null)" || SSH_EFFECTIVE=""
fi
sshget() { # baca nilai efektif direktif; args: nama, nilai lalai pilihan
  local key="$1" default="${2:-}"
  local key_lc value=""
  key_lc="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')"
  if [ -n "$SSH_EFFECTIVE" ]; then
    value="$(printf '%s\n' "$SSH_EFFECTIVE" | awk -v key="$key_lc" '$1 == key {print tolower($2); exit}')"
  elif [ -r "$SSHD" ]; then
    # Fallback konservatif. sshd -T diutamakan kerana ia memproses Include/Match dan nilai lalai.
    value="$(awk -v key="$key_lc" 'tolower($1) == key {print tolower($2); exit}' "$SSHD" 2>/dev/null)"
  fi
  printf '%s' "${value:-$default}"
}
if [ -r "$SSHD" ]; then
  PRL="$(sshget PermitRootLogin prohibit-password)"
  if [ "$PRL" = "no" ]; then
    record pass "SSH" "Log masuk root dimatikan" "PermitRootLogin = no." ""
  elif [ "$PRL" = "prohibit-password" ]; then
    record warning "SSH" "Root masih boleh masuk dengan kunci" "PermitRootLogin = prohibit-password." "Pertimbang 'PermitRootLogin no' dan gunakan akaun pentadbir berasingan dengan sudo."
  else
    record critical "SSH" "Log masuk root SSH dibenarkan" "PermitRootLogin = $PRL." "Set 'PermitRootLogin no' dalam $SSHD, uji 'sudo sshd -t', kemudian muat semula SSH."
  fi

  PWA="$(sshget PasswordAuthentication yes)"
  if [ "$PWA" = "no" ]; then
    record pass "SSH" "Pengesahan kata laluan dimatikan" "Direktif PasswordAuthentication = no." ""
  else
    record warning "SSH" "Pengesahan kata laluan dibenarkan" "PasswordAuthentication = $PWA." "Guna kunci SSH dan set 'PasswordAuthentication no' untuk halang brute-force."
  fi

  KBD="$(sshget KbdInteractiveAuthentication yes)"
  if [ "$KBD" = "yes" ]; then
    record warning "SSH" "Pengesahan interaktif dibenarkan" "KbdInteractiveAuthentication = yes; ini boleh membenarkan cabaran kata laluan/PAM." "Set 'KbdInteractiveAuthentication no' jika tidak menggunakan MFA berasaskan PAM."
  fi

  SSHPORT="$(sshget Port 22)"
  record info "SSH" "Port SSH: ${SSHPORT}" "SSH mendengar pada port ${SSHPORT}." "$( [ "$SSHPORT" = "22" ] && echo 'Menukar port bukan langkah keselamatan sebenar, tetapi mengurangkan bising log.' )"

  if [ "$(sshget X11Forwarding yes)" = "yes" ]; then
    record warning "SSH" "X11Forwarding dihidupkan" "Boleh membuka permukaan serangan tidak perlu." "Set 'X11Forwarding no' jika tidak diperlukan."
  fi

  MAXAUTH="$(sshget MaxAuthTries 6)"
  if [[ "$MAXAUTH" =~ ^[0-9]+$ ]] && [ "$MAXAUTH" -gt 4 ]; then
    record warning "SSH" "MaxAuthTries tinggi ($MAXAUTH)" "Lebih banyak cubaan dibenarkan bagi setiap sambungan SSH." "Pertimbang 'MaxAuthTries 3' atau 4, kemudian uji konfigurasi sebelum reload."
  fi
else
  record info "SSH" "sshd_config tidak dibaca" "Tiada akses baca ke $SSHD (mungkin bukan root, atau SSH tidak dipasang)." "Jalankan sebagai sudo untuk semakan penuh."
fi

# ==============================================================================
#  4. Pengguna & pengesahan
# ==============================================================================
section "Pengguna & akaun"
EMPTY_PW="$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)"
if [ -n "$EMPTY_PW" ]; then
  record critical "Pengguna" "Akaun tanpa kata laluan" "Akaun: $(echo "$EMPTY_PW" | tr '\n' ' ')" "Kunci akaun: sudo passwd -l <user>, atau tetapkan kata laluan kukuh."
elif [ -r /etc/shadow ]; then
  record pass "Pengguna" "Tiada akaun kosong kata laluan" "Semua akaun ada kata laluan atau dikunci." ""
fi

UID0="$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null | grep -v '^root$')"
if [ -n "$UID0" ]; then
  record critical "Pengguna" "Akaun UID 0 tambahan" "Selain root: $(echo "$UID0" | tr '\n' ' ')" "Akaun UID 0 = akses root penuh. Siasat & keluarkan jika tidak sah."
else
  record pass "Pengguna" "Hanya root ber-UID 0" "Tiada akaun superuser tersembunyi." ""
fi

SUDOERS_NOPW="$(grep -rhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | sed 's/[[:space:]]*#.*$//' | grep -E 'NOPASSWD')"
if [ -n "$SUDOERS_NOPW" ]; then
  record warning "Pengguna" "sudo tanpa kata laluan" "Ada peraturan NOPASSWD dalam sudoers." "Semak /etc/sudoers.d/. Elakkan NOPASSWD kecuali benar-benar perlu."
fi

# ==============================================================================
#  5. Port & perkhidmatan mendengar
# ==============================================================================
section "Port terbuka & perkhidmatan"
if has ss; then
  LISTEN="$(ss -H -lntu 2>/dev/null)"
  PUBLIC="$(printf '%s\n' "$LISTEN" | awk '
    {
      addr=$5
      if (addr ~ /^0\.0\.0\.0:/ || addr ~ /^\[::\]:/ || addr ~ /^\*:/) {
        sub(/^.*:/, "", addr)
        if (addr ~ /^[0-9]+$/) print addr
      }
    }' | sort -un | tr '\n' ' ')"
elif has netstat; then
  LISTEN="$(netstat -tuln 2>/dev/null | tail -n +3)"
  PUBLIC="$(printf '%s\n' "$LISTEN" | awk '
    {
      addr=$4
      if (addr ~ /^0\.0\.0\.0:/ || addr ~ /^:::/ || addr ~ /^\*:/) {
        sub(/^.*:/, "", addr)
        if (addr ~ /^[0-9]+$/) print addr
      }
    }' | sort -un | tr '\n' ' ')"
else
  LISTEN=""; PUBLIC=""
fi
if [ -n "$LISTEN" ]; then
  NPUB="$(echo "$PUBLIC" | wc -w | tr -d ' ')"
  record info "Rangkaian" "${NPUB} port mendengar pada semua antaramuka" "Port: ${PUBLIC:-tiada}" "Semak sama ada setiap port diperlukan dan benar-benar dibenarkan oleh firewall. Bind semua antaramuka tidak semestinya boleh dicapai dari internet."
  for risky in 23:Telnet 21:FTP 3306:MySQL 5432:PostgreSQL 6379:Redis 27017:MongoDB 9200:Elasticsearch 11211:Memcached; do
    p="${risky%%:*}"; name="${risky##*:}"
    if [[ " $PUBLIC " == *" $p "* ]]; then
      if [ "$p" = "21" ] || [ "$p" = "23" ]; then
        record critical "Rangkaian" "${name} pada semua antaramuka (port ${p})" "Protokol tanpa penyulitan dikesan pada alamat wildcard." "Matikan ${name}; gunakan protokol selamat seperti SSH/SFTP. Sahkan juga peraturan firewall."
      else
        record warning "Rangkaian" "${name} pada semua antaramuka (port ${p})" "Perkhidmatan sensitif mendengar pada alamat wildcard; firewall mungkin masih menyekatnya." "Ikat pada loopback/rangkaian persendirian atau hadkan port ${p} dengan firewall."
      fi
    fi
  done
else
  record info "Rangkaian" "Tidak dapat senaraikan port" "ss/netstat tiada." "Pasang: sudo apt install iproute2."
fi

# ==============================================================================
#  6. Fail & keizinan berisiko
# ==============================================================================
section "Fail & keizinan"
declare -a WW_FILES=()
while IFS= read -r file; do
  WW_FILES+=("$file")
done < <(find /etc /usr/local -xdev -type f -perm -0002 -print 2>/dev/null | head -n 21)
if [ "${#WW_FILES[@]}" -gt 0 ]; then
  NW="${#WW_FILES[@]}"; MORE=""
  if [ "$NW" -gt 20 ]; then NW=20; MORE="+"; fi
  WW_EXAMPLE="$(printf '%s\n' "${WW_FILES[@]:0:3}" | tr '\n' ' ')"
  record warning "Fail" "${NW}${MORE} fail world-writable dalam /etc,/usr/local" "Contoh: $WW_EXAMPLE" "Buang izin tulis umum: sudo chmod o-w <fail>."
else
  record pass "Fail" "Tiada fail world-writable kritikal" "/etc dan /usr/local bersih." ""
fi

if [ -r /etc/shadow ]; then
  SHSTAT="$(stat -c '%a %U %G' /etc/shadow 2>/dev/null || true)"
  read -r SHMODE SHOWNER SHGROUP <<<"$SHSTAT"
  SHMODE_DEC=0
  [[ "${SHMODE:-}" =~ ^[0-7]{3,4}$ ]] && SHMODE_DEC=$((8#$SHMODE))
  # Benarkan maksimum 0640: rw untuk root dan baca untuk kumpulan shadow/root.
  if [ "$SHOWNER" != "root" ] || { [ "$SHGROUP" != "shadow" ] && [ "$SHGROUP" != "root" ]; } || (( SHMODE_DEC == 0 || (SHMODE_DEC & ~8#0640) != 0 )); then
    record warning "Fail" "/etc/shadow pemilikan/izin berisiko" "Mod ${SHMODE:-tidak diketahui}, pemilik ${SHOWNER:-?}:${SHGROUP:-?}." "Pulihkan pemilikan root:shadow dan mod 640 (atau dasar distro yang lebih ketat)."
  else
    record pass "Fail" "/etc/shadow pemilikan/izin ketat" "Mod $SHMODE, pemilik $SHOWNER:$SHGROUP." ""
  fi
fi

SUID="$(find / -xdev -type f -perm -4000 2>/dev/null | wc -l | tr -d ' ')"
SUID_NOTE=""; [ "$IS_ROOT" -eq 0 ] && SUID_NOTE=" Kiraan mungkin tidak lengkap tanpa root."
record info "Fail" "${SUID} binari SUID dikesan" "SUID boleh membenarkan naik taraf keistimewaan jika dieksploit.${SUID_NOTE}" "Semak senarai: sudo find / -xdev -perm -4000 -type f. Buang SUID yang tidak perlu."

# ==============================================================================
#  7. Perkhidmatan tambahan & pengukuhan
# ==============================================================================
section "Pengukuhan tambahan"
if has fail2ban-client && service_is_active fail2ban; then
  record pass "Hardening" "Fail2ban aktif" "Melindungi daripada brute-force." ""
else
  record warning "Hardening" "Fail2ban tidak aktif" "Tiada perlindungan brute-force automatik." "Pasang: sudo apt install fail2ban && sudo systemctl enable --now fail2ban."
fi

# SELinux / AppArmor
if { [ -r /sys/module/apparmor/parameters/enabled ] && grep -q '^Y' /sys/module/apparmor/parameters/enabled; } || { has aa-status && aa-status --enabled 2>/dev/null; }; then
  record pass "Hardening" "AppArmor dihidupkan" "Kawalan akses mandatori aktif." ""
elif has getenforce && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
  record pass "Hardening" "SELinux Enforcing" "MAC aktif." ""
else
  record warning "Hardening" "Tiada MAC aktif (AppArmor/SELinux)" "Lapisan kawalan tambahan tiada." "Hidupkan AppArmor: sudo systemctl enable --now apparmor."
fi

# Masa tepat penting untuk TLS, log korelasi dan pengesahan berasaskan masa.
if has timedatectl; then
  NTP_STATE="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
  if [ "$NTP_STATE" = "yes" ]; then
    record pass "Hardening" "Jam sistem disegerakkan" "Penyegerakan masa rangkaian aktif." ""
  elif [ "$NTP_STATE" = "no" ]; then
    record warning "Hardening" "Jam sistem tidak disegerakkan" "timedatectl melaporkan NTPSynchronized=no." "Aktifkan systemd-timesyncd, chrony atau perkhidmatan NTP yang diluluskan."
  fi
fi

# ==============================================================================
#  Ringkasan
# ==============================================================================
TOTAL=$((N_CRIT+N_WARN+N_INFO+N_PASS))
SCORE=100
SCORE=$((SCORE - N_CRIT*15 - N_WARN*5))
[ "$SCORE" -lt 0 ] && SCORE=0
if   [ "$SCORE" -ge 90 ]; then GRADE="A"
elif [ "$SCORE" -ge 80 ]; then GRADE="B"
elif [ "$SCORE" -ge 65 ]; then GRADE="C"
elif [ "$SCORE" -ge 50 ]; then GRADE="D"
else GRADE="F"; fi

printf '\n%s%s══ Ringkasan%s\n' "$C_BOLD" "$C_CLAY" "$C_RESET"
printf '  Gred keseluruhan : %s%s%s  (%s/100)\n' "$C_BOLD" "$GRADE" "$C_RESET" "$SCORE"
printf '  %sKritikal%s %-3s  %sAmaran%s %-3s  %sInfo%s %-3s  %sLulus%s %-3s  (jumlah %s)\n' \
  "$C_RED" "$C_RESET" "$N_CRIT" "$C_YEL" "$C_RESET" "$N_WARN" \
  "$C_BLU" "$C_RESET" "$N_INFO" "$C_GRN" "$C_RESET" "$N_PASS" "$TOTAL"

# ==============================================================================
#  Laporan HTML
# ==============================================================================
if [ "$MAKE_HTML" -eq 1 ]; then
  esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
  OUT_DIR="$(dirname -- "$HTML_OUT")"
  OUT_BASE="$(basename -- "$HTML_OUT")"
  HTML_TMP="$(mktemp "${OUT_DIR}/.${OUT_BASE}.tmp.XXXXXX" 2>/dev/null || true)"
  if [ -z "$HTML_TMP" ]; then
    REPORT_ERROR=1
    printf '\n  %s⚠ Gagal mencipta laporan HTML dalam %s%s\n' "$C_YEL" "$OUT_DIR" "$C_RESET"
  elif {
    cat <<HTMLHEAD
<!doctype html><html lang="ms"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecScan Server Audit — $(printf '%s' "$HOSTN" | esc)</title>
<style>
:root{--bg:#faf9f5;--surface:#fff;--surface2:#f5f4ef;--border:#e4e2d8;--t1:#1f1e1d;--t2:#63615a;--t3:#918e83;--clay:#c96442;--crit:#c63a2f;--warn:#c07e14;--info:#2f74b8;--pass:#4e8a22}
@media(prefers-color-scheme:dark){:root{--bg:#262624;--surface:#2d2c2a;--surface2:#31302e;--border:#3b3a37;--t1:#f0eee6;--t2:#b3b0a5;--t3:#8a877b;--clay:#d97757;--crit:#cf4b3f;--warn:#c08222;--info:#3d7fbf;--pass:#559130}}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t1);font-family:'Inter',-apple-system,'Segoe UI',sans-serif;line-height:1.6;padding:32px 16px}
.wrap{max-width:860px;margin:0 auto}
h1{font-family:'Lora',Georgia,serif;font-weight:500;font-size:1.7rem;margin-bottom:4px}
.sub{color:var(--t2);font-size:.9rem;margin-bottom:24px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:24px}
.mbox{background:var(--surface2);border-radius:10px;padding:11px 13px}
.mbox b{display:block;font-size:.7rem;color:var(--t3);font-weight:500;margin-bottom:3px}
.grade{display:flex;align-items:center;gap:20px;background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:22px;margin-bottom:20px}
.gnum{font-family:'Lora',serif;font-size:3.2rem;font-weight:600;line-height:1}
.gA{color:var(--pass)}.gB{color:var(--info)}.gC,.gD{color:var(--warn)}.gF{color:var(--crit)}
.counts{display:flex;flex-wrap:wrap;gap:8px}
.pill{border-radius:999px;padding:5px 13px;font-size:.78rem;font-weight:600;color:#fff}
.p-crit{background:var(--crit)}.p-warn{background:var(--warn)}.p-info{background:var(--info)}.p-pass{background:var(--pass)}
.row{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px;margin-bottom:10px;display:flex;gap:13px;align-items:flex-start}
.badge{flex:0 0 auto;min-width:78px;text-align:center;border-radius:999px;padding:4px 10px;font-size:.66rem;font-weight:600;color:#fff}
.b-crit{background:var(--crit)}.b-warn{background:var(--warn)}.b-info{background:var(--info)}.b-pass{background:var(--pass)}
.content{min-width:0;flex:1}
.title{font-weight:500;font-size:.92rem}
.cat{font-size:.7rem;color:var(--t3);margin-bottom:4px}
.detail{font-size:.82rem;color:var(--t2);margin-top:3px;overflow-wrap:anywhere}
.rec{font-size:.82rem;color:var(--info);background:color-mix(in srgb,var(--info) 10%,transparent);border-radius:8px;padding:8px 11px;margin-top:8px;overflow-wrap:anywhere}
.foot{color:var(--t3);font-size:.75rem;text-align:center;margin-top:28px;border-top:1px solid var(--border);padding-top:16px}
</style></head><body><div class="wrap">
<h1>Server Security Audit</h1>
<div class="sub">Laporan dijana oleh SecScan Server Audit v${SCRIPT_VERSION}</div>
<div class="meta">
<div class="mbox"><b>Host</b>$(printf '%s' "$HOSTN" | esc)</div>
<div class="mbox"><b>Sistem</b>$(printf '%s' "$OS_NAME" | esc)</div>
<div class="mbox"><b>Kernel</b>$(printf '%s' "$KERNEL" | esc)</div>
<div class="mbox"><b>Masa</b>$(now_iso | esc)</div>
</div>
<div class="grade">
<div class="gnum g${GRADE}">${GRADE}</div>
<div>
<div style="font-size:1.1rem;font-weight:500;margin-bottom:8px">Skor ${SCORE}/100</div>
<div class="counts">
<span class="pill p-crit">${N_CRIT} Kritikal</span>
<span class="pill p-warn">${N_WARN} Amaran</span>
<span class="pill p-info">${N_INFO} Info</span>
<span class="pill p-pass">${N_PASS} Lulus</span>
</div></div></div>
HTMLHEAD

    for order in critical warning info pass; do
      for i in "${!ROW_SEVS[@]}"; do
        sev="${ROW_SEVS[$i]}"; cat="${ROW_CATS[$i]}"; title="${ROW_TITLES[$i]}"
        detail="${ROW_DETAILS[$i]}"; rec="${ROW_RECS[$i]}"
        [ "$sev" != "$order" ] && continue
        case "$sev" in
          critical) bc="b-crit"; lbl="Kritikal" ;;
          warning)  bc="b-warn"; lbl="Amaran" ;;
          pass)     bc="b-pass"; lbl="Lulus" ;;
          *)        bc="b-info"; lbl="Info" ;;
        esac
        printf '<div class="row"><span class="badge %s">%s</span><div class="content"><div class="cat">%s</div><div class="title">%s</div>' \
          "$bc" "$lbl" "$(printf '%s' "$cat" | esc)" "$(printf '%s' "$title" | esc)"
        [ -n "$detail" ] && printf '<div class="detail">%s</div>' "$(printf '%s' "$detail" | esc)"
        [ -n "$rec" ] && printf '<div class="rec">%s</div>' "$(printf '%s' "$rec" | esc)"
        printf '</div></div>\n'
      done
    done

    cat <<HTMLFOOT
<div class="foot">Audit read-only — tiada perubahan dibuat pada sistem. Sahkan setiap cadangan sebelum melaksanakan.<br>SecScan Server Audit · $(printf '%s' "$HOSTN" | esc) · $(now_iso | esc)</div>
</div></body></html>
HTMLFOOT
  } > "$HTML_TMP"; then
    if mv -- "$HTML_TMP" "$HTML_OUT" 2>/dev/null; then
      HTML_TMP=""
      printf '\n  %s✓ Laporan HTML disimpan:%s %s\n' "$C_GRN" "$C_RESET" "$HTML_OUT"
      printf '    %sBuka dalam browser atau muat turun fail ini.%s\n' "$C_DIM" "$C_RESET"
    else
      rm -f -- "$HTML_TMP"
      HTML_TMP=""
      REPORT_ERROR=1
      printf '\n  %s⚠ Gagal memindahkan laporan HTML ke %s%s\n' "$C_YEL" "$HTML_OUT" "$C_RESET"
    fi
  else
    rm -f -- "$HTML_TMP"
    HTML_TMP=""
    REPORT_ERROR=1
    printf '\n  %s⚠ Gagal menulis laporan HTML ke %s%s\n' "$C_YEL" "$HTML_OUT" "$C_RESET"
  fi
fi

# Kod keluar penjanaan laporan diutamakan supaya kegagalan -o tidak terlepas pandang.
if   [ "$REPORT_ERROR" -gt 0 ]; then exit 73
elif [ "$N_CRIT" -gt 0 ]; then exit 2
elif [ "$N_WARN" -gt 0 ]; then exit 1
else exit 0; fi
