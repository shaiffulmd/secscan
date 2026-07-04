#!/usr/bin/env bash
# ==============================================================================
#  SecScan Server Audit — semakan keselamatan untuk pelayan Ubuntu/Debian
# ------------------------------------------------------------------------------
#  Guna:
#     sudo bash audit.sh                 # terminal + laporan HTML
#     sudo bash audit.sh --no-html       # terminal sahaja
#     sudo bash audit.sh -o /path.html   # tetapkan lokasi laporan
#
#  Skrip ini READ-ONLY: ia hanya membaca konfigurasi dan tidak mengubah apa-apa
#  pada sistem. Jalankan sebagai root/sudo untuk keputusan paling lengkap.
# ==============================================================================

set -o pipefail

# ---------- Tetapan ----------
SCRIPT_VERSION="1.0.0"
HTML_OUT=""
MAKE_HTML=1

while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-html)      MAKE_HTML=0 ;;
    -o|--output)    HTML_OUT="$2"; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -n 14
      exit 0 ;;
    *) echo "Pilihan tidak dikenali: $1" >&2; exit 2 ;;
  esac
  shift
done

[ -z "$HTML_OUT" ] && HTML_OUT="secscan-audit-$(hostname -s 2>/dev/null || echo server)-$(date +%Y%m%d-%H%M%S).html"

# ---------- Warna terminal ----------
if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[38;5;167m'; C_GRN=$'\033[38;5;71m'
  C_YEL=$'\033[38;5;179m'; C_BLU=$'\033[38;5;74m'; C_CLAY=$'\033[38;5;173m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CLAY=""
fi

# ---------- Kaunter & simpanan keputusan ----------
N_CRIT=0; N_WARN=0; N_INFO=0; N_PASS=0
declare -a ROWS   # setiap entri: severity|kategori|tajuk|butiran|cadangan

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
  ROWS+=("${sev}|${cat}|${title}|${detail}|${rec}")

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
}

section() { printf '\n%s%s══ %s%s\n' "$C_BOLD" "$C_CLAY" "$1" "$C_RESET"; }
has() { command -v "$1" >/dev/null 2>&1; }

# ==============================================================================
#  Header
# ==============================================================================
OS_NAME="$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Unknown OS}" )"
KERNEL="$(uname -r)"
HOSTN="$(hostname -f 2>/dev/null || hostname)"
UPTIME="$(uptime -p 2>/dev/null | sed 's/^up //')"
IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1

clear 2>/dev/null || true
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
  UPD="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst' )"
  SEC="$(apt-get -s upgrade 2>/dev/null | grep -i '^Inst' | grep -ic security)"
  if [ "${UPD:-0}" -eq 0 ]; then
    record pass "Kemas kini" "Sistem terkini" "Tiada pakej menunggu kemas kini." ""
  elif [ "${SEC:-0}" -gt 0 ]; then
    record critical "Kemas kini" "$SEC kemas kini keselamatan tertunggak" "$UPD pakej boleh dikemas kini ($SEC berkaitan keselamatan)." "Jalankan: sudo apt update && sudo apt upgrade. Pertimbang unattended-upgrades."
  else
    record warning "Kemas kini" "$UPD pakej belum dikemas kini" "Tiada yang dikelaskan keselamatan, tetapi elok dikemas kini." "Jalankan: sudo apt update && sudo apt upgrade."
  fi
  if dpkg -l 2>/dev/null | grep -q '^ii  unattended-upgrades'; then
    record pass "Kemas kini" "unattended-upgrades dipasang" "Patch keselamatan automatik tersedia." ""
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
if has ufw; then
  if ufw status 2>/dev/null | grep -qi 'Status: active'; then
    record pass "Firewall" "UFW aktif" "Firewall UFW sedang berjalan." ""
  else
    record critical "Firewall" "UFW tidak aktif" "UFW dipasang tetapi tidak dihidupkan." "Hidupkan: sudo ufw enable (pastikan port SSH dibenarkan dahulu)."
  fi
elif has firewall-cmd; then
  if firewall-cmd --state 2>/dev/null | grep -qi running; then
    record pass "Firewall" "firewalld aktif" "firewalld sedang berjalan." ""
  else
    record critical "Firewall" "firewalld tidak aktif" "firewalld dipasang tetapi tidak berjalan." "Hidupkan: sudo systemctl enable --now firewalld."
  fi
elif iptables -L -n 2>/dev/null | grep -qE '^(DROP|REJECT)'; then
  record info "Firewall" "Peraturan iptables dikesan" "Ada peraturan iptables tetapi tiada pengurus firewall mesra pengguna." "Pertimbang UFW untuk pengurusan lebih mudah: sudo apt install ufw."
else
  record critical "Firewall" "Tiada firewall dikesan" "Tiada UFW, firewalld, atau peraturan iptables menyekat." "Pasang & konfigur UFW: sudo apt install ufw && sudo ufw default deny incoming && sudo ufw allow OpenSSH && sudo ufw enable."
fi

# ==============================================================================
#  3. SSH
# ==============================================================================
section "Konfigurasi SSH"
SSHD=/etc/ssh/sshd_config
sshget() { # baca nilai efektif direktif; args: nama
  { [ -r "$SSHD" ] && grep -Ehi "^[[:space:]]*$1[[:space:]]+" "$SSHD" /etc/ssh/sshd_config.d/*.conf 2>/dev/null; } \
    | tail -n1 | awk '{print tolower($2)}'
}
if [ -r "$SSHD" ]; then
  PRL="$(sshget PermitRootLogin)"
  if [ "$PRL" = "no" ] || [ "$PRL" = "prohibit-password" ]; then
    record pass "SSH" "Log masuk root terkawal" "PermitRootLogin = ${PRL}." ""
  else
    record critical "SSH" "Log masuk root SSH dibenarkan" "PermitRootLogin = ${PRL:-default(yes)}." "Set 'PermitRootLogin no' dalam $SSHD, kemudian: sudo systemctl restart ssh."
  fi

  PWA="$(sshget PasswordAuthentication)"
  if [ "$PWA" = "no" ]; then
    record pass "SSH" "Pengesahan kata laluan dimatikan" "Hanya kunci SSH dibenarkan." ""
  else
    record warning "SSH" "Pengesahan kata laluan dibenarkan" "PasswordAuthentication = ${PWA:-default(yes)}." "Guna kunci SSH dan set 'PasswordAuthentication no' untuk halang brute-force."
  fi

  SSHPORT="$(sshget Port)"; [ -z "$SSHPORT" ] && SSHPORT=22
  record info "SSH" "Port SSH: ${SSHPORT}" "SSH mendengar pada port ${SSHPORT}." "$( [ "$SSHPORT" = "22" ] && echo 'Menukar port bukan langkah keselamatan sebenar, tetapi mengurangkan bising log.' )"

  if [ "$(sshget X11Forwarding)" = "yes" ]; then
    record warning "SSH" "X11Forwarding dihidupkan" "Boleh membuka permukaan serangan tidak perlu." "Set 'X11Forwarding no' jika tidak diperlukan."
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

SUDOERS_NOPW="$(grep -rhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#')"
if [ -n "$SUDOERS_NOPW" ]; then
  record warning "Pengguna" "sudo tanpa kata laluan" "Ada peraturan NOPASSWD dalam sudoers." "Semak /etc/sudoers.d/. Elakkan NOPASSWD kecuali benar-benar perlu."
fi

# ==============================================================================
#  5. Port & perkhidmatan mendengar
# ==============================================================================
section "Port terbuka & perkhidmatan"
if has ss; then
  LISTEN="$(ss -tulnH 2>/dev/null)"
elif has netstat; then
  LISTEN="$(netstat -tuln 2>/dev/null | tail -n +3)"
else
  LISTEN=""
fi
if [ -n "$LISTEN" ]; then
  # port yang mendengar pada semua antara muka (0.0.0.0 / [::])
  PUBLIC="$(echo "$LISTEN" | grep -Eo '(0\.0\.0\.0|\*|\[::\]):[0-9]+' | grep -Eo '[0-9]+$' | sort -un | tr '\n' ' ')"
  NPUB="$(echo "$PUBLIC" | wc -w | tr -d ' ')"
  record info "Rangkaian" "${NPUB} port mendengar secara awam" "Port: ${PUBLIC:-tiada}" "Pastikan setiap port ini memang perlu terdedah ke internet; sekat yang lain dengan firewall."
  for risky in 23:Telnet 21:FTP 3306:MySQL 5432:PostgreSQL 6379:Redis 27017:MongoDB 9200:Elasticsearch 11211:Memcached; do
    p="${risky%%:*}"; name="${risky##*:}"
    if echo " $PUBLIC " | grep -q " $p "; then
      record critical "Rangkaian" "${name} terdedah (port ${p})" "Perkhidmatan sensitif mendengar pada antara muka awam." "Ikat pada 127.0.0.1 sahaja atau sekat port ${p} dengan firewall. Elak Telnet/FTP sepenuhnya."
    fi
  done
else
  record info "Rangkaian" "Tidak dapat senaraikan port" "ss/netstat tiada." "Pasang: sudo apt install iproute2."
fi

# ==============================================================================
#  6. Fail & keizinan berisiko
# ==============================================================================
section "Fail & keizinan"
WW="$(find /etc /usr/local -xdev -type f -perm -0002 2>/dev/null | head -n 20)"
if [ -n "$WW" ]; then
  NW="$(echo "$WW" | wc -l | tr -d ' ')"
  record warning "Fail" "${NW}+ fail world-writable dalam /etc,/usr/local" "Contoh: $(echo "$WW" | head -n3 | tr '\n' ' ')" "Buang izin tulis umum: sudo chmod o-w <fail>."
else
  record pass "Fail" "Tiada fail world-writable kritikal" "/etc dan /usr/local bersih." ""
fi

if [ -r /etc/shadow ]; then
  SHMODE="$(stat -c '%a' /etc/shadow 2>/dev/null)"
  if [ "$SHMODE" -gt 640 ] 2>/dev/null; then
    record warning "Fail" "/etc/shadow terlalu terbuka (mod $SHMODE)" "Fail kata laluan patut ketat." "sudo chmod 640 /etc/shadow (atau 600)."
  else
    record pass "Fail" "/etc/shadow keizinan betul" "Mod $SHMODE." ""
  fi
fi

SUID="$(find / -xdev -type f -perm -4000 2>/dev/null | wc -l | tr -d ' ')"
record info "Fail" "${SUID} binari SUID dikesan" "SUID membenarkan naik taraf keistimewaan jika dieksploit." "Semak senarai: find / -perm -4000 -type f. Buang SUID yang tidak perlu."

# ==============================================================================
#  7. Perkhidmatan tambahan & pengukuhan
# ==============================================================================
section "Pengukuhan tambahan"
if has fail2ban-client && systemctl is-active --quiet fail2ban 2>/dev/null; then
  record pass "Hardening" "Fail2ban aktif" "Melindungi daripada brute-force." ""
else
  record warning "Hardening" "Fail2ban tidak aktif" "Tiada perlindungan brute-force automatik." "Pasang: sudo apt install fail2ban && sudo systemctl enable --now fail2ban."
fi

# SELinux / AppArmor
if has aa-status && aa-status --enabled 2>/dev/null; then
  record pass "Hardening" "AppArmor dihidupkan" "Kawalan akses mandatori aktif." ""
elif has getenforce && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
  record pass "Hardening" "SELinux Enforcing" "MAC aktif." ""
else
  record warning "Hardening" "Tiada MAC aktif (AppArmor/SELinux)" "Lapisan kawalan tambahan tiada." "Hidupkan AppArmor: sudo systemctl enable --now apparmor."
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
  {
    cat <<HTMLHEAD
<!doctype html><html lang="ms"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecScan Server Audit — ${HOSTN}</title>
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
      for entry in "${ROWS[@]}"; do
        IFS='|' read -r sev cat title detail rec <<<"$entry"
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
<div class="foot">Audit read-only — tiada perubahan dibuat pada sistem. Sahkan setiap cadangan sebelum melaksanakan.<br>SecScan Server Audit · ${HOSTN} · $(now_iso | esc)</div>
</div></body></html>
HTMLFOOT
  } > "$HTML_OUT" 2>/dev/null

  if [ -f "$HTML_OUT" ]; then
    printf '\n  %s✓ Laporan HTML disimpan:%s %s\n' "$C_GRN" "$C_RESET" "$HTML_OUT"
    printf '    %sBuka dalam browser atau muat turun fail ini.%s\n' "$C_DIM" "$C_RESET"
  else
    printf '\n  %s⚠ Gagal menulis laporan HTML ke %s%s\n' "$C_YEL" "$HTML_OUT" "$C_RESET"
  fi
fi

# Kod keluar: 2 jika ada kritikal, 1 jika ada amaran, 0 jika bersih
if   [ "$N_CRIT" -gt 0 ]; then exit 2
elif [ "$N_WARN" -gt 0 ]; then exit 1
else exit 0; fi
