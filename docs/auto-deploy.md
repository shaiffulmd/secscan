# Auto-deploy dari GitHub

Setiap push ke `main` akan mengemas kini web secara automatik:

1. GitHub Actions menjalankan semua ujian. Jika gagal, tiada apa-apa di-deploy.
2. Actions menyambung ke VPS melalui SSH dan mencetuskan `scripts/deploy.sh`.
3. VPS mengambil commit terbaharu dan menjalankan ujian sekali lagi dengan PHP pelayan.
4. Fail disalin ke web root, kemudian laman diperiksa. Jika laman gagal, versi
   sebelumnya dipulihkan secara automatik.

Pull request hanya menjalankan ujian dan tidak melakukan deploy.

Fail yang tidak disentuh: `.env`, kandungan `data/`, dan fail dalam web root yang
tiada dalam git. Fail yang dibuang daripada git juga kekal dalam web root; jumlahnya
dilaporkan dan senarainya ada dalam `~/.secscan-deploy/stale-files.txt` untuk disemak.

## Setup sekali sahaja

Keperluan VPS: `git`, `rsync`, `curl` dan PHP CLI. Jalankan langkah VPS sebagai
pengguna yang memiliki fail web, bukan root.

### 1. Pasang skrip di VPS

    mkdir -p ~/bin
    curl -fsSL https://raw.githubusercontent.com/shaiffulmd/secscan/main/scripts/deploy.sh -o ~/bin/secscan-deploy
    chmod 700 ~/bin/secscan-deploy

Baca skrip itu sebelum menggunakannya. Salinan ini tidak dikemas kini secara
automatik, jadi ulang langkah ini jika `scripts/deploy.sh` berubah.

### 2. Cipta konfigurasi di VPS

Simpan dalam `~/.secscan-deploy.env`, dengan `chmod 600`:

    SECSCAN_WEB_ROOT=/laluan/penuh/ke/web/root
    SECSCAN_HEALTH_URL=https://security.apasaja.my/index.php
    # Pilihan, jika perubahan PHP lambat kelihatan kerana opcache:
    # SECSCAN_POST_DEPLOY_CMD="sudo systemctl reload php8.3-fpm"

### 3. Uji secara manual di VPS

    ~/bin/secscan-deploy

Deploy pertama hanya boleh dibuat selepas skrip ini ada di `main`. Pada deploy
pertama tiada versi sebelumnya untuk dipulihkan, jadi buat sandaran web root dahulu.

`SECSCAN_HEALTH_URL` mesti memulangkan HTTP 200 kepada `curl` dari VPS. Jika Cloudflare
atau WAF mencabar permintaan itu, setiap deploy akan dianggap gagal dan dipulihkan.
Pemulihan menyalin semula fail versi lama, tetapi fail baharu daripada versi yang gagal
kekal dalam web root dan akan disenaraikan dalam `stale-files.txt`.

### 4. Cipta kunci SSH khas untuk deploy

Di komputer anda:

    ssh-keygen -t ed25519 -f secscan_deploy_key -N "" -C "secscan-github-deploy"

Di VPS, tambah satu baris ini dalam `~/.ssh/authorized_keys`, menggunakan kandungan
`secscan_deploy_key.pub`. Sekatan ini bermakna kunci tersebut hanya boleh mencetuskan
deploy, walaupun ia bocor:

    command="/home/PENGGUNA/bin/secscan-deploy",restrict ssh-ed25519 AAAA... secscan-github-deploy

### 5. Tambah secrets di GitHub

Pergi ke **Settings → Secrets and variables → Actions** dalam repo:

| Secret | Nilai |
|---|---|
| `VPS_HOST` | IP asal VPS. Jangan guna domain yang melalui proxy Cloudflare, kerana SSH tidak akan sampai ke VPS |
| `VPS_USER` | Pengguna VPS dari langkah 4 |
| `VPS_SSH_KEY` | Kandungan fail `secscan_deploy_key` (kunci peribadi) |
| `VPS_KNOWN_HOSTS` | Output `ssh-keyscan -p PORT IP_VPS`. Sahkan cap jarinya dengan `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` di VPS |
| `VPS_PORT` | Pilihan, jika SSH bukan pada port 22 |

Selepas itu, padam fail `secscan_deploy_key` dari komputer anda.

Firewall VPS perlu membenarkan SSH daripada GitHub Actions, yang tidak menggunakan
IP tetap. Pastikan login kata laluan SSH dimatikan.

## Kegunaan harian

- **Kemas kini web:** push atau merge ke `main`.
- **Lihat status:** tab **Actions** dalam repo. Repo ini public, jadi log ini boleh
  dibaca sesiapa; butiran penuh hanya ada dalam `~/.secscan-deploy/deploy.log` di VPS.
- **Deploy semula:** tab Actions → **Test and deploy** → **Run workflow**.
- **Batalkan versi buruk:** `git revert <commit>` dan push ke `main`.
- **Lock tertinggal:** jika deploy terhenti secara paksa, buang `~/.secscan-deploy/lock`.
