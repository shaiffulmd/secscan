# Joomla: Hardening ↔ Detection Map

Tujuan dokumen: bila kita **hardening** site pelanggan untuk sembunyikan ciri Joomla
daripada penyerang, secscan sendiri **tidak boleh jadi buta**. Setiap tindakan
hardening di bawah dipeta ke lapisan detection yang masih menangkap Joomla —
supaya kita tak dapat **false negative** untuk site yang kita lindungi.

Prinsip teras: **jangan bergantung satu petanda.** secscan kini guna banyak isyarat
bebas berpemberat (lihat `src/JoomlaFingerprint.php`). Buang satu, yang lain masih cukup.

---

## Model dua lapisan secscan

| Lapisan | Sumber | Bila jalan |
|---|---|---|
| **Pasif** | HTML homepage + header + tag `generator` | Setiap imbasan |
| **Aktif (jaring keselamatan)** | Probe endpoint khusus-Joomla | Bila pasif = 0 (nampak "no CMS"), atau Joomla dikesan tanpa versi |

Skor: setiap isyarat ada berat. `≥7` = keyakinan tinggi, `≥4` = dikesan, `1–3` = lemah.

---

## Peta: petanda → hardening → apa yang masih tangkap

| # | Petanda Joomla (yang penyerang nampak) | Tindakan hardening | Selepas hardening, secscan masih tangkap melalui |
|---|---|---|---|
| 1 | `<meta name="generator" content="Joomla!">` | Set **Global Config → Site → Include Version = Off**, atau override di template | Path aset (`/media/system/`, `/components/com_`), probe aktif `joomla.xml` |
| 2 | `/media/system/js/*`, `/media/jui/`, `/media/legacy/` | Susah dibuang tanpa rosak site; boleh proxy/rename via WAF rewrite | Probe aktif (`joomla.xml`, language XML, README.txt) |
| 3 | `/components/com_*` dalam URL aset | SEF + template override, gabung/rename aset | `option=com_`, `Itemid=`, `/index.php/component/`, probe aktif |
| 4 | `/cache/com_templates/…` (isyarat terkuat pasif) | Alih cache luar web root / rename folder cache | Probe aktif kekal |
| 5 | `format=opensearch`, `title="… Joomla"` | Buang/rename modul carian OpenSearch | Aset lain + probe aktif |
| 6 | `class="moduletable…"`, `joomla-script-options` | Override output template (chrome, layout) | Path aset + probe aktif |
| 7 | `/administrator/manifests/files/joomla.xml` **(bocor versi tepat)** | **Blok public** via server rule (lihat bawah) | Language XML, README.txt, `/api/`, aset frontend |
| 8 | `/language/en-GB/*.xml` (bocor versi) | Blok public `*.xml` dalam `/language/` | `joomla.xml` (jika terlepas), aset frontend |
| 9 | `/README.txt`, `/htaccess.txt`, `/web.config.txt` | Padam selepas install | Probe endpoint lain + aset |
| 10 | `/api/index.php` (Web Services JSON) | Matikan jika tak guna; hadkan IP | Aset frontend + endpoint lain |
| 11 | `/administrator/` login | Hadkan IP/VPN, tukar path admin, 2FA | Endpoint & aset lain |

> Baca sebagai lajur: satu baris = satu petanda; walaupun awak hardening kolum tengah,
> kolum kanan tunjuk secscan masih ada jalan untuk mengesan → tiada false negative.

---

## Server rules untuk halang kebocoran versi (baris 7–9)

**Apache / `.htaccess`:**
```apache
<FilesMatch "\.(xml|txt)$">
  <If "%{REQUEST_URI} =~ m#^/(administrator/manifests|language/)#">
    Require all denied
  </If>
</FilesMatch>
RedirectMatch 404 ^/(README\.txt|htaccess\.txt|web\.config\.txt)$
RedirectMatch 404 ^/administrator/manifests/
```

**Nginx:**
```nginx
location ~* ^/(administrator/manifests|language/.*\.(xml))  { deny all; return 404; }
location ~* ^/(README\.txt|htaccess\.txt|web\.config\.txt)$ { return 404; }
```

Selepas ini, secscan lapisan aktif **sepatutnya gagal** dapat versi dari endpoint tersebut
— itulah tanda hardening berjaya. Jalankan semula imbasan untuk sahkan finding
"Joomla Version Disclosure" hilang, tapi CMS **masih** dikesan (melalui aset/probe lain).

---

## Cara uji selepas hardening

```bash
composer test:detection          # ujian sedia ada
php scripts/test_joomla_fingerprint.php   # ujian pengesanan Joomla berlapis
```

Kemudian imbas site sebenar dan semak:

1. **CMS masih dikesan?** Kalau finding jadi "No common CMS fingerprint detected"
   tetapi awak tahu ia Joomla → hardening berjaya *tetapi* probe aktif patut tangkap.
   Kalau probe pun terlepas, tambah isyarat/endpoint baru dalam `JoomlaFingerprint`.
2. **Versi masih bocor?** Kalau finding "Joomla Version Disclosure" wujud → endpoint
   versi (baris 7–9) belum diblok.
3. **False negative check:** site Joomla yang di-hardening penuh patut keluar sebagai
   `CMS Detected (active probe) — warning`, bukan `pass`.

---

## Nota etika/undang-undang

Probe aktif menghantar request tambahan ke endpoint sasaran. Guna hanya pada
domain yang awak ada **kebenaran bertulis** (authorization/scope). Untuk institusi
kerajaan (cth. `*.edu.my`, `*.gov.my`), simpan surat kebenaran sebelum active scanning.
