<?php

/**
 * Public release notes, shown on updates.php and the scanner home page.
 *
 * Add a new entry at the top for every release, with the same version as the
 * VERSION file. This is public: describe what users gain or must do, and leave
 * out internal details that would help an attacker.
 */
final class Changelog
{
    private const MONTHS = ['Januari', 'Februari', 'Mac', 'April', 'Mei', 'Jun', 'Julai', 'Ogos', 'September', 'Oktober', 'November', 'Disember'];

    public const ENTRIES = [
        [
            'version' => '2.6.1',
            'date' => '2026-11-01',
            'title' => 'Pengesanan ancaman terkini',
            'items' => [
                'Senarai CVE untuk WordPress, Joomla dan Drupal kini mengutamakan CVE terbaharu, dan menanda CVE yang tersenarai dalam CISA KEV sebagai sedang dieksploitasi.',
                'Versi teras WordPress, Joomla dan Drupal kini disemak terus terhadap advisory terkini, termasuk CVE-2026-87902 untuk WordPress.',
                'Banner pelayan kini disemak untuk PHP2Shell (CVE-2026-109618 dan CVE-2026-109619) serta pembaikan terkini nginx dan Apache.',
                'Produk yang baru-baru ini dieksploitasi, seperti Ivanti, NetScaler, GitLab dan Magento, kini dikenal pasti sebagai peringatan untuk disemak. Ia tidak menjejaskan gred.',
                'Pengesanan kunci API yang terdedah kini merangkumi 12 format baharu dan blok kunci peribadi PGP.',
                'Rekod DNS MTA-STS kini disemak formatnya.',
                'Halaman Kemas Kini ini ditambah supaya setiap perubahan SecScan mudah dilihat.',
            ],
            'action' => 'Cadangan MTA-STS kami sebelum ini memaparkan contoh rekod yang tidak sah. Jika anda pernah menyalin rekod dengan id=$(date +%Y%m%d), gantikan id itu dengan nilai sebenar seperti id=20261101.',
        ],
        [
            'version' => '2.5.3',
            'date' => '2026-07-10',
            'title' => 'Penambahbaikan papan pemuka',
            'items' => [
                'Papan pemuka kini mempunyai penapisan yang lebih baik dan paparan lokasi GeoIP.',
            ],
        ],
    ];

    /** @return array{version:string,date:string,title:string,items:array<int,string>,action?:string} */
    public static function latest(): array
    {
        return self::ENTRIES[0];
    }

    /** Written out in Malay here because the intl extension is not a project requirement. */
    public static function formatDate(string $date): string
    {
        $parsed = DateTimeImmutable::createFromFormat('!Y-m-d', $date);
        if ($parsed === false) {
            return $date;
        }
        return $parsed->format('j') . ' ' . self::MONTHS[(int)$parsed->format('n') - 1] . ' ' . $parsed->format('Y');
    }
}
