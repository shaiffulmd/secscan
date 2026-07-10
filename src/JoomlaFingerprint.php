<?php

/**
 * JoomlaFingerprint — pengesanan Joomla berlapis (multi-signal, weighted).
 *
 * Masalah yang diselesaikan:
 *   Kalau detection cuma bergantung pada SATU petanda (cth. <meta generator>),
 *   sebaik sahaja petanda itu di-hardening/dibuang, scanner jadi buta →
 *   FALSE NEGATIVE untuk site yang kita nak bantu.
 *
 * Penyelesaian:
 *   Kumpul BANYAK isyarat bebas (independent signals). Setiap satu ada berat
 *   (weight). Skor dikira daripada jumlah berat isyarat yang padan, jadi
 *   walaupun beberapa isyarat dibuang, yang lain masih cukup untuk mengesan.
 *
 * Dua lapisan:
 *   1. PASIF  — regex/string ke atas HTML homepage + header (tiada request tambahan).
 *   2. AKTIF  — probe endpoint khusus-Joomla (jaring keselamatan bila lapisan
 *               pasif lemah; juga bocorkan versi tepat untuk padanan CVE).
 *
 * Semua kaedah bersifat pure & static supaya mudah diuji offline
 * (lihat scripts/test_joomla_fingerprint.php).
 */
final class JoomlaFingerprint
{
    /** Skor minimum untuk anggap "Joomla dikesan". */
    public const THRESHOLD_DETECTED = 4;

    /** Skor untuk anggap keyakinan tinggi (boleh skip active probe). */
    public const THRESHOLD_STRONG = 7;

    // ------------------------------------------------------------------
    //  LAPISAN 1 — ISYARAT PASIF (dari HTML + header, tanpa request tambahan)
    // ------------------------------------------------------------------
    //
    // Setiap entri: 'needle' (string|regex), 'weight', 'label', dan pilihan
    // 'regex'=>true untuk padanan regex. Isyarat berat = sangat khusus Joomla;
    // isyarat ringan = petunjuk sokongan yang mudah hilang selepas hardening.

    private static function passiveRules(): array
    {
        return [
            // — Isyarat KUAT (khusus Joomla, susah bertindih dgn CMS lain) —
            ['needle' => '/cache/com_templates/',      'weight' => 5, 'label' => 'Joomla template cache path'],
            ['needle' => '/media/system/js/',          'weight' => 4, 'label' => 'Joomla core system assets'],
            ['needle' => '/media/system/',             'weight' => 3, 'label' => 'Joomla /media/system path'],
            ['needle' => '/components/com_',           'weight' => 4, 'label' => 'Joomla component asset paths'],
            ['needle' => '/modules/mod_',              'weight' => 4, 'label' => 'Joomla module asset paths'],
            ['needle' => '/plugins/system/',           'weight' => 4, 'label' => 'Joomla system plugin assets'],
            ['needle' => '/index.php/component/',      'weight' => 4, 'label' => 'Joomla SEF component route'],
            ['needle' => '/media/vendor/joomla-custom-elements', 'weight' => 5, 'label' => 'Joomla 4/5 web components'],
            ['needle' => '/media/jui/',                'weight' => 4, 'label' => 'Joomla UI (JUI) assets'],
            ['needle' => '/media/legacy/',             'weight' => 3, 'label' => 'Joomla legacy media assets'],
            ['needle' => '/media/templates/site/',     'weight' => 4, 'label' => 'Joomla 4/5 site template assets'],
            ['needle' => '/administrator/templates/',  'weight' => 4, 'label' => 'Joomla admin template asset'],
            ['needle' => 'joomla-script-options',      'weight' => 4, 'label' => 'Joomla script-options block'],
            ['needle' => 'joomla-alert',               'weight' => 4, 'label' => 'Joomla alert web component'],
            ['needle' => 'format=opensearch',          'weight' => 3, 'label' => 'Joomla OpenSearch link'],

            // — Isyarat SEDERHANA (URL params & konvensyen) —
            ['needle' => 'option=com_',                'weight' => 3, 'label' => 'Joomla option=com_ param'],
            ['needle' => 'itemid=',                    'weight' => 2, 'label' => 'Joomla Itemid param'],
            ['needle' => '/\bcom-[a-z0-9_-]+\b/i',     'weight' => 3, 'label' => 'Joomla body component class', 'regex' => true],
            ['needle' => '/\bitemid-[0-9]+\b/i',       'weight' => 2, 'label' => 'Joomla body Itemid class', 'regex' => true],
            ['needle' => 'class="moduletable',         'weight' => 3, 'label' => 'Joomla module wrapper markup'],
            ['needle' => '/media/vendor/awesomplete',  'weight' => 3, 'label' => 'Joomla-bundled Awesomplete lib'],
            ['needle' => '/media/vendor/punycode',     'weight' => 3, 'label' => 'Joomla-bundled punycode lib'],
            ['needle' => '/media/vendor/short-and-sweet', 'weight' => 3, 'label' => 'Joomla-bundled short-and-sweet lib'],
            ['needle' => '/media/vendor/choicesjs',    'weight' => 2, 'label' => 'Joomla-bundled Choices.js'],
            ['needle' => '/templates/system/',         'weight' => 3, 'label' => 'Joomla system template fallback'],

            // — Isyarat RINGAN (kata kunci; mudah dibuang saat hardening) —
            ['needle' => 'joomla',                     'weight' => 2, 'label' => 'Joomla keyword'],
            ['needle' => 'com_content',                'weight' => 2, 'label' => 'com_content reference'],
            ['needle' => 'com-content',                'weight' => 2, 'label' => 'com-content reference'],
            ['needle' => 'com_sppagebuilder',          'weight' => 2, 'label' => 'SP Page Builder (Joomla extension)'],
            ['needle' => 'sppb-',                       'weight' => 1, 'label' => 'SP Page Builder markup'],
            ['needle' => '/language/en-gb/',           'weight' => 2, 'label' => 'Joomla language folder'],
        ];
    }

    /**
     * Kira isyarat pasif daripada badan HTML + header + tag generator.
     *
     * @return array{signals: array<int,array{label:string,weight:int}>, score:int, version:string}
     */
    public static function passiveSignals(string $html, string $headerHints = '', string $generator = ''): array
    {
        $hay = strtolower($html . ' ' . $headerHints);
        $signals = [];
        $score = 0;
        $seen = [];

        foreach (self::passiveRules() as $rule) {
            $match = !empty($rule['regex'])
                ? (bool)preg_match($rule['needle'], $html)
                : str_contains($hay, strtolower($rule['needle']));
            if ($match && !isset($seen[$rule['label']])) {
                $seen[$rule['label']] = true;
                $signals[] = ['label' => $rule['label'], 'weight' => $rule['weight']];
                $score += $rule['weight'];
            }
        }

        // Tag generator memberi berat besar + versi tepat (bila ada).
        $version = '';
        if (stripos($generator, 'Joomla') !== false) {
            $signals[] = ['label' => 'generator meta tag', 'weight' => 5];
            $score += 5;
            if (preg_match('/Joomla!?\s*([0-9][0-9A-Za-z.\-]*)/i', $generator, $m)) {
                $version = $m[1];
            }
        }

        return ['signals' => $signals, 'score' => $score, 'version' => $version];
    }

    // ------------------------------------------------------------------
    //  LAPISAN 2 — PROBE AKTIF (endpoint khusus-Joomla; jaring keselamatan)
    // ------------------------------------------------------------------
    //
    // Endpoint ini kekal walaupun homepage sudah di-hardening. Sesetengahnya
    // membocorkan VERSI tepat — penting untuk padanan CVE. Guna hanya bila
    // lapisan pasif lemah, untuk elak request berlebihan.
    //
    // Setiap probe: path => ['weight'=>int, 'label'=>string, 'version'=>?bool].

    public static function activeProbePaths(): array
    {
        return [
            // Kebocoran versi teras yang kanonik (paling bernilai).
            '/administrator/manifests/files/joomla.xml' => ['weight' => 6, 'label' => 'core manifest (exact version)', 'version' => true],
            '/language/en-GB/langmetadata.xml'          => ['weight' => 5, 'label' => 'language metadata (version)', 'version' => true],
            '/language/en-GB/en-GB.xml'                 => ['weight' => 5, 'label' => 'language pack (version)', 'version' => true],
            // Fail lalai yang dihantar bersama Joomla.
            '/README.txt'                               => ['weight' => 4, 'label' => 'Joomla README'],
            '/htaccess.txt'                             => ['weight' => 3, 'label' => 'Joomla htaccess template'],
            '/web.config.txt'                           => ['weight' => 3, 'label' => 'Joomla web.config template'],
            '/templates/system/css/system.css'         => ['weight' => 3, 'label' => 'Joomla system stylesheet'],
            // Aset khusus Joomla 4/5.
            '/media/vendor/joomla-custom-elements/js/joomla-alert.min.js' => ['weight' => 4, 'label' => 'Joomla 4/5 web component'],
            // Endpoint dinamik.
            '/api/index.php/v1/'                        => ['weight' => 4, 'label' => 'Joomla Web Services API'],
            '/administrator/'                           => ['weight' => 4, 'label' => 'admin login page'],
        ];
    }

    /**
     * Sahkan respons satu probe. Pure — sesuai untuk ujian offline.
     * Panggil dengan (path, kod HTTP, badan respons).
     *
     * @return array{matched:bool, weight:int, label:string, version:string, note:string}
     */
    public static function validateProbe(string $path, int $code, string $body): array
    {
        $meta = self::activeProbePaths()[$path] ?? ['weight' => 0, 'label' => $path];
        $none = ['matched' => false, 'weight' => 0, 'label' => $meta['label'], 'version' => '', 'note' => ''];

        if ($code !== 200 || $body === '') {
            return $none;
        }

        $version = '';
        $matched = false;
        $note = '';

        switch ($path) {
            case '/administrator/manifests/files/joomla.xml':
                if (stripos($body, '<extension') !== false && stripos($body, 'joomla') !== false) {
                    $matched = true;
                    if (preg_match('#<version>\s*([0-9][0-9.\-A-Za-z]*)\s*</version>#i', $body, $m)) {
                        $version = $m[1];
                        $note = 'exact core version disclosed';
                    }
                }
                break;

            case '/language/en-GB/langmetadata.xml':
            case '/language/en-GB/en-GB.xml':
                if (!self::looksHtml($body) && (stripos($body, '<metafile') !== false || stripos($body, '<extension') !== false || stripos($body, 'joomla') !== false)) {
                    if (preg_match('#<version>\s*([0-9][0-9.\-A-Za-z]*)\s*</version>#i', $body, $m)) {
                        $matched = true;
                        $version = $m[1];
                        $note = 'version disclosed via language pack';
                    } elseif (stripos($body, 'joomla') !== false) {
                        $matched = true;
                    }
                }
                break;

            case '/README.txt':
                // README Joomla sebenar — bukan README projek lain.
                if (preg_match('/Joomla!?\s+is\s+free\s+software|1-\s*What\s+is\s+this\?|Joomla!?\s+Content\s+Management/i', $body)) {
                    $matched = true;
                    if (preg_match('/Joomla!?\s*([0-9]+\.[0-9]+)/', $body, $m)) $version = $m[1];
                }
                break;

            case '/htaccess.txt':
                if (preg_match('/RewriteEngine|Joomla/i', $body) && !self::looksHtml($body)) {
                    $matched = true;
                }
                break;

            case '/web.config.txt':
                if (stripos($body, '<configuration') !== false && !self::looksHtml($body)) {
                    $matched = true;
                }
                break;

            case '/templates/system/css/system.css':
                if (!self::looksHtml($body) && (stripos($body, 'joomla') !== false || preg_match('/\.system-|#system-message|\.message\b/i', $body))) {
                    $matched = true;
                }
                break;

            case '/media/vendor/joomla-custom-elements/js/joomla-alert.min.js':
                if (!self::looksHtml($body) && (stripos($body, 'joomla-alert') !== false || stripos($body, 'customElements') !== false || stripos($body, 'JoomlaAlert') !== false)) {
                    $matched = true;
                }
                break;

            case '/api/index.php/v1/':
                // Joomla Web Services memulangkan JSON:API error yang agak
                // khusus. Jangan padankan JSON "errors" generik dari API lain.
                if (
                    stripos($body, 'application/vnd.api+json') !== false
                    || (
                        preg_match('/"errors"\s*:\s*\[/', $body)
                        && preg_match('/"links"\s*:\s*\{|"jsonapi"\s*:\s*\{|"title"\s*:\s*"[^"]*(?:Joomla|API|Resource|Route)/i', $body)
                    )
                ) {
                    $matched = true;
                    $note = 'Joomla 4/5 Web Services API reachable';
                }
                break;

            case '/administrator/':
                // Banyak site return homepage/catch-all HTML untuk /administrator/.
                // Perkataan "Joomla" atau "form-login" sahaja terlalu longgar
                // dan boleh false-positive pada aplikasi bukan Joomla.
                if (
                    stripos($body, 'com_login') !== false
                    || stripos($body, 'mod-login') !== false
                    || stripos($body, 'option=com_login') !== false
                    || preg_match('/name=["\']option["\']\s+value=["\']com_login["\']/i', $body)
                    || preg_match('/id=["\']form-login["\'][^>]*>.*(?:task|return|username|passwd)/is', $body)
                ) {
                    $matched = true;
                    $note = 'admin login reachable';
                }
                break;
        }

        if (!$matched) {
            return $none;
        }
        return [
            'matched' => true,
            'weight'  => (int)$meta['weight'],
            'label'   => (string)$meta['label'],
            'version' => $version,
            'note'    => $note,
        ];
    }

    private static function looksHtml(string $body): bool
    {
        return (bool)preg_match('/<!doctype html|<html[\s>]|<head[\s>]|<body[\s>]/i', $body);
    }

    /**
     * Terjemah skor kepada label keyakinan.
     */
    public static function confidence(int $score): string
    {
        if ($score >= self::THRESHOLD_STRONG)   return 'high';
        if ($score >= self::THRESHOLD_DETECTED) return 'medium';
        if ($score > 0)                         return 'low';
        return 'none';
    }
}
