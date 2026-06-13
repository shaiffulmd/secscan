<?php

$root = dirname(__DIR__);
$rii = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
);

$phpFiles = [];
foreach ($rii as $file) {
    if (!$file->isFile() || $file->getExtension() !== 'php') {
        continue;
    }

    $path = $file->getPathname();
    if (str_contains($path, DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR)) {
        continue;
    }
    $phpFiles[] = $path;
}

sort($phpFiles);
$failed = false;
foreach ($phpFiles as $file) {
    $cmd = escapeshellcmd(PHP_BINARY) . ' -l ' . escapeshellarg($file);
    exec($cmd, $output, $code);
    foreach ($output as $line) {
        echo $line . PHP_EOL;
    }
    $output = [];
    if ($code !== 0) {
        $failed = true;
    }
}

exit($failed ? 1 : 0);
