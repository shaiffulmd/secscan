<?php

/**
 * Small, shared protocol for the web application and the VPS worker.
 *
 * The signed payload includes a short-lived timestamp and one-time nonce.
 * This authenticates both sides without exposing the worker to public scan
 * requests or trusting client-controlled forwarding headers.
 */
final class WorkerProtocol
{
    public static function requestSignature(string $secret, string $timestamp, string $nonce, string $body): string
    {
        return hash_hmac('sha256', $timestamp . "\n" . $nonce . "\n" . $body, $secret);
    }

    public static function responseSignature(string $secret, string $nonce, string $body): string
    {
        return hash_hmac('sha256', $nonce . "\n" . $body, $secret);
    }

    public static function isFreshTimestamp(string $timestamp, int $maxAgeSeconds = 300): bool
    {
        if (!preg_match('/^\d{10}$/', $timestamp)) return false;
        return abs(time() - (int)$timestamp) <= $maxAgeSeconds;
    }

    public static function isValidNonce(string $nonce): bool
    {
        return (bool)preg_match('/^[a-f0-9]{32,128}$/i', $nonce);
    }
}
