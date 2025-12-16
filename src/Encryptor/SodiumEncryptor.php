<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Encryptor;

use NC\DoctrineEncrypt\KeyProvider\OwnerKeyProviderInterface;

final class SodiumEncryptor implements EncryptorInterface
{
    public function __construct(private OwnerKeyProviderInterface $keyProvider)
    {
        if (!\function_exists('sodium_crypto_secretbox')) {
            trigger_error('Sodium extension not available', E_USER_WARNING);
        }
    }

    public function encrypt(string $plaintext, string $ownerId, bool $deterministic = false): array
    {
        $keys = $this->keyProvider->getKeysForOwner($ownerId);
        if (!isset($keys['enc'])) {
            throw new \RuntimeException('enc key required for symmetric encryptor');
        }
        $encKey = $keys['enc'];
        $indexKey = $keys['index'] ?? null;
        $kid = $keys['kid'] ?? null;
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ct = sodium_crypto_secretbox($plaintext, $nonce, $encKey);
        $payload = ['v' => 1, 'mode' => 'symmetric', 'kid' => $kid, 'nonce' => base64_encode($nonce), 'ct' => base64_encode($ct)];
        $index = null;
        if ($deterministic) {
            if (null === $indexKey) {
                throw new \RuntimeException('index key required for deterministic index');
            }
            $index = hash_hmac('sha256', $plaintext, $indexKey, false);
        }
        sodium_memzero($encKey);
        if (null !== $indexKey) {
            sodium_memzero($indexKey);
        }

        return ['ciphertext' => base64_encode(json_encode($payload, JSON_UNESCAPED_SLASHES)), 'index' => $index];
    }

    public function decrypt(string $ciphertext, string $ownerId): ?string
    {
        $keys = $this->keyProvider->getKeysForOwner($ownerId);
        if (!isset($keys['enc'])) {
            throw new \RuntimeException('enc key required for symmetric decryptor');
        }
        $encKey = $keys['enc'];
        $raw = base64_decode($ciphertext, true);
        if (false === $raw) {
            return null;
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || ($data['mode'] ?? '') !== 'symmetric') {
            return null;
        }
        $nonce = base64_decode($data['nonce']);
        $ct = base64_decode($data['ct']);
        $plain = sodium_crypto_secretbox_open($ct, $nonce, $encKey);
        sodium_memzero($encKey);
        if (false === $plain) {
            return null;
        }

        return $plain;
    }
}
