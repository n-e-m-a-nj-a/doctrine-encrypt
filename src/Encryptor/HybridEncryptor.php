<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Encryptor;

use NC\DoctrineEncrypt\KeyProvider\OwnerKeyProviderInterface;

final class HybridEncryptor implements EncryptorInterface
{
    public function __construct(private OwnerKeyProviderInterface $keyProvider)
    {
        if (!\function_exists('sodium_crypto_box_seal')) {
            trigger_error('Sealed box functions not available', E_USER_WARNING);
        }
    }

    public function encrypt(string $plaintext, string $ownerId, bool $deterministic = false): array
    {
        $keys = $this->keyProvider->getKeysForOwner($ownerId);
        if (!isset($keys['pub'])) {
            throw new \RuntimeException('pub key required for hybrid encryptor');
        }
        $ownerPub = $keys['pub'];
        $indexKey = $keys['index'] ?? null;
        $kid = $keys['kid'] ?? null;
        $dataKey = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ct = sodium_crypto_secretbox($plaintext, $nonce, $dataKey);
        $wrapped = sodium_crypto_box_seal($dataKey, $ownerPub);
        $payload = ['v' => 1, 'mode' => 'hybrid', 'kid' => $kid, 'wk' => base64_encode($wrapped), 'nonce' => base64_encode($nonce), 'ct' => base64_encode($ct),];
        $index = null;
        if ($deterministic) {
            if ($indexKey === null) {
                throw new \RuntimeException('index key required for deterministic index');
            }
            $index = hash_hmac('sha256', $plaintext, $indexKey, false);
        }
        sodium_memzero($dataKey);
        if ($indexKey !== null) {
            sodium_memzero($indexKey);
        }
        return ['ciphertext' => base64_encode(json_encode($payload, JSON_UNESCAPED_SLASHES)), 'index' => $index];
    }

    public function decrypt(string $ciphertext, string $ownerId): ?string
    {
        $keys = $this->keyProvider->getKeysForOwner($ownerId);
        if (!isset($keys['priv'])) {
            // Private key unavailable for server;
            // cannot decrypt sealed box
            return null;
        }

        $ownerPriv = $keys['priv'];
        $raw = base64_decode($ciphertext, true);
        if ($raw === false) {
            return null;
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || ($data['mode'] ?? '') !== 'hybrid') {
            return null;
        }
        $wrapped = base64_decode($data['wk']);
        $nonce = base64_decode($data['nonce']);
        $ct = base64_decode($data['ct']);
        $dataKey = sodium_crypto_box_seal_open($wrapped, $ownerPriv);
        if ($dataKey === false) {
            return null;
        }
        $plain = sodium_crypto_secretbox_open($ct, $nonce, $dataKey);
        sodium_memzero($dataKey);
        if ($plain === false) {
            return null;
        }
        return $plain;
    }
}
