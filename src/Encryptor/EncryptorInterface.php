<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Encryptor;

interface EncryptorInterface
{
    /**
     * @return array{'ciphertext':string, 'index':null|string }
     */
    public function encrypt(string $plaintext, string $ownerId, bool $deterministic = false): array;

    public function decrypt(string $ciphertext, string $ownerId): ?string;
}
