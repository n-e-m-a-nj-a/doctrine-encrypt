<?php

declare(strict_types = 1);

namespace NC\DoctrineEncrypt\Encryptor;

interface EncryptorInterface
{
    /**
     *
     * @param string $plaintext
     * @param string $ownerId
     * @param bool $deterministic
     *
     * @return array{'ciphertext':string, 'index':null|string }
     */
    public function encrypt(string $plaintext, string $ownerId, bool $deterministic = false): array;

    /**
     * @param string $ciphertext
     * @param string $ownerId
     *
     * @return string|null
     */
    public function decrypt(string $ciphertext, string $ownerId): ?string;
}
