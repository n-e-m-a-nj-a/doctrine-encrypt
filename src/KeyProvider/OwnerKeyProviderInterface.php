<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\KeyProvider;

interface OwnerKeyProviderInterface
{
    /**
     * Return keys for an owner.
     * May include:
     *  - 'enc' => raw symmetric key
     *  - 'index' => raw index key
     *  - 'pub' => raw public key (for hybrid)
     *  - 'priv' => raw keypair (for hybrid decryption)
     *  - 'kid' => key identifier/version string.
     *
     * @return array<string, string>
     */
    public function getKeysForOwner(string $ownerId): array;
}
