<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\KeyProvider;

/**
 *  Development/testing-only key provider.
 */
final class StaticOwnerKeyProvider implements OwnerKeyProviderInterface
{
    /** * @param array<string,array<string,string>> $map */
    public function __construct(private array $map = []) {}

    public function getKeysForOwner(string $ownerId): array
    {
        if (!isset($this->map[$ownerId])) {
            throw new \RuntimeException(sprintf('No keys for owner %s', $ownerId));
        }

        return $this->map[$ownerId];
    }
}
