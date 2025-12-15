<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Owner;

interface OwnerProviderInterface
{
    /**
     * @param object $entity * @return string|null
     */
    public function getOwnerFor(object $entity): ?string;
}
