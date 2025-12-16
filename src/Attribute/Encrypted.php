<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Attribute;

#[\Attribute(\Attribute::TARGET_PROPERTY)]
final class Encrypted
{
    public function __construct(public bool $index = false, public ?string $indexColumn = null) {}
}
