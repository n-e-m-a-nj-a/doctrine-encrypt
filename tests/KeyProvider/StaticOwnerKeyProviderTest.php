<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Tests\KeyProvider;

use NC\DoctrineEncrypt\KeyProvider\StaticOwnerKeyProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 *
 * @coversNothing
 */
class StaticOwnerKeyProviderTest extends TestCase
{
    public function testGetKeysForOwner()
    {
        $map = ['o1' => ['enc' => 'x']];
        $p = new StaticOwnerKeyProvider($map);
        $this->assertSame($map['o1'], $p->getKeysForOwner('o1'));
        $this->expectException(\RuntimeException::class);
        $p->getKeysForOwner('missing');
    }
}
