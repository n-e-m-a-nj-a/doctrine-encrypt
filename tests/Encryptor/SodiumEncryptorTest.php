<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Tests\Encryptor;

use NC\DoctrineEncrypt\Encryptor\SodiumEncryptor;
use NC\DoctrineEncrypt\KeyProvider\StaticOwnerKeyProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 *
 * @coversNothing
 */
class SodiumEncryptorTest extends TestCase
{
    public function testEncryptDecryptAndIndex()
    {
        if (!function_exists('sodium_crypto_secretbox')) {
            $this->markTestSkipped('sodium not available');
        }
        $owner = 'owner-1';
        $encKey = random_bytes(32);
        $indexKey = random_bytes(32);
        $kid = 'v1';
        $provider = new StaticOwnerKeyProvider([$owner => ['enc' => $encKey, 'index' => $indexKey, 'kid' => $kid]]);
        $enc = new SodiumEncryptor($provider);
        $plaintext = 'hello secret';
        $res = $enc->encrypt($plaintext, $owner, true);
        $this->assertArrayHasKey('ciphertext', $res);
        $this->assertArrayHasKey('index', $res);
        $this->assertNotNull($res['index']);
        $this->assertSame(hash_hmac('sha256', $plaintext, $indexKey, false), $res['index']);
        $dec = $enc->decrypt($res['ciphertext'], $owner);
        $this->assertSame($plaintext, $dec);
    }
}
