<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Tests\Encryptor;

use NC\DoctrineEncrypt\Encryptor\HybridEncryptor;
use NC\DoctrineEncrypt\KeyProvider\StaticOwnerKeyProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 *
 * @coversNothing
 */
class HybridEncryptorTest extends TestCase
{
    public function testHybridEncryptDecrypt()
    {
        if (!function_exists('sodium_crypto_box_seal')) {
            $this->markTestSkipped('sodium sealed box not available');
        }
        $owner = 'owner-h';
        $keypair = sodium_crypto_box_keypair();
        $pub = sodium_crypto_box_publickey($keypair);
        $kid = 'hk-v1';
        $indexKey = random_bytes(32);
        $provider = new StaticOwnerKeyProvider([$owner => ['pub' => $pub, 'priv' => $keypair, 'index' => $indexKey, 'kid' => $kid]]);
        $enc = new HybridEncryptor($provider);
        $plaintext = 'hybrid secret';
        $res = $enc->encrypt($plaintext, $owner, true);
        $this->assertArrayHasKey('ciphertext', $res);
        $this->assertArrayHasKey('index', $res);
        $this->assertSame(hash_hmac('sha256', $plaintext, $indexKey, false), $res['index']);
        $dec = $enc->decrypt($res['ciphertext'], $owner);
        $this->assertSame($plaintext, $dec);
    }
}
