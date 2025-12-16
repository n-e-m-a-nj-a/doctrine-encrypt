<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Tests\Subscriber;

use Doctrine\Common\Annotations\AnnotationReader;
use Doctrine\Common\Annotations\IndexedReader;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\Event\LifecycleEventArgs;
use NC\DoctrineEncrypt\Encryptor\SodiumEncryptor;
use NC\DoctrineEncrypt\KeyProvider\StaticOwnerKeyProvider;
use NC\DoctrineEncrypt\Owner\OwnerProviderInterface;
use NC\DoctrineEncrypt\Subscriber\EncryptSubscriber;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 *
 * @coversNothing
 */
class EncryptSubscriberTest extends TestCase
{
    public function testPrePersistAndPostLoad()
    {
        if (!function_exists('sodium_crypto_secretbox')) {
            $this->markTestSkipped('sodium not available');
        }
        $ownerId = 'user-123';
        $encKey = random_bytes(32);
        $indexKey = random_bytes(32);
        $provider = new StaticOwnerKeyProvider([$ownerId => ['enc' => $encKey, 'index' => $indexKey, 'kid' => 'v1']]);
        $encryptor = new SodiumEncryptor($provider);
        $annotationReader = new AnnotationReader();
        $reader = new IndexedReader($annotationReader);
        $ownerProvider = new class($ownerId) implements OwnerProviderInterface {
            private $id;

            public function __construct($id)
            {
                $this->id = $id;
            }

            public function getOwnerFor(object $entity): ?string
            {
                if (method_exists($entity, 'getOwnerId')) {
                    return $entity->getOwnerId();
                }

                return $this->id;
            }
        };
        $subscriber = new EncryptSubscriber($reader, $encryptor, $ownerProvider);

        // simple entity
        $entity = new class {
            /**
             * @\NC\DoctrineEncrypt\Annotation\Encrypted(index=true)
             */
            private ?string $secret = null;
            private ?string $secret_index = null;
            private string $ownerId = 'user-123';

            public function setSecret(?string $s)
            {
                $this->secret = $s;
            }

            public function getSecret()
            {
                return $this->secret;
            }

            public function getOwnerId()
            {
                return $this->ownerId;
            }
        };

        $entity->setSecret('top');

        $em = $this->createMock(EntityManagerInterface::class);
        $args = new LifecycleEventArgs($entity, $em);

        // prePersist should replace secret with ciphertext and set index
        $subscriber->prePersist($args);
        $stored = $entity->getSecret();
        $this->assertIsString($stored);
        $this->assertNotSame('top', $stored);

        // postLoad should attempt decryption and restore plaintext
        $subscriber->postLoad($args);
        $this->assertSame('top', $entity->getSecret());
    }
}
