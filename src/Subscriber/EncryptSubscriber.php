<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Subscriber;

use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Events;
use Doctrine\Persistence\Event\LifecycleEventArgs;
use NC\DoctrineEncrypt\Annotation\Encrypted as EncryptedAnnotation;
use NC\DoctrineEncrypt\Attribute\Encrypted as EncryptedAttribute;
use NC\DoctrineEncrypt\Encryptor\EncryptorInterface;
use NC\DoctrineEncrypt\Owner\OwnerProviderInterface;

final class EncryptSubscriber implements EventSubscriber
{
    public function __construct(private Reader $annotationReader, private EncryptorInterface $encryptor, private OwnerProviderInterface $ownerProvider) {}

    public function getSubscribedEvents(): array
    {
        return [Events::prePersist, Events::preUpdate, Events::postLoad];
    }

    public function prePersist(LifecycleEventArgs $args): void
    {
        $this->handlePreSave($args);
    }

    public function preUpdate(LifecycleEventArgs $args): void
    {
        $this->handlePreSave($args);
    }

    public function postLoad(LifecycleEventArgs $args): void
    {
        $entity = $args->getObject();
        $refl = new \ReflectionClass($entity);
        foreach ($refl->getProperties() as $prop) {
            $meta = $this->getEncryptedMeta($prop);
            if (null === $meta) {
                continue;
            }
            $prop->setAccessible(true);
            $stored = $prop->getValue($entity);
            if (null === $stored) {
                continue;
            }
            $owner = $this->ownerProvider->getOwnerFor($entity);
            if (null === $owner) {
                continue;
            }
            $plain = null;

            try {
                $plain = $this->encryptor->decrypt((string) $stored, $owner);
            } catch (\Throwable $e) {
                $plain = null;
            }
            if (null !== $plain) {
                $prop->setValue($entity, $plain);
            }
        }
    }

    private function getEncryptedMeta(\ReflectionProperty $prop): ?array
    {
        $ann = $this->annotationReader->getPropertyAnnotation($prop, EncryptedAnnotation::class);
        if ($ann instanceof EncryptedAnnotation) {
            return ['index' => (bool) $ann->index, 'indexColumn' => $ann->indexColumn ?? null];
        }
        $attrs = $prop->getAttributes(EncryptedAttribute::class);
        if (count($attrs) > 0) {
            $inst = $attrs[0]->newInstance();

            return ['index' => (bool) $inst->index, 'indexColumn' => $inst->indexColumn];
        }

        return null;
    }

    private function handlePreSave(LifecycleEventArgs $args): void
    {
        $entity = $args->getObject();
        $refl = new \ReflectionClass($entity);
        foreach ($refl->getProperties() as $prop) {
            $meta = $this->getEncryptedMeta($prop);
            if (null === $meta) {
                continue;
            }
            $prop->setAccessible(true);
            $val = $prop->getValue($entity);
            if (null === $val) {
                continue;
            }
            if (!is_scalar($val)) {
                throw new \RuntimeException('Encrypted property must be scalar');
            }
            $owner = $this->ownerProvider->getOwnerFor($entity);
            if (null === $owner) {
                throw new \RuntimeException('Owner unknown for entity '.get_class($entity));
            }
            $res = $this->encryptor->encrypt((string) $val, $owner, (bool) $meta['index']);
            $prop->setValue($entity, $res['ciphertext']);
            if ($meta['index']) {
                $indexColumn = $meta['indexColumn'] ?? ($prop->getName().'_index');
                if ($refl->hasProperty($indexColumn)) {
                    $idx = $refl->getProperty($indexColumn);
                    $idx->setAccessible(true);
                    $idx->setValue($entity, $res['index']);
                } else {
                    throw new \RuntimeException(sprintf('Index column %s missing on %s', $indexColumn, get_class($entity)));
                }
            }
        }
    }
}
