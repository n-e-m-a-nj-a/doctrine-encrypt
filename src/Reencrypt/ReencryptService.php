<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Reencrypt;

use Doctrine\ORM\EntityManagerInterface;
use NC\DoctrineEncrypt\Encryptor\EncryptorInterface;
use NC\DoctrineEncrypt\Owner\OwnerProviderInterface;

final class ReencryptService
{
    public function __construct( private EntityManagerInterface $em, private OwnerProviderInterface $ownerProvider )
    {}

    /**
     * Re-encrypt a field for a given entity class from $oldEncryptor to $newEncryptor.
     *
     * This is a simple implementation that loads entities via ->findAll().
     * For large datasets implement batching & snapshotting.
     *
     * @return int processed count
     *
     * @throws \ReflectionException
     */
    public function reencryptField(string $entityClass, string $fieldName, EncryptorInterface $oldEncryptor, EncryptorInterface $newEncryptor, bool $computeIndex = false): int
    {
        $repo = $this->em->getRepository($entityClass);
        $entities = $repo->findAll();
        $count = 0;

        foreach ($entities as $entity) {
            $refl = new \ReflectionClass($entity);
            if (!$refl->hasProperty($fieldName)) {
                continue;
            }

            $prop = $refl->getProperty($fieldName);
            $prop->setAccessible(true);
            $stored = $prop->getValue($entity);

            if ($stored === null) {
                continue;
            }

            $owner = $this->ownerProvider->getOwnerFor($entity);

            if ($owner === null) {
                continue;
            }

            $plain = $oldEncryptor->decrypt((string)$stored, $owner);

            if ($plain === null) {
                continue;
            }

            $res = $newEncryptor->encrypt($plain, $owner, $computeIndex);

            $prop->setValue($entity, $res['ciphertext']);

            // attempt to set index if present
            if ($computeIndex) {
                $indexName = $fieldName . '_index';
                if ($refl->hasProperty($indexName)) {
                    $idxProp = $refl->getProperty($indexName);
                    $idxProp->setAccessible(true);
                    $idxProp->setValue($entity, $res['index']);
                }
            }
            $this->em->persist($entity);
            $count++;
            if ($count % 50 === 0) {
                $this->em->flush();
                $this->em->clear();
            }
        }

        $this->em->flush();

        return $count;
    }
}
