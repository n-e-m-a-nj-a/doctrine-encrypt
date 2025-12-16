<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Annotation;

use Doctrine\Common\Annotations\Annotation;

/**
 * @Annotation
 * @Target({"PROPERTY"})
 */
final class Encrypted
{
    public $index = false;

    public $indexColumn;
}
