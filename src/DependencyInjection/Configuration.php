<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $tb = new TreeBuilder('nc_doctrine_encrypt');
        $root = $tb->getRootNode();
        $root->children()
            ->scalarNode('encryptor_service')
            ->defaultNull()
            ->end()
            ->scalarNode('owner_key_provider')
            ->defaultNull()
            ->end()
            ->scalarNode('owner_provider')
            ->defaultNull()
            ->end()
            ->booleanNode('enable_attributes')
            ->defaultTrue()
            ->end()
            ->end()
        ;

        return $tb;
    }
}
