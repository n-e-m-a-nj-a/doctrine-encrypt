<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

final class NCDoctrineEncryptExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container)
    {
        $config = $this->processConfiguration(new Configuration(), $configs);

        // Allow service wiring by user; default services are not registered automatically here.
        $container->setParameter('nc_doctrine_encrypt.encryptor_service', $config['encryptor_service']);
        $container->setParameter('nc_doctrine_encrypt.owner_key_provider', $config['owner_key_provider']);
        $container->setParameter('nc_doctrine_encrypt.owner_provider', $config['owner_provider']);
        $container->setParameter('nc_doctrine_encrypt.enable_attributes', $config['enable_attributes']);

        // load services.yaml if exists in bundle (optional, leave to user's app)
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));

        if (file_exists(__DIR__.'/../Resources/config/services.yaml')) {
            $loader->load('services.yaml');
        }
    }
}
