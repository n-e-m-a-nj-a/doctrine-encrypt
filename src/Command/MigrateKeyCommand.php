<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Command;

use NC\DoctrineEncrypt\Reencrypt\ReencryptService;
use NC\DoctrineEncrypt\Encryptor\EncryptorInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** * Simple key migration command wrapper around ReencryptService. * Use --index to recompute deterministic index. */
final class MigrateKeyCommand extends Command
{
    protected static $defaultName = 'nc:encrypt:migrate-keys';

    public function __construct(private ReencryptService $service, private array $encryptorMap)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('entity', InputArgument::REQUIRED)
            ->addArgument('field', InputArgument::REQUIRED)
            ->addOption('from', null, InputOption::VALUE_REQUIRED)
            ->addOption('to', null, InputOption::VALUE_REQUIRED)
            ->addOption('index', null, InputOption::VALUE_NONE)
            ->setDescription('Migrate encryption keys by re-encrypting a field from one encryptor to another')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $entity = (string)$input->getArgument('entity');
        $field = (string)$input->getArgument('field');
        $from = $input->getOption('from');
        $to = $input->getOption('to');
        $computeIndex = (bool)$input->getOption('index');
        if (!is_string($from) || !is_string($to)) {
            $output->writeln('<error>--from and --to must be provided</error>');
            return Command::FAILURE;
        }
        if (!isset($this->encryptorMap[$from]) || !isset($this->encryptorMap[$to])) {
            $output->writeln('<error>Encryptor keys not configured</error>');
            return Command::FAILURE;
        }
        $count = $this->service->reencryptField($entity, $field, $this->encryptorMap[$from], $this->encryptorMap[$to], $computeIndex);
        $output->writeln(sprintf('Migrated %d entities', $count));
        return Command::SUCCESS;
    }
}
