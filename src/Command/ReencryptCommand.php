<?php

declare(strict_types=1);

namespace NC\DoctrineEncrypt\Command;

use NC\DoctrineEncrypt\Encryptor\EncryptorInterface;
use NC\DoctrineEncrypt\Reencrypt\ReencryptService;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class ReencryptCommand extends Command
{
    protected static $defaultName = 'nc:encrypt:reencrypt';

    public function __construct(
        private ReencryptService $service,
        private array $encryptorMap
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('entity', InputArgument::REQUIRED)
            ->addArgument('field', InputArgument::REQUIRED)
            ->addOption('old', null, InputOption::VALUE_REQUIRED)
            ->addOption('new', null, InputOption::VALUE_REQUIRED)
            ->addOption('index', null, InputOption::VALUE_NONE)
            ->setDescription('Re-encrypt a field for all rows of an entity')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $entity = (string) $input->getArgument('entity');
        $field = (string) $input->getArgument('field');
        $old = $input->getOption('old');
        $new = $input->getOption('new');
        $computeIndex = (bool) $input->getOption('index');
        if (!is_string($old) || !is_string($new)) {
            $output->writeln('<error>--old and --new options required and must match configured encryptor keys.</error>');

            return Command::FAILURE;
        }
        if (!isset($this->encryptorMap[$old]) || !isset($this->encryptorMap[$new])) {
            $output->writeln('<error>Encryptor keys not found in map.</error>');

            return Command::FAILURE;
        }

        /** @var EncryptorInterface $oldEnc */
        $oldEnc = $this->encryptorMap[$old];

        /** @var EncryptorInterface $newEnc */
        $newEnc = $this->encryptorMap[$new];
        $output->writeln(sprintf('Re-encrypting %s::%s from %s to %s', $entity, $field, $old, $new));
        $count = $this->service->reencryptField($entity, $field, $oldEnc, $newEnc, $computeIndex);
        $output->writeln(sprintf('Re-encrypted %d entities', $count));

        return Command::SUCCESS;
    }
}
