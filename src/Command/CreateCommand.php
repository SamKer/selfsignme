<?php

namespace SamKer\SelfSignMe\Command;

use SamKer\SelfSignMe\Lib\Certificates;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Filesystem\Filesystem;

class CreateCommand extends Command
{

    private Certificates $certService;

    public function __construct(Certificates $certificateService, ?string $name = null)
    {
        parent::__construct($name);
        $this->certService = $certificateService;

    }

    protected function configure(): void
    {
        $this
            ->setName('selfsignme:create')
            ->setDescription('create self signed certificates')
            ->addArgument('CN', InputArgument::REQUIRED, 'Common name')
            ->addOption('config', 'c', InputOption::VALUE_OPTIONAL, 'choose a specific config', 'default')
            ->addOption('caconf', null, InputOption::VALUE_OPTIONAL, 'choose a specific ca', null)
            ->addOption('capass', null, InputOption::VALUE_OPTIONAL, 'the ca passphrase', null)
            ->addOption('capath', null, InputOption::VALUE_OPTIONAL, 'path/to/ca.key', null)
            ->addOption('passphrase', 'p', InputOption::VALUE_OPTIONAL, 'your passphrase', null)
            ->addOption('overwrite', null, InputOption::VALUE_OPTIONAL, 'overwrite previous cn', null)
            ->addOption('san', null, InputOption::VALUE_IS_ARRAY | InputArgument::OPTIONAL, 'subject Alt Name, repeat otpion', [])
            ->addOption('type', null, InputOption::VALUE_OPTIONAL, 'create a ca instead', 'crt');
    }

    /**
     * @throws \Exception
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $cn = $input->getArgument('CN');
        $conf = $input->getOption('config');
        $caconf = $input->getOption('caconf');
        $capath = $input->getOption('capath');
        $capass = $input->getOption('capass');
        $passphrase = $input->getOption('passphrase');
        $overwrite = $input->getOption('overwrite');
        $type = $input->getOption('type');

        $san = $input->getOption('san');
        $san[] = $cn;

        $service = $this->certService;
        if ($overwrite !== false && is_dir($service->getDir($cn))) {
            (new Filesystem())->remove($service->getDir($cn));
        }

        switch ($type) {
            case "ca":
                $result = $service->createCA($cn, $conf, $passphrase);
                break;
            case 'crt':
            default:
                if ($caconf === null && $capath === null) {
                    throw new \Exception("you have to specify the ca conf with --caconf=[conf] or specify path to ca with --capath=[path/to/ca.key");;
                }
                if ($capath !== null && $capass === null) {
                    throw new \Exception("you have to specify the ca passphrase --capass=[passphrase]");
                }
                $result = $service->createCRT($cn, $conf, $passphrase, $caconf, $capath, $capass, $san);
                break;
        }


        $dump = $service->dumpCertificates($cn);


        $output->writeln("<info>les certificats ont été généré ici: $result</info>");

        dump($dump);
        return true;
    }

}
