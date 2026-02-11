<?php

namespace SamKer\SelfSignMe\Command;

use AllowDynamicProperties;
use SamKer\SelfSignMe\Services\Certificates;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Filesystem\Filesystem;

class SelfSignMeCreateCommand extends Command {


    private ?Certificates $certificates;

    public function __construct(?string $name = null, Certificates $certificates = null)
    {
        parent::__construct($name);
        $this->certificates = $certificates;
    }

    protected function configure(): void
    {
        $this
            ->setName('selfsignme:create')
            ->setDescription('create self signed certificates')
            ->addArgument('CN', InputArgument::REQUIRED, 'Common name')
            ->addOption('config', 'c', InputOption::VALUE_OPTIONAL, 'choose a specific config', 'default')
            ->addOption('caconf', null, InputOption::VALUE_OPTIONAL, 'choose a specific ca', false)
            ->addOption('capass', null, InputOption::VALUE_OPTIONAL, 'the ca passphrase', false)
            ->addOption('capath', null, InputOption::VALUE_OPTIONAL, 'path/to/ca.key', false)
            ->addOption('passphrase', 'p', InputOption::VALUE_OPTIONAL, 'your passphrase', false)
            ->addOption('overwrite', null, InputOption::VALUE_OPTIONAL, 'overwrite previous cn', false)
            ->addOption('type', null, InputOption::VALUE_OPTIONAL, 'create a ca instead', 'crt');
    }

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
//        $kernel = $this->getApplication()->getKernel();
//        $service = $kernel->getContainer()->get('self_sign_me.certificates');
        $service = $this->certificates;
        if($overwrite !== false && is_dir($service->getDir($cn))) {
            (new Filesystem())->remove($service->getDir($cn));
        }

        switch ($type) {
            case "ca":
                $result = $service->createCA($cn, $conf, $passphrase);
                break;
            case 'crt':
            default:
                if ($caconf === false && $capath === false) {
                    throw new \Exception("you have to specify the ca conf with --caconf=[conf] or specify path to ca with --capath=[path/to/ca.key");;
                }
                if ($capath !== false && $capass === false) {
                    throw new \Exception("you have to specify the ca passphrase --capass=[passphrase]");
                }
                $result = $service->createCRT($cn, $conf, $passphrase, $caconf, $capath, $capass);
                break;
        }


        $dump = $service->dumpCertificates($cn);


        $output->writeln("<info>les certificats ont été généré ici: $result</info>");

        dump($dump);
        return 0;
    }

}
