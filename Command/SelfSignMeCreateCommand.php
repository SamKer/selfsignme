<?php

namespace SamKer\SelfSignMeBundle\Command;

use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class SelfSignMeCreateCommand extends ContainerAwareCommand {
    protected function configure() {
        $this
            ->setName('selfsignme:create')
            ->setDescription('create self signed certificates')
            ->addArgument('CN', InputArgument::REQUIRED, 'Common name')
            ->addOption('config', 'c', InputOption::VALUE_OPTIONAL, 'choose a specific config', 'default')
            ->addOption('caconf', null, InputOption::VALUE_OPTIONAL, 'choose a specific ca', false)
            ->addOption('capass', null, InputOption::VALUE_OPTIONAL, 'the ca passphrase', false)
            ->addOption('capath', null, InputOption::VALUE_OPTIONAL, 'path/to/ca.key', false)
            ->addOption('passphrase', 'p', InputOption::VALUE_OPTIONAL, 'your passphrase', false)
            ->addOption('type', null, InputOption::VALUE_OPTIONAL, 'create a ca instead', 'crt');
    }

    protected function execute(InputInterface $input, OutputInterface $output) {
        $cn = $input->getArgument('CN');
        $conf = $input->getOption('config');
        $caconf = $input->getOption('caconf');
        $capath = $input->getOption('capath');
        $capass = $input->getOption('capass');
        $passphrase = $input->getOption('passphrase');
        $type = $input->getOption('type');

        switch ($type) {
            case "ca":
                $result = $this->getContainer()->get('self_sign_me.certificates')->createCA($cn, $conf, $passphrase);
                break;
            case 'crt':
            default:
                if ($caconf === false && $capath === false) {
                    throw new \Exception("you have to specify the ca conf with --caconf=[conf] or specify path to ca with --capath=[path/to/ca.key");;
                }
                if ($capath !== false && $capass === false) {
                    throw new \Exception("you have to specify the ca passphrase --capass=[passphrase]");
                }

                $result = $this->getContainer()->get('self_sign_me.certificates')
                               ->createCRT($cn, $conf, $passphrase, $caconf, $capath, $capass);

                break;
        }


        dump($result);
        $output->writeln('Command result.');
    }

}
