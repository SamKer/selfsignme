<?php

namespace SamKer\SelfSignMeBundle\Command;

use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;

class SelfSignMeSurveyCommand extends ContainerAwareCommand
{

    protected static $defaultName = 'selfsignme:survey';

    /**
     * @var \Twig_Environment
     */
    private $twig;

    /**
     * SelfSignMeSurveyCommand constructor.
     * @param \Twig_Environment $twig
     */
    public function __construct(\Twig_Environment $twig) {
        $this->twig = $twig;
        parent::__construct();
    }

    protected function configure()
    {
        $this
            ->setName('selfsignme:survey')
            ->setDescription('vérifie les certificats')
//            ->addArgument('argument', InputArgument::OPTIONAL, 'Argument description')
//            ->addOption('option', null, InputOption::VALUE_NONE, 'Option description')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
//        $argument = $input->getArgument('argument');
        $config = $this->getContainer()->getParameter('selfsignme');
        $survey = $config['survey'];

//        foreach ($survey['local'] as $certFile) {
//
//        }
//        dump($survey);die;
// nmap -p 443 --script ssl-cert sagef.dvgendarmerie.fr | grep "Not valid after" | cut -d':' -f2
//        openssl s_client -connect sagef.dvgendarmerie.fr:443

        $rapport = [];

        foreach ($survey['remote'] as $host) {
            $rapport[$host] = ["expire_at"=>"","mail_at"=>"", "error"=>""];
            $cmd = "nmap -p 443 --script ssl-cert $host | grep 'Not valid after' | cut -d':' -f2,3,4";
            $date = $this->cmd($cmd);
            $date = $this->formatDate($date);
            if(!$date) {
                $rapport[$host]['error']  = "impossible de récupérer les infos";
            }
            $rapport[$host]['expire_at'] = $date->format("d/m/Y");
            $dateMail = $date->sub(new \DateInterval("P2M"));
            $rapport[$host]['mail_at'] = $dateMail->format("d/m/Y");

        }

        $message = new \Swift_Message("SURVEY CERTIFICATES");
        $message->setTo($survey['mailto']);
        $message->setFrom($survey['mailfrom']);
        $message->setBody(
            $this->twig->render("@SamKerSelfSignMe/Default/mail.html.twig",
                ['rapport' => $rapport]
            )
        );
        $mailer = $this->getContainer()->get('mailer');
        $recipients = $mailer->send($message);

        dump($recipients);die;


    }

    private function formatDate($date) {
        $date = trim($date);
        if (preg_match("#([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})#", $date, $matches)) {
            $d = new \DateTime();
            $d->setDate($matches[1],$matches[2],$matches[3]);
            $d->setTime($matches[4],$matches[5],$matches[6]);
            return $d;
        }
        return false;
    }

    private function cmd($cmd) {
        $process = new Process($cmd);
        $process->run();
        if (!$process->isSuccessful()) {
            throw new ProcessFailedException($process);
        }


        return $process->getOutput();

    }

}
