<?php

namespace SamKer\SelfSignMe\Command;

use SamKer\SelfSignMe\Lib\Certificates;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;
use Twig\Environment;
use Twig_Environment;

class SurveyCommand extends Command
{

    protected static string $defaultName = 'selfsignme:survey';

    private Environment $twig;

    private array $confSurvey;
    private Certificates $certService;

    /**
     * SelfSignMeSurveyCommand constructor.
     * @param Environment $twig
     */
    public function __construct(Environment $twig, array $selfsignmeSurvey, Certificates $certService) {
        $this->twig = $twig;
        $this->confSurvey = $selfsignmeSurvey;
        $this->certService = $certService;
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('selfsignme:survey')
            ->setDescription('vérifie les certificats')
//            ->addArgument('argument', InputArgument::OPTIONAL, 'Argument description')
//            ->addOption('option', null, InputOption::VALUE_NONE, 'Option description')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $survey = $this->confSurvey;

        $rapport = [];


        $url = "https://partage-ng.psi.minint.fr";
        $this->certService->checkRemoteCert($url);
$orignal_parse = parse_url($url, PHP_URL_HOST);
$get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE)));
$read = stream_socket_client("ssl://".$orignal_parse.":443", $errno, $errstr,
30, STREAM_CLIENT_CONNECT, $get);
$cert = stream_context_get_params($read);
$certinfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);

dd($certinfo);


        $now = new \DateTime();
        foreach ($survey['remote'] as $host) {

            $cmd = "nmap -p 443 --script ssl-cert $host";
//            $cmd = "nmap -p 443 --script ssl-cert $host | grep 'Not valid after' | cut -d':' -f2,3,4";
//            $date = $this->cmd($cmd);
            $r = $this->cmd($cmd);
            $r = explode("\n", $r);
            $p = [];
            foreach ($r as $l) {
                if(preg_match("#Not valid after: (.*)#", $l, $matches)) {
                    $p['date'] = $matches[1];
                }
                if(preg_match("#Issuer: commonName=(.*)/organ#", $l, $matches)) {
                    $p['issuer'] = $matches[1];
                }
            }

            $date = $this->formatDate($p['date']);
            if(!$date) {
                $rapport[$host] = [];
                $rapport[$host]['error']  = "impossible de récupérer les infos";
                $rapport[$host]['tag']  = "wtf";
                $rapport[$host]['expire_at']  = "/";
                $rapport[$host]['dn']  = $host;
                $rapport[$host]['issuer']  = $p['issuer'];
            } else {
                $dateS = $date->format("Y-m-d");
                $rapport["$dateS-$host"] = [];
                $rapport["$dateS-$host"]['expire_at'] = $date->format("d/m/Y");
                $rapport["$dateS-$host"]['error'] = "";
                $rapport["$dateS-$host"]['dn'] = $host;
                $rapport["$dateS-$host"]['issuer']  = $p['issuer'];
                if ($date->diff($now)->days <= 7) {
                    $rapport["$dateS-$host"]['tag'] = 'panic';
                } elseif ($date->diff($now)->days <= 60) {
                    $rapport["$dateS-$host"]['tag'] = 'warning';
                } else {
                    $rapport["$dateS-$host"]['tag'] = 'cool';
                }
            }
        }


        ksort($rapport);
        dump($rapport);die;

        $message = new \Swift_Message("SURVEY CERTIFICATES");
        $message->setTo($survey['mailto']);
        $message->setFrom("samir.keriou@gendarmerie.interieur.gouv.fr");
        $message->setBody(
            $this->twig->render("@SamKerSelfSignMe/Default/mail.html.twig",
                ['rapport' => $rapport]
            )
        );
        $message->setContentType("text/html");

        $mailer = $this->getContainer()->get('mailer');


        $logger = new \Swift_Plugins_Loggers_ArrayLogger();
        $mailer->registerPlugin(new \Swift_Plugins_LoggerPlugin($logger));
//        dump($mailer);die;

//        $transport = $this->getContainer()->get('swiftmailer.mailer.default.transport');
//        $transport->setStreamOptions(array('ssl' => array('allow_self_signed' => true, 'verify_peer' => false,'verify_peer_name' => false)));

        $recipients = $mailer->send($message);

        dump($recipients);
        dump($logger->dump());
//        die;


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

    private function cmd($cmd): string
    {
        $process = new Process([$cmd]);
        $process->run();
        if (!$process->isSuccessful()) {
            throw new ProcessFailedException($process);
        }


        return $process->getOutput();

    }

}
