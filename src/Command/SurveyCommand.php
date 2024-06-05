<?php

namespace SamKer\SelfSignMe\Command;

use SamKer\SelfSignMe\Lib\Certificates;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Header\Headers;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;
use Twig\Environment;
use Twig\Error\LoaderError;
use Twig\Error\RuntimeError;
use Twig\Error\SyntaxError;
use Twig_Environment;

class SurveyCommand extends Command
{

    protected static $defaultName = 'selfsignme:survey';

    private Environment $twig;

    private array $confSurvey;
    private Certificates $certService;
    private TransportInterface $mailer;

    /**
     * SelfSignMeSurveyCommand constructor.
     * @param Environment $twig
     */
    public function __construct(Environment $twig, array $selfsignmeSurvey, Certificates $certService, TransportInterface $mailer) {
        $this->twig = $twig;
        $this->confSurvey = $selfsignmeSurvey;
        $this->certService = $certService;
        $this->mailer = $mailer;
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

    /**
     * @throws SyntaxError
     * @throws TransportExceptionInterface
     * @throws RuntimeError
     * @throws LoaderError
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $survey = $this->confSurvey;
        $rapport = [];
        $now = new \DateTime();
        foreach ($survey['remote'] as $host) {
            $certificat = $this->certService->checkRemoteCert($host);

            $p = [];
            $date = $certificat->getDateEnd();
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
                $rapport["$dateS-$host"]['issuer']  = $certificat->getIssuer();
                if ($date->diff($now)->days <= 7) {
                    $rapport["$dateS-$host"]['tag'] = 'panic';
                } elseif ($date->diff($now)->days <= 60) {
                    $rapport["$dateS-$host"]['tag'] = 'warning';
                } else {
                    $rapport["$dateS-$host"]['tag'] = 'cool';
                }
            }
        }


//        ksort($rapport);
//        dump($rapport);die;

        $message = new Email();
        foreach ($survey['mailto'] as $to) {
            $message->addTo($to);
        }
        $message->subject("Certificats Check");
        $message->from($survey['mailfrom']);
        $message->html(
            $this->twig->render("@SamKerSelfSignMe/Default/mail.html.twig",
                ['rapport' => $rapport]
            )
        );
        $message->getHeaders()->addHeader("Content-Type", "text/html");

        $mailer = $this->mailer;

        try {
            $sendMessage = $mailer->send($message);
        } catch (TransportExceptionInterface $e) {
            $io->error($e->getMessage());
        }
//        if($r = $sendMessage->getDebug()) {
//            dd($r);
//        }
        dump($rapport);
        return true;


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
