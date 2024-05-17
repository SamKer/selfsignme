<?php
/**
 * Created by PhpStorm.
 * User: samir.keriou
 * Date: 03/10/17
 * Time: 15:46
 */

namespace SamKer\SelfSignMe\Lib;


use Exception;
use Jelix\IniFile\IniException;
use Jelix\IniFile\IniModifier;
use Random\RandomException;
use SamKer\SelfSignMe\Entity\Certificat;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Yaml\Yaml;
use function Webmozart\Assert\Tests\StaticAnalysis\boolean;

class Certificates
{


    private string $dirConfig;

    /**
     * @var array $config
     */
    private array $config;
    private array $survey;
    private string $opensslConf;


    public function __construct(
        string $selfsignmeDir,
        string $selfsignmeOpensslConf,
        array $selfsignmeConfig,
        array $selfsignmeSurvey
    )
    {
        $this->dirConfig = $selfsignmeDir;
        $this->opensslConf = $selfsignmeOpensslConf;
        $fs = new Filesystem();
        //dirconf
        if (!$fs->exists($this->dirConfig)) {
            $fs->mkdir($this->dirConfig);
        }
        $this->config = $selfsignmeConfig;
        $this->survey = $selfsignmeSurvey;
    }


    /**
     * Create ca
     *
     * @param string $cn subdir to store certificates
     * @param string $conf options for create certificates with specific conf
     * @param ?string $passphrase
     * @throws Exception
     */
    public function createCA(string $cn, string $conf,?string  $passphrase = null): string
    {
        //test conf
        if (!isset($this->config[$conf])) {
            throw new Exception("conf option for ca: $conf not exist in parameters");
        }
        $config = $this->config[$conf];

        //check dirconf
        $dir = $this->dirConfig . "/" . $cn;
        $fileKEY = $dir . "/$cn.key";
        $fileCSR = $dir . "/$cn.csr";
        $fileCRT = $dir . "/$cn.crt";
        $fileCNF = $dir . "/$cn.conf";
        //algo crypt
        $config['algorythme']['x509_extensions'] = 'v3_ca';
        $configAlgo = $config['algorythme'];
        //$passphrase
        if ($passphrase === null && $config['passphrase'] !== false) {
            $passphrase = $config['passphrase'];
        } else {
            $config['passphrase'] = $passphrase;
        }
        //csr
        $configRequest = $config['csr'];
        //dn
        $configRequest['commonName'] = $cn;

        //$config
        $config['csr'] = $configRequest;
        $yaml = Yaml::dump($config);
//        dump($passphrase);die;
//        dump($configRequest);
//        dump($configAlgo);die;
        //create private key
        $privateKey = openssl_pkey_new($configAlgo);
        //new csr
        $csr = openssl_csr_new($configRequest, $privateKey);
        //crt self signed
        $crt = openssl_csr_sign($csr, null, $privateKey, $config['days'], $configAlgo);

        $fs = new Filesystem();
        if ($fs->exists($dir)) {
            throw new Exception("dir $dir exist, specify another CN or delete it first");
        }

        $fs->mkdir($dir);

        //write files
        openssl_pkey_export_to_file($privateKey, $fileKEY, $passphrase);
        openssl_csr_export_to_file($csr, $fileCSR);
        openssl_x509_export_to_file($crt, $fileCRT);
        file_put_contents($fileCNF, $yaml);

        return $dir;
    }

    /**
     * Create a certificate
     * Les San ne semble pas être pris en compte en option pour les csr
     * On utilise ici la méthode classique de modifier le openssl.cnf en live pour le fournir à la fct openssl_new_csr
     *
     * @param string $cn commonName
     * @param string $conf specific config
     * @param string|null $passphrase mot de pass
     * @param string|null $caconf ca à utiliser
     * @param string|null $capath
     * @param string|null $capass
     * @param array $san
     * @return string $dir
     * @throws RandomException
     * @throws IniException
     */
    public function createCRT(
        string $cn,
        string $conf,
        ?string $passphrase = null,
        ?string $caconf = null,
        ?string $capath = null,
        ?string $capass = null,
        array $san = []
    ): string
    {
        $fs = new Filesystem();
        //test conf
        if (!isset($this->config[$conf])) {
            throw new Exception("conf option for ca: $conf not exist in parameters");
        }
        $config = $this->config[$conf];
        //check dirconf
        $dir = $this->dirConfig . "/" . $cn;
        $fileKEY = $dir . "/$cn.key";
        $fileCSR = $dir . "/$cn.csr";
        $fileCRT = $dir . "/$cn.crt";
        $fileP12 = $dir . "/$cn.p12";
        $fileCNF = $dir . "/$cn.conf";

        //opensslConfTmpFile
        if(!file_exists($this->opensslConf)) {
            throw new Exception("openssl.cnf not found at ". $this->opensslConf);
        }
        $opensslConf = $this->dirConfig . "/openssl.cnf";
        copy($this->opensslConf, $opensslConf);

        //algo crypt
        $configAlgo = $config['algorythme'];
        //$passphrase
        if ($passphrase === null) {
            $passphrase = $config['passphrase'];
        } else {
            $config['passphrase'] = $passphrase;
        }

        //csr
        $configRequest = $config['csr'];

        //dn
        $configRequest['commonName'] = $cn;

        //SAN
        if(empty($san)) {
            $san[] = $cn;
        }
        if(!in_array($cn, $san)) {
            $san[] = $cn;
        }
        $subjectAltName = implode(",", array_map(
            function ($dn) {
                return "DNS:" . $dn;
            }, $san)
        );

        $ini = new IniModifier($opensslConf);
        $ini->setValue("subjectAltName", "@selfsignme_san", " v3_req ");
        foreach ($san as $i => $dn) {
            $ini->setValue("DNS.$i", "$dn", " selfsignme_san ");
        }

        $ini->save();
        putenv("SELFSIGNME_SUBJECTALTNAME=$subjectAltName");


        //$config
        $config['csr'] = $configRequest;
        $yaml = Yaml::dump($config);

        //cacert
        if ($capath === null) {
            if ($caconf === null) {
                throw new Exception("conf option for ca not given");
            }
            $capath = $this->dirConfig . "/" . $caconf . "/" . $caconf . ".crt";
            if(!file_exists($capath)) {
                throw new Exception("path for ca conf not exist");
            }
        }
        if ($capass === null) {
            if ($caconf === null) {
                throw new Exception("conf option for ca not given");
            }
            $caconfig = Yaml::parse(file_get_contents($this->dirConfig . "/" . $caconf . "/" . $caconf . ".conf"));
            $capass = $caconfig['passphrase'];
        }

        $cacert = file_get_contents($capath);
        $capkey = openssl_pkey_get_private("file://$this->dirConfig/$caconf/$caconf.key", $capass);
        if ($capkey === false) {
            throw new Exception(openssl_error_string());
        }
        //create private key
        $privateKey = openssl_pkey_new($configAlgo);
        //new csr
        // conf
        $configAlgo['config'] = $opensslConf;
       $configAlgo['req_extensions']= 'v3_req';
        $csr = openssl_csr_new($configRequest, $privateKey, $configAlgo);

        //crt with ca
        $crt = openssl_csr_sign($csr, $cacert, $capkey, $config['days'], $configAlgo, random_int(0, 100000));


        if ($fs->exists($dir)) {
            throw new Exception("dir $dir exist, specify another CN or delete it first");
        }

        $fs->mkdir($dir);

        //write files
        openssl_pkey_export_to_file($privateKey, $fileKEY, $passphrase);
        openssl_csr_export_to_file($csr, $fileCSR);
        openssl_x509_export_to_file($crt, $fileCRT);
        openssl_pkcs12_export_to_file('file://' . $fileCRT, $fileP12, $privateKey, $passphrase);
        file_put_contents($fileCNF, $yaml);
        return $dir;
    }

    /**
     * Give certificates directory for cn
     * @param string $cn
     * @return string $dir;
     */
    public function getDir($cn): string
    {
        return $this->dirConfig . "/" . $cn;
    }


    /**
     * give certificates contents
     * @param $cn
     * @return array
     */
    public function dumpCertificates($cn): array
    {
        $dump = ["cn" => $cn, "storage_directory" => $this->getDir($cn)];
        $finder = new Finder();
        $files = $finder->files()->in($this->getDir($cn));
        foreach ($files as $file) {
            $dump[$file->getExtension()] = $file->getContents();
        }
        return $dump;
    }

    public function checkRemoteCert(string $url): Certificat
    {
        $get = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "verify_peer" => false
            ]
        ]);

        $read = stream_socket_client(
            "ssl://" . $url . ":443",
            $errno,
            $errstr,
            30,
            STREAM_CLIENT_CONNECT,
            $get
        );
        if($errstr) {
            throw new Exception($errstr);
        }
        $cert = stream_context_get_params($read);

        $certificat = new Certificat();
        $certificat->setCertInfos(openssl_x509_parse($cert['options']['ssl']['peer_certificate']));
        return $certificat;
    }


}
