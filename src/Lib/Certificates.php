<?php
/**
 * Created by PhpStorm.
 * User: samir.keriou
 * Date: 03/10/17
 * Time: 15:46
 */

namespace SamKer\SelfSignMe\Lib;


use Exception;
use SamKer\SelfSignMe\Entity\Certificat;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Yaml\Yaml;

class Certificates
{


    private string $dirConfig;

    /**
     * @var array $config
     */
    private array $config;
    private array $survey;


    public function __construct(string $selfsignmeDir, array $selfsignmeConfig, array $selfsignmeSurvey)
    {
        $this->dirConfig = $selfsignmeDir;
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
     *
     * @param string $cn commonName
     * @param string $conf specific config
     * @param string $passphrase mot de pass
     * @param string $caconf ca à utiliser
     * @param string $capath
     * @param string $capass
     * @return string $dir
     */
    public function createCRT(string $cn,string $conf, ?string $passphrase = null, ?string $caconf = null, ?string $capath = null, ?string $capass = null)
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

        //$config
        $config['csr'] = $configRequest;
        $yaml = Yaml::dump($config);

        //cacert
        if ($capath === false) {
            if ($caconf === false) {
                throw new Exception("conf option for ca not given");
            }
            $capath = $this->dirConfig . "/" . $caconf . "/" . $caconf . ".crt";

        }
        if ($capass === false) {
            if ($caconf === false) {
                throw new Exception("conf option for ca not given");
            }
            $caconfig = Yaml::parse(file_get_contents($this->dirConfig . "/" . $caconf . "/" . $caconf . ".conf"));
            $capass = $caconfig['passphrase'];
        }


        $cacert = file_get_contents($capath);
        $capkey = openssl_pkey_get_private('file://' . $this->dirConfig . "/" . $caconf . "/" . $caconf . ".key", $capass);
        if ($capkey === false) {
            throw new Exception(openssl_error_string());
        }
        //create private key
        $privateKey = openssl_pkey_new($configAlgo);
        //new csr
        $csr = openssl_csr_new($configRequest, $privateKey);
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
    public function getDir($cn)
    {
        return $this->dirConfig . "/" . $cn;
    }


    /**
     * give certificates contents
     * @param $cn
     * @return array
     */
    public function dumpCertificates($cn)
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

//        $orignal_parse = parse_url($url, PHP_URL_HOST);
        $get = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => TRUE,
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
