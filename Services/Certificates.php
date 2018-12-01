<?php
/**
 * Created by PhpStorm.
 * User: samir.keriou
 * Date: 03/10/17
 * Time: 15:46
 */

namespace SamKer\SelfSignMeBundle\Services;


use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Yaml;

class Certificates {

    /**
     * @var Container
     */
    private $container;


    /**
     * @var sting path to dir selsignme
     */
    private $dirConfig;

    /**
     * @var array $config
     */
    private $config;


    public function __construct(Container $container, $params) {
        $this->container = $container;
        $this->dirConfig = $params["dir"];
        $fs = new Filesystem();
        //dirconf
        if (!$fs->exists($this->dirConfig)) {
            $fs->mkdir($this->dirConfig);
        }
        $this->config = $this->parseConfig($params['config']);
    }

    /**
     * parse params for constant php
     * TODO remove in symfony >= 3.2
     *
     * @param array $config
     * @return array $config
     */
    private function parseConfig($config) {
        foreach ($config as $conf => $params) {
            foreach ($params['algorythme'] as $k => $v) {
                if (preg_match("#\!php\/const\:(.*)#", $v, $matches)) {
                    $config[$conf]['algorythme'][$k] = constant($matches[1]);
                }
            }
        }
        return $config;
    }


    /**
     * Create ca
     *
     * @param string $dir    subdir to store certificates
     * @param array  $config options for create certificates with specific conf
     * @throws \Exception
     */
    public function createCA($CN, $conf, $passphrase = false) {
        //test conf
        if (!isset($this->config[$conf])) {
            throw new \Exception("conf option for ca: $conf not exist in parameters");
        }
        $config = $this->config[$conf];

        //check dirconf
        $dir = $this->dirConfig . "/" . $CN;
        $fileKEY = $dir . "/$CN.key";
        $fileCSR = $dir . "/$CN.csr";
        $fileCRT = $dir . "/$CN.crt";
        $fileCNF = $dir . "/$CN.conf";
        //algo crypt
        $config['algorythme']['x509_extensions'] = 'v3_ca';
        $configAlgo = $config['algorythme'];
        //$passphrase
        if ($passphrase === false) {
            $passphrase = $config['passphrase'];
        } else {
            $config['passphrase'] = $passphrase;
        }
        //csr
        $configRequest = $config['csr'];
        //dn
        $configRequest['commonName'] = $CN;

        //$config
        $config['csr'] = $configRequest;
        $yaml = Yaml::dump($config);
//        dump($passphrase);
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
            throw new \Exception("dir $dir exist, specify another CN or delete it first");
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
     * @param string $CN     commonName
     * @param string $conf specific config
     * @param string $passphrase mot de pass
     * @param string $caconf ca à utiliser
     * @param string $capath
     * @param string $capass
     * @return string $dir
     */
    public function createCRT($CN, $conf, $passphrase = false, $caconf = false, $capath = false, $capass = false) {
        $fs = new Filesystem();
        //test conf
        if (!isset($this->config[$conf])) {
            throw new \Exception("conf option for ca: $conf not exist in parameters");
        }
        $config = $this->config[$conf];
        //check dirconf
        $dir = $this->dirConfig . "/" . $CN;
        $fileKEY = $dir . "/$CN.key";
        $fileCSR = $dir . "/$CN.csr";
        $fileCRT = $dir . "/$CN.crt";
        $fileP12 = $dir . "/$CN.p12";
        $fileCNF = $dir . "/$CN.conf";

        //algo crypt
        $configAlgo = $config['algorythme'];
        //$passphrase
        if ($passphrase === false) {
            $passphrase = $config['passphrase'];
        } else {
            $config['passphrase'] = $passphrase;
        }

        //csr
        $configRequest = $config['csr'];
        //dn
        $configRequest['commonName'] = $CN;

        //$config
        $config['csr'] = $configRequest;
        $yaml = Yaml::dump($config);

        //cacert
        if ($capath === false) {
            if ($caconf === false) {
                throw new \Exception("conf option for ca not given");
            }
            $capath = $this->dirConfig . "/" . $caconf . "/" . $caconf . ".crt";

        }
        if ($capass === false) {
            if ($caconf === false) {
                throw new \Exception("conf option for ca not given");
            }
            $caconfig = Yaml::parse(file_get_contents($this->dirConfig . "/" . $caconf . "/" . $caconf . ".conf"));
            $capass = $caconfig['passphrase'];
        }
        $cacert = file_get_contents($capath);
        $capkey = openssl_pkey_get_private('file://'.$this->dirConfig . "/" . $caconf . "/" . $caconf . ".key", $capass);
        if($capkey === false) {
            throw new \Exception(openssl_error_string());
        }
        //create private key
        $privateKey = openssl_pkey_new($configAlgo);
        //new csr
        $csr = openssl_csr_new($configRequest, $privateKey);
        //crt with ca
        $crt = openssl_csr_sign($csr, $cacert, $capkey, $config['days'], $configAlgo, random_int(0,100000));


        if ($fs->exists($dir)) {
            throw new \Exception("dir $dir exist, specify another CN or delete it first");
        }

        $fs->mkdir($dir);

        //write files
        openssl_pkey_export_to_file($privateKey, $fileKEY, $passphrase);
        openssl_csr_export_to_file($csr, $fileCSR);
        openssl_x509_export_to_file($crt, $fileCRT);
        openssl_pkcs12_export_to_file('file://'.$fileCRT, $fileP12, $privateKey, $passphrase);
        file_put_contents($fileCNF, $yaml);
        return $dir;
    }


}