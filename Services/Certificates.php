<?php
/**
 * Created by PhpStorm.
 * User: samir.keriou
 * Date: 03/10/17
 * Time: 15:46
 */

namespace Sam\SelfSignMeBundle\Services;


use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\DependencyInjection\Dumper\YamlDumper;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;
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
//        $home = posix_getpwuid(posix_getuid())["dir"];
        $this->dirConfig = $params["dir"];
        $fs = new Filesystem();
        //dirconf
        if (!$fs->exists($this->dirConfig)) {
            $fs->mkdir($this->dirConfig);
        }

        $this->config = $this->parseConfig($params['config']);

//        $this->createCA('ca');
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
     * Create certificates self signed
     *
     * @param      $CN
     * @param bool $CA
     */
    public function create($CN, $conf = 'default', $CA = false, $type = 'crt') {
        die('obsolete');
        $fs = new Filesystem();
        if (!isset($this->config[$conf])) {
            throw new \Exception("conf option: $conf not exist in parameters");
        }
        $config = $this->config[$conf];

        if (!isset($this->config[$CA]) && !$fs->exists($CA)) {
            throw new \Exception("conf option for ca: $CA not exist in parameters or path to ca $CA not exist");
        }

        switch ($type) {
            case 'crt':
                $this->createCRT($CN, $config, $CA);
            default:
                break;
            case 'ca':
                $this->createCA($CN, $config);
                break;
            case 'private':
                break;

        }
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

        return [$fileCRT];
    }

    /**
     * Create a certificate
     *
     * @param $CN     commonName
     * @param $config specific config
     * @param $CA     specific configCA or /path/to/ca.pem
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
        $capkey = openssl_pkey_get_private(file_get_contents($this->dirConfig . "/" . $caconf . "/" . $caconf . ".key"), $capass);
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
        file_put_contents($fileCNF, $yaml);
        return [$fileCRT];
    }


}