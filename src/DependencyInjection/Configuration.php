<?php

namespace SamKer\SelfSignMe\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treebuilder = new Treebuilder("samker_selfsignme");
        $treebuilder->getRootNode()
            ->children()
                ->scalarNode("dir")->defaultValue("/var/www/var/selfsignme")->end()
                ->arrayNode("config")
                    ->arrayPrototype()
                        ->children()
                            ->scalarNode("name")->defaultValue("name")->end()
                            ->scalarNode("passphrase")->defaultValue("passphrase")->end()
                            ->scalarNode("days")->defaultValue("days")->end()
                            ->arrayNode("algorythme")
                                ->children()
                                    ->scalarNode("digest_alg")->defaultValue("sha512")->end()
                                    ->scalarNode("x509_extensions")->defaultValue("v3_req")->end()
                                    ->integerNode("private_key_bits")->defaultValue(2048)->end()
                                    ->scalarNode("private_key_type")->defaultValue("!php/const:OPENSSL_KEYTYPE_RSA")->end()
                                ->end()
                            ->end()
                            ->arrayNode("csr")
                                ->children()
                                    ->scalarNode("countryName")->defaultValue("FR")->end()
                                    ->scalarNode("stateOrProvinceName")->defaultValue("STATE")->end()
                                    ->scalarNode("localityName")->defaultValue("CITY")->end()
                                    ->scalarNode("organizationName")->defaultValue("ORGA")->end()
                                    ->scalarNode("organizationalUnitName")->defaultValue("CIE")->end()
                                    ->scalarNode("commonName")->defaultValue("dn")->end()
                                    ->scalarNode("emailAddress")->defaultValue("mail")->end()
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
                ->arrayNode("survey")
                    ->children()
                        ->arrayNode("extensions")
                            ->scalarPrototype()->defaultValue("ext")->end()
                        ->end()
                        ->scalarNode("mailfrom")->defaultValue("mail_from")->end()
                        ->arrayNode("mailto")
                            ->scalarPrototype()->defaultValue("mail")->end()
                        ->end()
                        ->arrayNode("local")
                            ->scalarPrototype()->defaultValue("url")->end()
                        ->end()
                        ->arrayNode("remote")
                            ->scalarPrototype()->defaultValue("url")->end()
                        ->end()
                    ->end()
                ->end()
            ->end();
        return $treebuilder;
    }
}
