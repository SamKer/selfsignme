<?php

namespace SamKer\SelfSignMe\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;

class SelfSignMeExtension extends Extension
{

    public function getAlias(): string
    {
        return "samker_selfsignme";
    }

     public function load(array $configs, ContainerBuilder $container)
    {
        //je sais plus pourquoi mais on defini une constante pour le type
        foreach ($configs[0]['config'] as $n => $config) {
            $configs[0]['config'][$n]['name'] = $n;
            if (preg_match("#\!php\/const\:(.*)#", $config['algorythme']['private_key_type'], $matches)) {
                    $configs[0]['config'][$n]['algorythme']['private_key_type'] = constant($matches[1]);
                }
        }
        // TODO: Implement load() method.
        $container->setParameter("samker_selfsignme.dir", $configs[0]['dir']);
        $container->setParameter("samker_selfsignme.config", $configs[0]['config']);
        $container->setParameter("samker_selfsignme.survey", $configs[0]['survey']);
    }

}