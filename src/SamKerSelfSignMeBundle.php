<?php

namespace SamKer\SelfSignMe;

use SamKer\SelfSignMe\DependencyInjection\SelfSignMeExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class SamKerSelfSignMeBundle extends Bundle
{

    public function getContainerExtension(): ?ExtensionInterface
    {
        if (null === $this->extension) {
            $this->extension = new SelfSignMeExtension();
        }
        return $this->extension;
    }
}
