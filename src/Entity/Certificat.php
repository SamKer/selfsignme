<?php

namespace SamKer\SelfSignMe\Entity;

class Certificat
{
    private string $cn;
    private string $issuer;

    private \DateTime $dateEnd;

    private array $certInfos;

    public function getCn(): string
    {
        return $this->cn;
    }

    public function setCn(string $cn): self
    {
        $this->cn = $cn;
        return $this;
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function setIssuer(string $issuer): self
    {
        $this->issuer = $issuer;
        return $this;
    }

    public function getDateEnd(): \DateTime
    {
        return $this->dateEnd;
    }

    public function setDateEnd(\DateTime $dateEnd): self
    {
        $this->dateEnd = $dateEnd;
        return $this;
    }

    public function getCertInfos(): array
    {
        return $this->certInfos;
    }

    public function setCertInfos(array $certInfos): self
    {
        $this->certInfos = $certInfos;
        $this->setCn($certInfos["subject"]["CN"])
            ->setIssuer($certInfos["issuer"]["CN"])
            ->setDateEnd((new \DateTime())->setTimestamp($certInfos["validTo_time_t"]))
            ;
        return $this;
    }


    public function __toArray(): array
    {
        return [
            "cn" => $this->getCn(),
            "issuerCN" => $this->getIssuer(),
            "dateEnd" => $this->getDateEnd(),
            "certInfos" => $this->getCertInfos()
        ];
    }


}