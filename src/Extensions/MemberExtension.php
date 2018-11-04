<?php

namespace ElliotSawyer\TOTPAuthenticator;

use Endroid\QrCode\QrCode;
use OTPHP\TOTP;
use ParagonIE\ConstantTime\Base32;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\ToggleCompositeField;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Member;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * Class MemberExtension
 *
 * @package ElliotSawyer\TOTPAuthenticator
 * @property Member|MemberExtension $owner
 * @property string $TOTPSecret
 */
class MemberExtension extends DataExtension
{
    /**
     * @var array
     */
    private static $db = [
        'TOTPSecret' => 'Varchar(1024)',
    ];

    /**
     * @throws \Exception
     */
    public function onBeforeWrite()
    {
        // Only regenerate if there is no secret and MFA is not enabled yet
        // Inherits MFAEnabled from Bootstrap object extension
        if (!$this->owner->TOTPSecret || !$this->owner->MFAEnabled) {
            $secret = Base32::encodeUpper(random_bytes(128)); // We generate our own 1024 bits secret
            $this->owner->TOTPSecret = $secret;
        }
    }

    /**
     * @param FieldList $fields
     */
    public function updateCMSFields(FieldList $fields)
    {
        if ($this->owner->TOTPSecret !== '') {
            $qrcodeURI = $this->getQRCode();
            $fields->addFieldToTab('Root.Main', ToggleCompositeField::create(
                null,
                'Second Factor Token Secret',
                LiteralField::create(null, sprintf('<img src="%s" />', $qrcodeURI))
            ));
            $fields->removeByName('TOTPSecret');
        }
    }

    /**
     * @return string
     */
    protected function getQRCode()
    {
        $qrCode = new QrCode($this->generateOTPAuthString());
        $qrCode->setSize(300);
        $qrCode->setWriterByName('png');

        return $qrCode->writeDataUri();
    }

    /**
     * @return string
     */
    protected function generateOTPAuthString()
    {
        $issuer = SiteConfig::current_site_config()->Title;
        $secret = $this->owner->TOTPSecret;
        $label = $this->owner->Email;

        $totp = TOTP::create($secret);
        $totp->setIssuer($issuer);
        $totp->setLabel($label);

        return $totp->getProvisioningUri();
    }
}
