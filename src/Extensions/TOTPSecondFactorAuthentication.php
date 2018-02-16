<?php


namespace SilverstripeElliot\TOTPAuthenticator;

use SilverStripe\ORM\DataExtension;

use lfkeitel\phptotp\{Base32,Totp};
use SilverStripe\SiteConfig\SiteConfig;
use SilverStripe\Forms\{FieldList,LiteralField,ToggleCompositeField};

class TOTPSecondFactorAuthExtension extends DataExtension
{
    private static $db = [
        'TOTPSecret' => 'Varchar(1024)'
    ];
    public function onBeforeWrite() {
        if(strlen($this->owner->TOTPSecret) == 0) {
            $secret = Totp::GenerateSecret(16);
            $secret = Base32::encode($secret);
            $this->owner->TOTPSecret = $secret;
        }
    }

    public function updateCMSFields(\SilverStripe\Forms\FieldList $fields)
    {
        if(strlen($this->owner->TOTPSecret)) {

            $qrcodeURI = $this->GoogleAuthenticatorQRCode();

            $fields->addFieldToTab('Root.Main', ToggleCompositeField::create(null, 'Second Factor Token Secret',
                LiteralField::create(null, sprintf("<img src=\"%s\" />", $qrcodeURI))
            ));

            $fields->removeByName('TOTPSecret');

        }

    }

    public function generateOTPAuthString() {

        $label = urlencode(SiteConfig::current_site_config()->Title);
        $secret = $this->owner->TOTPSecret;
        $email = $this->owner->Email;
        return sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
            $label,
            $email,
            $secret,
            $label
        );
    }

    public function GoogleAuthenticatorQRCode() {
        $qrCode = new \Endroid\QrCode\QrCode($this->generateOTPAuthString());
        $qrCode->setSize(300);
        $qrCode->setWriterByName('png');
        $qrcodeURI = $qrCode->writeDataUri();

        return $qrcodeURI;
    }

}
