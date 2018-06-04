<?php

namespace ElliotSawyer\TOTPAuthenticator;

use Endroid\QrCode\Exception\InvalidWriterException;
use Endroid\QrCode\QrCode;
use lfkeitel\phptotp\Base32;
use lfkeitel\phptotp\Totp;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\ToggleCompositeField;
use SilverStripe\ORM\DataExtension;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * Class MemberExtension
 *
 * @package ElliotSawyer\TOTPAuthenticator
 * @property MemberExtension $owner
 * @property string $TOTPSecret
 */
class MemberExtension extends DataExtension
{
    /**
     * @var array
     */
    private static $db = [
        'TOTPSecret' => 'Varchar(1024)'
    ];

    /**
     * @throws \Exception
     */
    public function onBeforeWrite()
    {
        // Only regenerate if there is no secret and MFA is not enabled yet
        // Inherits MFAEnabled from Bootstrap object extension
        if (!$this->owner->TOTPSecret || !$this->owner->MFAEnabled) {
            $secret = Totp::GenerateSecret(16);
            $secret = Base32::encode($secret);
            $this->owner->TOTPSecret = $secret;
        }
    }

    /**
     * @param FieldList $fields
     * @throws InvalidWriterException
     */
    public function updateCMSFields(FieldList $fields)
    {
        if (strlen($this->owner->TOTPSecret)) {
            $qrcodeURI = $this->GoogleAuthenticatorQRCode();
            $fields->addFieldToTab('Root.Main', ToggleCompositeField::create(
                null,
                _t(self::class . '.CMSTOGGLEQRCODELABEL', 'Second Factor Token Secret'),
                LiteralField::create(null, sprintf("<img src=\"%s\" />", $qrcodeURI))
            ));
            $fields->removeByName('TOTPSecret');
        }
    }

    /**
     * @return string
     * @throws InvalidWriterException
     */
    public function GoogleAuthenticatorQRCode()
    {
        $qrCode = new QrCode($this->generateOTPAuthString());
        $qrCode->setSize(300);
        $qrCode->setWriterByName('png');
        $qrcodeURI = $qrCode->writeDataUri();

        return $qrcodeURI;
    }

    /**
     * @return string
     */
    public function generateOTPAuthString()
    {
        $label = urlencode(SiteConfig::current_site_config()->Title);
        $secret = $this->owner->TOTPSecret;
        $email = $this->owner->Email;

        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s',
            $label,
            $email,
            $secret,
            $label
        );
    }
}
