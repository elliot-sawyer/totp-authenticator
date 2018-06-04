<?php


namespace ElliotSawyer\TOTPAuthenticator;

use Firesphere\BootstrapMFA\Providers\BootstrapMFAProvider;
use Firesphere\BootstrapMFA\Providers\MFAProvider;
use lfkeitel\phptotp\Base32;
use lfkeitel\phptotp\Totp;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use SilverStripe\Security\PasswordEncryptor_NotFoundException;

/**
 * Class TOTPProvider
 * @package ElliotSawyer\TOTPAuthenticator
 */
class TOTPProvider extends BootstrapMFAProvider implements MFAProvider
{
    /**
     * @param string $token
     * @param null $result
     * @return bool|Member
     * @throws ValidationException
     * @throws PasswordEncryptor_NotFoundException
     * @throws \Exception
     */
    public function verifyToken($token, &$result = null)
    {
        if (!$result) {
            $result = Injector::inst()->get(ValidationResult::class);
        }
        $member = $this->getMember();
        if ($member && $member->ID) {
            if (!$token) {
                $result->addError(_t(self::class . '.INVALIDORMISSINGTOKEN', 'Invalid or missing second factor token'));
            } else {
                $secret = Base32::decode($member->TOTPSecret);
                $key = (new Totp())->GenerateToken($secret);
                $user_submitted_key = $token;
                if ($user_submitted_key !== $key) {
                    $result->addError(_t(self::class . '.INVALIDORMISSINGTOKEN', 'Invalid or missing second factor token'));
                } else {
                    return $this->member;
                }
            }
        }

        return parent::verifyToken($token, $result);
    }
}
