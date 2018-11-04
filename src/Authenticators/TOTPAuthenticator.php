<?php

namespace ElliotSawyer\TOTPAuthenticator;

use Firesphere\BootstrapMFA\Authenticators\BootstrapMFAAuthenticator;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use Firesphere\BootstrapMFA\Forms\BootstrapMFALoginForm;
use Firesphere\BootstrapMFA\Handlers\BootstrapMFALoginHandler;
use Firesphere\BootstrapMFA\Interfaces\MFAAuthenticator;
use OTPHP\TOTP;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

/**
 * Class TOTPAuthenticator
 * @package ElliotSawyer\TOTPAuthenticator
 */
class TOTPAuthenticator extends BootstrapMFAAuthenticator implements MFAAuthenticator
{
    use Configurable;

    /**
     * Google Authenticator and Authy only support tokens generated with SHA-1
     * Other authenticators MAY implement SHA-256 or SHA-512 as outlined in RFC6238
     * You may use the Config API to adjust this algorithm if you need to support
     * a specific TOTP authenticator
     */
    private static $algorithm = 'sha1';
    
    /**
     * Get configured algorithm for TOTP Authenticator
     *
     * Must be one of: "sha1", "sha256", "sha512"
     * If not specified or invalid, default to "sha1"
     * @return string
     */
    public static function get_algorithm()
    {
        $algorithm = self::config()->get('algorithm');

        return in_array(strtolower($algorithm), ['sha1', 'sha256', 'sha512'])
            ? $algorithm
            : 'sha1';
    }

    /**
     * @param array $data
     * @param HTTPRequest $request
     * @param $token
     * @param ValidationResult $result
     * @return bool|null|Member
     * @throws \Exception
     */
    public function verifyMFA($data, $request, $token, &$result)
    {
        $memberID = $request->getSession()->get(BootstrapMFAAuthenticator::SESSION_KEY . '.MemberID');

        // First, let's see if we know the member
        /** @var Member|null $member */
        $member = Member::get()->byID($memberID);

        // Continue if we have a valid member
        if ($member && $member instanceof Member) {
            if (!$token) {
                $member->registerFailedLogin();

                $result->addError(_t(self::class . '.NOTOKEN', 'No token sent'));
            } else {
                /** @var TOTPProvider $provider */
                $provider = Injector::inst()->get(TOTPProvider::class);
                $provider->setMember($member);
                /** @var TOTP $totp */
                $totp = $provider->fetchToken($token);


                if (!$totp->verify($token)) {
                    $result->addError(_t(self::class . '.TOTPFAILED', 'TOTP Failed'));
                }
            }


            if ($result->isValid()) {
                return $member;
            }
        } else {
            $result->addError(_t(self::class . '.NOMEMBER', 'Member not found'));
        }
    }

    /**
     * @param BootstrapMFALoginHandler $controller
     * @param string $name
     * @return TOTPForm|BootstrapMFALoginForm
     */
    public function getMFAForm($controller, $name)
    {
        return TOTPForm::create($controller, $name, $this);
    }

    /**
     * @return string
     */
    public function getTokenField()
    {
        return 'token';
    }
}
