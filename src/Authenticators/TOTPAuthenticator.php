<?php

namespace ElliotSawyer\TOTPAuthenticator;

use Firesphere\BootstrapMFA\Authenticators\BootstrapMFAAuthenticator;
use lfkeitel\phptotp\Base32;
use lfkeitel\phptotp\Totp;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

/**
 * Class TOTPAuthenticator
 * @package ElliotSawyer\TOTPAuthenticator
 */
class TOTPAuthenticator extends BootstrapMFAAuthenticator
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
     * @param string $link
     * @return \SilverStripe\Security\MemberAuthenticator\LoginHandler|static
     */
    public function getLoginHandler($link)
    {
        return TOTPLoginHandler::create($link, $this);
    }

    /**
     * @param array $data
     * @param HTTPRequest $request
     * @param ValidationResult $result
     * @return bool|null|Member
     * @throws \Exception
     */
    public function validateTOTP($data, $request, &$result)
    {
        $memberID = $request->getSession()->get(BootstrapMFAAuthenticator::SESSION_KEY . '.MemberID');

        // First, let's see if we know the member
        /** @var Member $member */
        $member = Member::get()->byID($memberID);

        // Continue if we have a valid member
        if ($member && $member instanceof Member) {
            if (!isset($data['token'])) {
                $member->registerFailedLogin();

                $result->addError(_t(self::class . '.NOTOKEN', 'No token sent'));
            } else {
                $secret = Base32::decode($member->TOTPSecret);
                $key = $this->getTokenFromTOTP($secret);
                $user_submitted_key = $data['token'];

                if ($user_submitted_key !== $key) {
                    $result->addError(_t(self::class . '.TOTPFAILED', 'TOTP Failed'));
                }
            }


            if ($result->isValid()) {
                return $member;
            }
        }

        $result->addError(_t(self::class . '.NOMEMBER', 'Member not found'));

        return $result;
    }

    /**
     * Given a TOTP secret, use Totp to resolve to a one time token
     *
     * @param string $secret
     * @param string $algorithm If not provided, will default to the configured algorithm
     * @return bool|int|string
     */
    protected function getTokenFromTOTP($secret, $algorithm = '')
    {
        if (!$algorithm) {
            $algorithm = self::get_algorithm();
        }

        $totp = new Totp($algorithm);
        return $totp->GenerateToken($secret);
    }

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
}
