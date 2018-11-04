<?php


namespace ElliotSawyer\TOTPAuthenticator;

use Firesphere\BootstrapMFA\Interfaces\MFAProvider;
use Firesphere\BootstrapMFA\Providers\BootstrapMFAProvider;
use OTPHP\TOTP;

/**
 * Class TOTPProvider
 * @package ElliotSawyer\TOTPAuthenticator
 */
class TOTPProvider extends BootstrapMFAProvider implements MFAProvider
{
    /**
     * @param string $token
     * @return bool|TOTP
     * @throws \Exception
     */
    public function fetchToken($token = null)
    {
        $member = $this->getMember();
        if ($member && $member->ID) {
            $algorithm = TOTPAuthenticator::get_algorithm();

            return TOTP::create($member->TOTPSecret, 30, $algorithm);
        }

        return false;
    }
}
