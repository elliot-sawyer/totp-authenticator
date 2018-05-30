<?php

namespace SilverstripeElliot\TOTPAuthenticator;

use Firesphere\BootstrapMFA\Authenticators\BootstrapMFAAuthenticator;
use Firesphere\BootstrapMFA\Handlers\MFALoginHandler;
use lfkeitel\phptotp\Base32;
use lfkeitel\phptotp\Totp;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

/**
 * Class TOTPAuthenticator
 * @package SilverstripeElliot\TOTPAuthenticator
 */
class TOTPAuthenticator extends BootstrapMFAAuthenticator
{
    /**
     * @param string $link
     * @return \SilverStripe\Security\MemberAuthenticator\LoginHandler|static
     */
    public function getLoginHandler($link)
    {
        return TOTPLoginHandler::create($link, $this);
    }

    /**
     * @param $data
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
                $key = (new Totp())->GenerateToken($secret);
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
}
