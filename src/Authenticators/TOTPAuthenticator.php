<?php
namespace SilverstripeElliot\TOTPAuthenticator;

use Firesphere\BootstrapMFA\BootstrapMFAAuthenticator;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use lfkeitel\phptotp\{Totp,Base32};
use SilverStripe\Security\DefaultAdminService;

class TOTPAuthenticator extends BootstrapMFAAuthenticator
{
    public function getLoginHandler($link)
    {
        return TOTPLoginHandler::create($link, $this);
    }

    public function validateTOTP($data, $request, &$message)
    {
        $memberID = $request->getSession()->get('MFALogin.MemberID');

        // First, let's see if we know the member
        /** @var Member $member */
        $member = Member::get()->byID(['ID' => $memberID]);

        // Continue if we have a valid member
        if ($member && $member instanceof Member) {

            if(!isset($data['2FAToken'])) {
                $member->registerFailedLogin();
                return false;
            } else {

                $secret = Base32::decode($member->TOTPSecret);
                $key = (new Totp())->GenerateToken($secret);
                $user_submitted_key = $data['2FAToken'];


                if($user_submitted_key !== $key) {
                    return false;
                }
            }


            return $member;

        }
        return null;
    }
}
