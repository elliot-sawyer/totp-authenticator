<?php


namespace SilverstripeElliot\TOTPAuthenticator;


use Firesphere\BootstrapMFA\BootstrapMFAProvider;
use lfkeitel\phptotp\{Base32,Totp};

class TOTPProvider extends BootstrapMFAProvider
{
    public function verifyToken($token, &$result = null)
    {
        $member = $this->getMember();
        if($member && $member->ID) {
            if(!isset($token)) {
                $result->addError('Invalid or missing second factor token');
            } else {
                $secret = Base32::decode($member->TOTPSecret);
                $key = (new Totp())->GenerateToken($secret);
                $user_submitted_key = $token;
                if($user_submitted_key !== $key) {
                    $result->addError('Invalid or missing second factor token');
                } else {
                    return $this->member;
                }


            }
        }
        return parent::verifyToken($token, $result);
    }
}
