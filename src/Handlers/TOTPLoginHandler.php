<?php


namespace SilverstripeElliot\TOTPAuthenticator;

use Firesphere\BootstrapMFA\MFALoginHandler;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
class TOTPLoginHandler extends MFALoginHandler
{
    private static $allowed_actions = [
        'MFAForm',
        'validateTOTP'
    ];

    public function validateTOTP($data, $form, $request) {
        $session = $request->getSession();
        $message = false;

        $this->request['BackURL'] = !empty($session->get('MFALogin.BackURL')) ? $session->get('MFALogin.BackURL') : '';
        $member = $this->authenticator->validateTOTP($data, $request, $message);

        if ($member instanceof Member) {

            $memberData = $session->get('MFALogin');

            $this->performLogin($member, $memberData, $request);
            Security::setCurrentUser($member);
            $session->clear('MFAForm');
            return $this->redirectAfterSuccessfulLogin();
        }
        return $this->redirect($this->link());
    }
    public function MFAForm() {

        return TOTPLoginForm::create(
            $this,
            get_class($this->authenticator),
            'MFAForm'
        );
    }
}
