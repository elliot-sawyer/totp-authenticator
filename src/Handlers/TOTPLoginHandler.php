<?php


namespace SilverstripeElliot\TOTPAuthenticator;

use Psr\Container\NotFoundExceptionInterface;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use SilverStripe\Security\PasswordEncryptor_NotFoundException;
use SilverStripe\Security\Security;
use Firesphere\BootstrapMFA\Handlers\BootstrapMFALoginHandler;

/**
 * Class TOTPLoginHandler
 * @package SilverstripeElliot\TOTPAuthenticator
 */
class TOTPLoginHandler extends BootstrapMFALoginHandler
{
    /**
     * @var array
     */
    private static $allowed_actions = [
        'MFAForm',
        'validateTOTP'
    ];

    /**
     * @param $data
     * @param $form
     * @param HTTPRequest $request
     * @return HTTPResponse
     * @throws NotFoundExceptionInterface
     * @throws ValidationException
     * @throws PasswordEncryptor_NotFoundException
     */
    public function validateTOTP($data, $form, $request)
    {
        $result = Injector::inst()->get(ValidationResult::class);
        $session = $request->getSession();

        $this->request['BackURL'] = !empty($session->get('MFALogin.BackURL')) ? $session->get('MFALogin.BackURL') : '';
        $member = $this->authenticator->validateTOTP($data, $request, $result);

        if (!$member instanceof Member) {
            $member = parent::validate($data, $form, $request, $result);
        }

        if ($member instanceof Member && $result->isValid()) {
            $member->MFAEnabled = true;
            $member->write();
            $memberData = $session->get('MFALogin');

            $this->performLogin($member, $memberData, $request);
            Security::setCurrentUser($member);
            $session->clear('MFAForm');

            return $this->redirectAfterSuccessfulLogin();
        }

        return $this->redirect($this->link());
    }

    /**
     * @return static|TOTPForm
     */
    public function MFAForm()
    {
        return TOTPForm::create(
            $this,
            get_class($this->authenticator),
            'MFAForm'
        );
    }
}
