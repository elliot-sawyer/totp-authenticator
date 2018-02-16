<?php
namespace SilverstripeElliot\TOTPAuthenticator;
use Firesphere\BootstrapMFA\MFALoginForm;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Forms\{PasswordField,HiddenField,FieldList,FormAction,RequiredFields};

class TOTPLoginForm extends MFALoginForm
{
    public function __construct(
        RequestHandler $controller = null,
        $validator = null,
        $name = self::DEFAULT_NAME
    ) {
        $this->controller = $controller;
        $validator = RequiredFields::create(['token']);
        $fields = $this->getFormFields();
        $actions = $this->getFormActions();

        parent::__construct($controller, $validator, $name, $fields, $actions);
    }

    public function getFormFields()
    {
        $fields = FieldList::create();
        $fields->push(PasswordField::create('token', '2FA Code'));

        $backURL = $this->controller->getRequest()->getVar('BackURL');
        if ($backURL) {
            $fields->push(HiddenField::create('BackURL', $backURL));
        }
        return $fields;
    }

    public function getFormActions()
    {
        $action = FieldList::create(
            [
                FormAction::create('validateTOTP', 'Validate')
            ]
        );
        return $action;
    }

    public function getAuthenticatorName()
    {
        return _t('TOTPLoginForm.TITLE', 'Second factor authentication');
    }
}
