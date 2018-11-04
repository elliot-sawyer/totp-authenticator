<?php

namespace ElliotSawyer\TOTPAuthenticator;

use SilverStripe\Control\RequestHandler;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\PasswordField;
use SilverStripe\Forms\RequiredFields;
use SilverStripe\Security\LoginForm;

/**
 * Class TOTPForm
 * @package ElliotSawyer\TOTPAuthenticator
 */
class TOTPForm extends LoginForm
{
    /**
     * TOTPForm constructor.
     * @param RequestHandler|null $controller
     * @param string $name
     * @param null|TOTPAuthenticator $authenticator
     */
    public function __construct(
        RequestHandler $controller = null,
        $name = self::DEFAULT_NAME,
        $authenticator = null
    ) {
        $this->controller = $controller;
        $fields = $this->getFormFields();
        $actions = $this->getFormActions();
        $validator = RequiredFields::create(['token']);

        parent::__construct($controller, $name, $fields, $actions, $validator);
        $this->setAuthenticatorClass(get_class($authenticator));
    }

    /**
     * @return FieldList|static
     */
    public function getFormFields()
    {
        $fields = FieldList::create([
            PasswordField::create('token', _t(self::class . '.TOTPCODE', 'TOTP Code')),
            HiddenField::create('AuthenticationMethod', $this->authenticator_class)
        ]);

        $backURL = $this->controller->getRequest()->getVar('BackURL');
        if ($backURL) {
            $fields->push(HiddenField::create('BackURL', $backURL));
        }

        return $fields;
    }

    /**
     * @return FieldList|static
     */
    public function getFormActions()
    {
        $action = FieldList::create(
            [
                FormAction::create('validateTOTP', _t(self::class . '.VALIDATETOTP', 'Validate'))
            ]
        );

        return $action;
    }

    /**
     * Return the title of the form for use in the frontend
     * For tabs with multiple login methods, for example.
     * This replaces the old `get_name` method
     * @return string
     */
    public function getAuthenticatorName()
    {
        return _t(self::class . '.TITLE', 'TOTP Second factor authentication');
    }
}
