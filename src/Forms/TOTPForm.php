<?php

namespace SilverstripeElliot\TOTPAuthenticator;

use Firesphere\BootstrapMFA\Forms\BootstrapMFALoginForm;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\PasswordField;

/**
 * Class TOTPForm
 * @package SilverstripeElliot\TOTPAuthenticator
 */
class TOTPForm extends BootstrapMFALoginForm
{
    /**
     * TOTPForm constructor.
     * @param RequestHandler|null $controller
     * @param null $validator
     * @param string $name
     */
    public function __construct(
        RequestHandler $controller = null,
        $validator = null,
        $name = self::DEFAULT_NAME
    ) {
        $this->controller = $controller;
        $fields = $this->getFormFields();
        $actions = $this->getFormActions();

        parent::__construct($controller, $validator, $name, $fields, $actions);
    }

    /**
     * @return FieldList|static
     */
    public function getFormFields()
    {
        $fields = FieldList::create();
        $fields->push(PasswordField::create('token', _t(self::class . '.TOTPCODE', 'TOTP Code')));

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
                FormAction::create('validateTOTP', 'Validate')
            ]
        );

        return $action;
    }

    /**
     * @return string
     */
    public function getAuthenticatorName()
    {
        return _t(self::class . '.TITLE', 'TOTP Second factor authentication');
    }
}
