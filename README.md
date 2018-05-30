# SilverStripe TOTP (Time-based One Time Password) Authenticator

This is a time-based token authenticator for SilverStripe. It allows users with apps such as Google Authenticator or Authy to generate a code to be used for logging into a SilverStripe installation. Backup codes are also available to the user, in case their second factor is lost or stolen.

This is based off Firesphere's MFABootstrap module. 

## Installation
`composer require silverstripe-elliot/totp-authenticator 0.0.2`

## Configuration

Add the following to config.yml

```
SilverStripe\Security\Member:
  extensions:
    - SilverstripeElliot\TOTPAuthenticator\MemberExtension

SilverStripe\Core\Injector\Injector:
  SilverStripe\Security\Security:
    properties:
      Authenticators:
        totpauthenticator: %$SilverstripeElliot\TOTPAuthenticator\TOTPAuthenticator

```

### Set config.yml

1. Login to CMS. Visit the Security admin and select your user. Ignore the TOTPSecret field for now. Tick the "MFA Enabled" and “Reset MFA codes” and save the Member.
2. Take note of your backup tokens, as they can be used to log into your account if the authenticator is lost, stolen, or otherwise unavailable. These are stored encrypted in the database and are not recoverable. They must be reset if lost.
3. Return to Main tab and reveal the “Second Factor Token Secret. Scan the QR code with Google Authenticator or Authy. Your website name ( as defined by Site title) and your username are visible at the end of Google Authenticator.
4. Visit https://<yoursite>/Security/login/totpauthenticator to log in. You will be prompted for your second factor access code. 

* Usage docs
* Allow developer to enable/disable
* Tests
