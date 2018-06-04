# SilverStripe TOTP (Time-based One Time Password) Authenticator

This is a time-based token authenticator for SilverStripe. It allows users with apps such as Google Authenticator or Authy to generate a code to be used for logging into a SilverStripe installation. Backup codes are also available to the user, in case their second factor is lost, stolen, or otherwise unavailable.

This extends and builds from Firesphere's MFABootstrap module, and has been tested with a vanilla installation of CWP 2.0 and SilverStripe 4.1.1

## Supported Authenticators
It is difficult to support an exhaustive list of authenticator apps, but for the purposes of an initial release the following authenticators are supported.

* Google Authenticator
* Authy

If you know of any others that can be added to this list, raise a pull request along with any code and unit tests you've added to ensure support.

## Installation
`composer require elliot-sawyer/totp-authenticator`

## Configuration

Add the following to config.yml

```
SilverStripe\Security\Member:
  extensions:
    - ElliotSawyer\TOTPAuthenticator\MemberExtension

SilverStripe\Core\Injector\Injector:
  SilverStripe\Security\Security:
    properties:
      Authenticators:
        totpauthenticator: %$ElliotSawyer\TOTPAuthenticator\TOTPAuthenticator

```

## Usage

1. Login to CMS as usual, taking care to use the "default" authenticator. Visit the Security admin and select your user. Ignore the TOTPSecret field for now. Tick the "MFA Enabled" and “Reset MFA codes” and save the Member.
2. Take note of your backup tokens, as they can be used to log into your account if the authenticator is lost, stolen, or otherwise unavailable. These are stored encrypted in the database and are not recoverable. They must be reset if lost.
3. Return to Main tab and reveal the “Second Factor Token Secret. Scan the QR code with Google Authenticator or Authy. Your website name ( as defined by Site title) and your username are visible at the end of Google Authenticator.
4. Visit https://yoursite.local/Security/login/totpauthenticator to log in. You will be prompted for your second factor access code. 


## TODO
Please raise issues and feature requests at https://github.com/elliot-sawyer/totp-authenticator/issues
