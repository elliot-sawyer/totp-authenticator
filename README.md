# NOT PRODUCTION READY. USE AT YOUR OWN RISK

# SilverStripe TOTP (Time-based One Time Password) Authenticator

This is a time-based token authenticator for SilverStripe. It allows users with apps such as Google Authenticator or Authy to generate a code to be used for logging into a SilverStripe installation. Backup codes are also available to the user, in case their second factor is lost or stolen.

This is based off Firesphere's MFABootstrap module. 

## Installation
`composer require silverstripe-elliot/totp-authenticator 0.0.2`

## TODO
* Allow developer to enable/disable
* Tests
