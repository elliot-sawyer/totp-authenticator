<?php

namespace ElliotSawyer\TOTPAuthenticator\Tests\Authenticators;

use ElliotSawyer\TOTPAuthenticator\TOTPAuthenticator;
use Firesphere\BootstrapMFA\Authenticators\BootstrapMFAAuthenticator;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

class TOTPAuthenticatorTest extends SapphireTest
{
    protected static $fixture_file = 'TOTPAuthenticatorTest.yml';

    /**
     * @var HTTPRequest
     */
    protected $request;

    /**
     * @var ValidationResult
     */
    protected $result;

    /**
     * @var TOTPAuthenticator
     */
    protected $authenticator;

    protected function setUp()
    {
        parent::setUp();

        $this->request = new HTTPRequest('GET', '/');
        $this->request->setSession(new Session([]));

        $this->result = new ValidationResult();

        $this->authenticator = $this->getMockBuilder(TOTPAuthenticator::class)
            ->setMethods(['getTokenFromTOTP'])
            ->getMock();

        // Assign a member ID from the fixtures to the session
        $memberId = $this->idFromFixture(Member::class, 'admin_user');
        $this->request->getSession()->set(BootstrapMFAAuthenticator::SESSION_KEY . '.MemberID', $memberId);
    }

    /**
     * @todo is this actually desired behaviour?
     */
    public function testValidateTOTPReturnsValidationResultOnFailure()
    {
        $this->request->getSession()->clearAll();
        $result = $this->authenticator->validateTOTP([], $this->request, $this->result);

        $this->assertInstanceOf(ValidationResult::class, $result);
    }

    public function testValidateTOTPWithoutToken()
    {
        $this->authenticator->validateTOTP([], $this->request, $this->result);

        $this->assertFalse($this->result->isValid(), 'Missing input data should cause an error');
        $this->assertContains('No token sent', $this->result->serialize());
    }

    public function testValidateTOTPWithMismatchingKeyProvided()
    {
        $this->authenticator->validateTOTP(['token' => 'willnotmatch'], $this->request, $this->result);

        $this->assertFalse($this->result->isValid(), 'Mismatching token should cause an error');
        $this->assertContains('TOTP Failed', $this->result->serialize());
    }

    public function testValidateTOTPWithValidData()
    {
        $this->authenticator->expects($this->once())->method('getTokenFromTOTP')->willReturn('123456');
        $memberToken = '123456';

        $result = $this->authenticator->validateTOTP(['token' => $memberToken], $this->request, $this->result);

        $this->assertTrue($this->result->isValid(), 'Valid TOTP token should validate successfully');
        $this->assertInstanceOf(Member::class, $result, 'The member object should be returned on success');
    }

    /**
     * @param string $configuredAlgorithm
     * @param string $expected
     * @dataProvider algorithmProvider
     */
    public function testGetAlgorithm($configuredAlgorithm, $expected)
    {
        Config::modify()->set(TOTPAuthenticator::class, 'algorithm', $configuredAlgorithm);

        $this->assertSame($expected, TOTPAuthenticator::get_algorithm());
    }

    /**
     * @return array[]
     */
    public function algorithmProvider()
    {
        return [
            'valid algorithm' => ['sha256', 'sha256'],
            'another valid algorithm' => ['sha512', 'sha512'],
            'invalid algorithm' => ['foo123', 'sha1'],
        ];
    }
}
