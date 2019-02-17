<?php

declare(strict_types=1);

namespace Oro\Security\Api\Login;

use Assert\Assert;
use Oroshi\Core\Middleware\Action\ValidatorInterface;
use Oroshi\Core\Middleware\Action\ValidatorTrait;
use Oroshi\Core\Middleware\ActionHandler;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Stringy\Stringy;

final class LoginValidator implements ValidatorInterface
{
    use ValidatorTrait;

    /** @var int */
    private const PWD_MIN = 8;

    /** @var int */
    private const PWD_MAX = 60;

    /** @var int */
    private const NAME_MIN = 1;

    /** @var int */
    private const NAME_MAX = 30;

    /** @var string[] */
    private const INPUT_FIELDS = ['username', 'password'];

    /** @var LoggerInterface */
    private $logger;

    /** @var string */
    private $exportTo;

    /** @var string */
    private $exportErrors;

    /** @var string */
    private $exportErrorCode;

    public function __construct(
        LoggerInterface $logger,
        string $exportTo,
        string $exportErrors = ActionHandler::ATTR_ERRORS,
        string $exportErrorCode = ActionHandler::ATTR_ERROR_CODE
    ) {
        $this->logger = $logger;
        $this->exportTo = $exportTo;
        $this->exportErrors = $exportErrors;
        $this->exportErrorCode = $exportErrorCode;
    }

    public function __invoke(ServerRequestInterface $request): ServerRequestInterface
    {
        $errors = [];
        $payload = $this->validateFields(self::INPUT_FIELDS, $request, $errors);

        return empty($errors)
            ? $request->withAttribute($this->exportTo, $payload)
            : $request->withAttribute($this->exportErrors, $errors)
                ->withAttribute($this->exportErrorCode, $errorCode ?? null);
    }

    private function validateUsername(string $name, $value): string
    {
        $value = trim($value);
        Assert::lazy()
            ->that($value, $name)
            ->tryAll()
            ->string('Must be a string.')
            ->betweenLength(
                self::NAME_MIN,
                self::NAME_MAX,
                sprintf("Must be between %d and %d characters.", self::NAME_MIN, self::NAME_MAX)
            )
            ->verifyNow();
        return $value;
    }

    private function validatePassword(string $name, $value): string
    {
        $value = trim($value);
        Assert::lazy()
            ->that($value, $name)
            ->tryAll()
            ->string('Must be a string.')
            ->betweenLength(
                self::PWD_MIN,
                self::PWD_MAX,
                sprintf("Must be between %d and %d characters.", self::PWD_MIN, self::PWD_MAX)
            )
            ->verifyNow();
        return $value;
    }
}
