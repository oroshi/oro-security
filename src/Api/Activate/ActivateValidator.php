<?php

declare(strict_types=1);

namespace Oro\Security\Api\Activate;

use Assert\Assert;
use Oro\Security\ReadModel\Standard\Users;
use Oro\Security\ValueObject\RandomToken;
use Oroshi\Core\Middleware\ActionHandler;
use Oroshi\Core\Middleware\Action\ValidatorInterface;
use Oroshi\Core\Middleware\Action\ValidatorTrait;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

final class ActivateValidator implements ValidatorInterface
{
    use ValidatorTrait;

    /** @var string */
    private const TOKEN = '_vt';

    /** @var LoggerInterface */
    private $logger;

    /** @var Users */
    private $users;

    /** @var string */
    private $exportTo;

    /** @var string */
    private $exportErrors;

    /** @var string */
    private $exportErrorCode;

    public function __construct(
        LoggerInterface $logger,
        Users $users,
        string $exportTo,
        string $exportErrors = ActionHandler::ATTR_ERRORS,
        string $exportErrorCode = ActionHandler::ATTR_ERROR_CODE
    ) {
        $this->logger = $logger;
        $this->users = $users;
        $this->exportTo = $exportTo;
        $this->exportErrors = $exportErrors;
        $this->exportErrorCode = $exportErrorCode;
    }

    public function __invoke(ServerRequestInterface $request): ServerRequestInterface
    {
        $errors = [];
        $payload = $this->validateFields([self::TOKEN], $request, $errors);

        $token = $payload[self::TOKEN];
        if ($token && !$user = $this->users->byToken($token)) {
            $errors[self::TOKEN][] = 'Not found.';
            $errorCode = self::STATUS_NOT_FOUND;
        }

        return empty($errors)
            ? $request->withAttribute($this->exportTo, $payload + ['user' => $user])
            : $request->withAttribute($this->exportErrors, $errors)
                ->withAttribute($this->exportErrorCode, $errorCode ?? null);
    }

    private function validateVt(string $name, $value): RandomToken
    {
        Assert::lazy()
            ->that($value, $name)
            ->tryAll()
            ->string('Must be a string.')
            ->regex('#^[a-f0-9]{64}$#i', 'Must be 64 hex characters.')
            ->verifyNow();

        return RandomToken::fromNative($value);
    }
}
