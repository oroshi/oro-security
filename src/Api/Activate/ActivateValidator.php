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

    public function __construct(
        LoggerInterface $logger,
        Users $users,
        string $exportTo,
        string $exportErrors = ActionHandler::ATTR_ERRORS
    ) {
        $this->logger = $logger;
        $this->users = $users;
        $this->exportTo = $exportTo;
        $this->exportErrors = $exportErrors;
    }

    public function __invoke(ServerRequestInterface $request): ServerRequestInterface
    {
        $user = null;
        $errors = [];
        $payload = $this->validateFields([self::TOKEN], $request, $errors);

        if (empty($errors)) {
            if (!$user = $this->users->byToken($payload[self::TOKEN])) {
                $errors[self::TOKEN][] = 'Activation token not found.';
            }
        }

        return is_null($user)
            ? $request->withAttribute($this->exportErrors, $errors)
            : $request->withAttribute($this->exportTo, $payload + ['user' => $user]);
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
