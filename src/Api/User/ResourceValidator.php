<?php

declare(strict_types=1);

namespace Oro\Security\Api\User;

use Assert\Assert;
use Oro\Security\ReadModel\Standard\Users;
use Oroshi\Core\Middleware\ActionHandler;
use Oroshi\Core\Middleware\Action\ValidatorInterface;
use Oroshi\Core\Middleware\Action\ValidatorTrait;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

final class ResourceValidator implements ValidatorInterface
{
    use ValidatorTrait;

    /** @var string */
    private const TOKEN = 'userId';

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
        $errors = [];
        $payload = $this->validateAttributes([self::TOKEN], $request, $errors);
        $userId = $payload[self::TOKEN];

        $user = $userId && $userId !== ResourceAction::USER_ME
            ? $this->users->byId($userId)
            : null;

        return empty($errors)
            ? $request->withAttribute($this->exportTo, $payload + ['user' => $user])
            : $request->withAttribute($this->exportErrors, $errors);
    }

    private function validateUserId(string $name, $value): string
    {
        if ($value !== ResourceAction::USER_ME) {
            Assert::that($value, null, $name)->regex(
                '#^(?:\w+\.){2}\w+-[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$#i',
                'Invalid format.'
            );
        }

        return $value;
    }
}
