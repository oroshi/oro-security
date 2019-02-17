<?php

declare(strict_types=1);

namespace Oro\Security\Api\User;

use Assert\Assert;
use Oro\Security\Middleware\AuthenticationHandler;
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
    const USER_ID = 'userId';

    /** @var string */
    const USER_ME = 'me';

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
        $payload = $this->validateAttributes([self::USER_ID], $request, $errors);

        if ($userId = $payload[self::USER_ID]) {
            if ($userId === self::USER_ME) {
                $user = $request->getAttribute(AuthenticationHandler::ATTR_USER);
            } else {
                if (!$user = $this->users->byId($userId)) {
                    $errors[self::USER_ID][] = 'Not found.';
                    $errorCode = self::STATUS_NOT_FOUND;
                }
            }
        }

        return empty($errors)
            ? $request->withAttribute($this->exportTo, $payload + ['user' => $user])
            : $request->withAttribute($this->exportErrors, $errors)
                ->withAttribute($this->exportErrorCode, $errorCode ?? null);
    }

    private function validateUserId(string $name, $value): string
    {
        if ($value !== self::USER_ME) {
            Assert::that($value, null, $name)->regex(
                '#^(?:\w+\.){2}\w+-[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$#i',
                'Invalid format.'
            );
        }

        return $value;
    }
}
