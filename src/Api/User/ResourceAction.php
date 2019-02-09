<?php

declare(strict_types=1);

namespace Oro\Security\Api\User;

use Oro\Security\Api\MessageResponder;
use Oro\Security\Api\UserActionTrait;
use Oro\Security\Middleware\AuthenticationHandler;
use Oroshi\Core\Middleware\ActionHandler;
use Oroshi\Core\Middleware\Action\ActionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ResourceAction implements ActionInterface
{
    use UserActionTrait;

    const ATTR_PAYLOAD = '@resource';

    public function __invoke(ServerRequestInterface $request): ServerRequestInterface
    {
        $payload = $request->getAttribute(self::ATTR_PAYLOAD);
        $user = $payload['userId'] === 'me'
            ? $request->getAttribute(AuthenticationHandler::ATTR_USER)
            : $payload['resource'];

        return $request->withAttribute(
            ActionHandler::ATTR_RESPONDER,
            [ResourceResponder::class, [':user' => $user]]
        );
    }

    public function registerValidator(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(
            ActionHandler::ATTR_VALIDATOR,
            [ResourceValidator::class, [':exportTo' => self::ATTR_PAYLOAD]]
        );
    }

    public function handleError(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(
            ActionHandler::ATTR_RESPONDER,
            [MessageResponder::class, [
                ':message' => 'Invalid user request data.',
                ':statusCode' => self::STATUS_UNPROCESSABLE_ENTITY
            ]]
        );
    }

    public function isSecure(): bool
    {
        return true;
    }
}
