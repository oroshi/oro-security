<?php

declare(strict_types=1);

namespace Oro\Security\Api\User;

use Oro\Security\Api\MessageResponder;
use Oro\Security\Api\UserActionTrait;
use Oro\Security\Middleware\UserHandler;
use Oroshi\Core\Middleware\ActionHandler;
use Oroshi\Core\Middleware\Action\ActionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ResourceAction implements ActionInterface
{
    use UserActionTrait;

    public function __invoke(ServerRequestInterface $request): ServerRequestInterface
    {
        $user = $request->getAttribute(UserHandler::ATTR_USER);

        return $request->withAttribute(
            ActionHandler::ATTR_RESPONDER,
            [ResourceResponder::class, [':user' => $user]]
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
