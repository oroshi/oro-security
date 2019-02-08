<?php

declare(strict_types=1);

namespace Oro\Security\Api\User;

use Oro\Security\Api\MessageResponder;
use Oro\Security\Api\UserActionTrait;
use Oroshi\Core\Middleware\ActionHandler;
use Oroshi\Core\Middleware\Action\ActionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Oroshi\Core\Middleware\JwtDecoder;

final class ResourceAction implements ActionInterface
{
    use UserActionTrait;

    const ATTR_PAYLOAD = '@user';

    public function __invoke(ServerRequestInterface $request): ServerRequestInterface
    {
        $payload = $request->getAttribute(self::ATTR_PAYLOAD);
        $params = [':user' => $payload['_user']];

        return $request->withAttribute(ActionHandler::ATTR_RESPONDER, [ResourceResponder::class, $params]);
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
