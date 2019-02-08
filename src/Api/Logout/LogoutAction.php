<?php

declare(strict_types=1);

namespace Oro\Security\Api\Logout;

use Oro\Security\Api\MessageResponder;
use Oro\Security\Api\UserActionTrait;
use Oroshi\Core\Middleware\Action\ActionInterface;
use Oroshi\Core\Middleware\ActionHandler;
use Oroshi\Core\Middleware\JwtDecoder;
use Psr\Http\Message\ServerRequestInterface;

final class LogoutAction implements ActionInterface
{
    use UserActionTrait;

    public function __invoke(ServerRequestInterface $request): ServerRequestInterface
    {
        try {
            // Reset auth token on logout
            if ($jwt = $request->getAttribute(JwtDecoder::ATTR_TOKEN)) {
                $this->userService->logout($jwt->data->id);
            }
        } catch (\Exception $error) {
            // Continue if logout is invalid for any reason
        }

        return $request->withAttribute(
            ActionHandler::ATTR_RESPONDER,
            [LogoutResponder::class, []]
        );
    }

    public function handleError(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(
            ActionHandler::ATTR_RESPONDER,
            [MessageResponder::class, [
                ':message' => 'Invalid logout request.',
                ':statusCode' => self::STATUS_UNPROCESSABLE_ENTITY
            ]]
        );
    }

    public function isSecure(): bool
    {
        return false;
    }
}
