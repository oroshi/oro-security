<?php

declare(strict_types=1);

namespace Oro\Security\Api\Logout;

use Oro\Security\Api\UserActionTrait;
use Oro\Security\Middleware\JwtDecoder;
use Oroshi\Core\Middleware\Action\ActionInterface;
use Oroshi\Core\Middleware\ActionHandler;
use Psr\Http\Message\ServerRequestInterface;

final class LogoutAction implements ActionInterface
{
    use UserActionTrait;

    public function __invoke(ServerRequestInterface $request): ServerRequestInterface
    {
        try {
            // Reset auth token on logout
            if ($jwt = $request->getAttribute(JwtDecoder::ATTR_JWT)) {
                $this->userService->logout($jwt->uid);
            }
        } catch (\Exception $error) {
            // Continue if logout is invalid for any reason
        }

        return $request->withAttribute(
            ActionHandler::ATTR_RESPONDER,
            [LogoutResponder::class, []]
        );
    }
}
