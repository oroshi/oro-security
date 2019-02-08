<?php

declare(strict_types=1);

namespace Oro\Security\Middleware;

use Middlewares\Utils\Traits\HasResponseFactory;
use Oro\Security\ReadModel\Standard\Users;
use Oroshi\Core\Middleware\RoutingHandler;
use Oroshi\Core\Middleware\Action\ActionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

class AuthenticationHandler implements MiddlewareInterface
{
    use HasResponseFactory;

    const ATTR_USER = '_user';

    /** @var LoggerInterface */
    private $logger;

    /** @var Users */
    private $users;

    public function __construct(LoggerInterface $logger, Users $users)
    {
        $this->logger = $logger;
        $this->users = $users;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $user = null;
        if ($this->isSecure($request)) {
            $jwt = $request->getAttribute(JwtDecoder::ATTR_JWT);
            $xsrfToken = $request->getAttribute(JwtDecoder::ATTR_XSRF);
            
            if (!$jwt || !$jwt->uid) {
                return $this->createResponse(403);
            }
            if ($jwt->xsrf !== $xsrfToken) {
                return $this->createResponse(401, 'Unauthorized XSRF');
            }
            if (!$user = $this->users->byId($jwt->uid)) {
                return $this->createResponse(403, 'User not found');
            }
        }

        return $handler->handle($request->withAttribute(self::ATTR_USER, $user));
    }

    private function isSecure(ServerRequestInterface $request): bool
    {
        $requestHandler = $request->getAttribute(RoutingHandler::ATTR_HANDLER);
        return !empty($requestHandler) && $requestHandler instanceof ActionInterface
            ? $requestHandler->isSecure()
            : false;
    }
}
