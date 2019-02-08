<?php

declare(strict_types=1);

namespace Oro\Security\Middleware;

use Oro\Security\ReadModel\Standard\Users;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

class UserHandler implements MiddlewareInterface
{
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
        $jwt = $request->getAttribute(JwtDecoder::ATTR_JWT);

        $user = $jwt
            ? $this->users->byId($jwt->data->id)
            : null;

        return $handler->handle($request->withAttribute(self::ATTR_USER, $user));
    }
}
