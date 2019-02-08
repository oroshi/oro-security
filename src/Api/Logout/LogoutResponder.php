<?php

declare(strict_types=1);

namespace Oro\Security\Api\Logout;

use Oroshi\Core\Middleware\JwtDecoder;
use Oroshi\Core\Middleware\Action\ResponderInterface;
use Oroshi\Core\Middleware\Action\ResponderTrait;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\EmptyResponse;

final class LogoutResponder implements ResponderInterface
{
    use ResponderTrait;

    public function respondToJson(ServerRequestInterface $request): ResponseInterface
    {
        //@todo send secure in production
        $cookie = JwtDecoder::ATTR_TOKEN.'=;path=/;httponly;expires=Thu, 01 Jan 1970 00:00:00 GMT;';

        return new EmptyResponse(self::STATUS_NO_CONTENT, ['Set-Cookie' => $cookie]);
    }

    public function respondToHtml(ServerRequestInterface $request): ResponseInterface
    {
        return $this->respondToJson($request);
    }
}
