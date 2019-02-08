<?php

declare(strict_types=1);

namespace Oro\Security\Api\Logout;

use Dflydev\FigCookies\FigResponseCookies;
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
        return FigResponseCookies::expire(
            new EmptyResponse(self::STATUS_NO_CONTENT),
            JwtDecoder::ATTR_TOKEN
        );
    }

    public function respondToHtml(ServerRequestInterface $request): ResponseInterface
    {
        return $this->respondToJson($request);
    }
}
