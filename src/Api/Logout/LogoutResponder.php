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
        $response = FigResponseCookies::expire(
            new EmptyResponse,
            JwtDecoder::ATTR_TOKEN
        );

        $response = FigResponseCookies::expire(
            $response,
            JwtDecoder::ATTR_XSRF
        );

        return $response;
    }

    public function respondToHtml(ServerRequestInterface $request): ResponseInterface
    {
        return $this->respondToJson($request);
    }
}
