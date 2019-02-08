<?php

declare(strict_types=1);

namespace Oro\Security\Api\Login;

use Firebase\JWT\JWT;
use Oroshi\Core\Middleware\ActionHandler;
use Oroshi\Core\Middleware\JwtDecoder;
use Oroshi\Core\Middleware\Action\ResponderInterface;
use Oroshi\Core\Middleware\Action\ResponderTrait;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\EmptyResponse;

final class LoginResponder implements ResponderInterface
{
    use ResponderTrait;

    /** @var string */
    private $jwt;

    public function __construct(string $jwt)
    {
        $this->jwt = $jwt;
    }

    public function respondToJson(ServerRequestInterface $request): ResponseInterface
    {
        $payload = explode('.', $this->jwt)[1];
        $decodedToken = JWT::jsonDecode(JWT::urlsafeB64Decode($payload));

        $cookie = sprintf(
            '%s=%s;path=/;httponly;expires=%s;', //@todo send secure in production
            JwtDecoder::ATTR_TOKEN,
            $this->jwt,
            gmdate('D, d-M-Y H:i:s T', $decodedToken->exp)
        );

        return new EmptyResponse(
            self::STATUS_NO_CONTENT,
            [
                'Set-Cookie' => $cookie,
                'X-CSRF-TOKEN' => $decodedToken->csrf
            ]
        );
    }

    public function respondToHtml(ServerRequestInterface $request): ResponseInterface
    {
        return $this->respondToJson($request);
    }
}
