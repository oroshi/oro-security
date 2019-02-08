<?php

declare(strict_types=1);

namespace Oro\Security\Api\Login;

use Daikon\Config\ConfigProviderInterface;
use Dflydev\FigCookies\FigResponseCookies;
use Dflydev\FigCookies\SetCookie;
use Dflydev\FigCookies\Modifier\SameSite;
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

    /** @var ConfigProviderInterface */
    private $config;

    /** @var string */
    private $jwt;

    public function __construct(ConfigProviderInterface $config, string $jwt)
    {
        $this->config = $config;
        $this->jwt = $jwt;
    }

    public function respondToJson(ServerRequestInterface $request): ResponseInterface
    {
        $payload = explode('.', $this->jwt)[1];
        $decodedToken = JWT::jsonDecode(JWT::urlsafeB64Decode($payload));

        /*
         * Use an xsrf cookie so the lifetime of the token matches the jwt. Also the
         * _Host- cookie name prefix requires that domain be excluded and path be '/'.
         */
        $response = FigResponseCookies::set(
            new EmptyResponse,
            SetCookie::create(JwtDecoder::ATTR_TOKEN)
                ->withValue($this->jwt)
                ->withExpires(gmdate('D, d M Y H:i:s T', $decodedToken->exp))
                ->withPath('/')
                ->withSecure($this->config->get('project.cors.scheme') === 'https')
                ->withHttpOnly(true)
                ->withSameSite(SameSite::strict())
        );

        $response = FigResponseCookies::set(
            $response,
            SetCookie::create(JwtDecoder::ATTR_XSRF)
                ->withValue($decodedToken->xsrf)
                ->withExpires(gmdate('D, d M Y H:i:s T', $decodedToken->exp))
                ->withPath('/')
                ->withSecure($this->config->get('project.cors.scheme') === 'https')
                ->withSameSite(SameSite::strict())
        );

        return $response;
    }

    public function respondToHtml(ServerRequestInterface $request): ResponseInterface
    {
        return $this->respondToJson($request);
    }
}
