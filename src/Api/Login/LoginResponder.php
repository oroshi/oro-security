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
        $setCookie = SetCookie::create(JwtDecoder::ATTR_TOKEN)
            ->withValue($this->jwt)
            ->withExpires(gmdate('D, d M Y H:i:s T', $decodedToken->exp))
            ->withPath('/')
            ->withDomain($this->config->get('project.cors.host', 'localhost'))
            ->withSecure($this->config->get('project.cors.scheme') === 'https')
            ->withHttpOnly(true)
            ->withSameSite(SameSite::strict());

        return FigResponseCookies::set(
            new EmptyResponse(
                self::STATUS_NO_CONTENT,
                ['X-XSRF-TOKEN' => $decodedToken->xsrf]
            ),
            $setCookie
        );
    }

    public function respondToHtml(ServerRequestInterface $request): ResponseInterface
    {
        return $this->respondToJson($request);
    }
}
