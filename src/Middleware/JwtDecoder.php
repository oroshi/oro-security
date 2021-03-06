<?php

declare(strict_types=1);

namespace Oro\Security\Middleware;

use Daikon\Config\ConfigProviderInterface;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

class JwtDecoder implements MiddlewareInterface
{
    const ATTR_JWT = '_Host-_jwt';

    const ATTR_XSRF = '_Host-_xsrf';

    /** @var LoggerInterface */
    private $logger;

    /** @var ConfigProviderInterface */
    private $configProvider;

    public function __construct(LoggerInterface $logger, ConfigProviderInterface $configProvider)
    {
        $this->logger = $logger;
        $this->configProvider = $configProvider;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $cookieParams = $request->getCookieParams();
        $encodedJwt = $cookieParams[self::ATTR_JWT]
            ?? $this->parseAuthHeader($request->getHeaderLine('Authorization'));
        $xsrfToken = $cookieParams[self::ATTR_XSRF] ?? $request->getHeaderLine('X-XSRF-TOKEN');

        $decodedJwt = null;
        if ($encodedJwt) {
            $decodedJwt = $this->decodeJwt($encodedJwt);
        }

        return $handler->handle($request
            ->withAttribute(self::ATTR_JWT, $decodedJwt)
            ->withAttribute(self::ATTR_XSRF, $xsrfToken)
        );
    }

    private function decodeJwt(string $jwt): ?object
    {
        $secretKey = $this->configProvider->get('crates.oro.security.jwt.secret', 'oroshi');
        try {
            return JWT::decode($jwt, $secretKey, ['HS256']);
        } catch (BeforeValidException $err) {
            return null;
        } catch (ExpiredException $err) {
            return null;
        } catch (SignatureInvalidException $err) {
            return null;
        }
    }

    private static function parseAuthHeader(string $header): ?string
    {
        if (preg_match('/Bearer ([\w\.\-_]+)/', $header, $matches)) {
            return trim($matches[1]);
        }
        return null;
    }
}
