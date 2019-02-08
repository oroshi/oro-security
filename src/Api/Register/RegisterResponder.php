<?php

declare(strict_types=1);

namespace Oro\Security\Api\Register;

use Oro\Security\User\Register\RegisterUser;
use Oroshi\Core\Middleware\Action\ResponderInterface;
use Oroshi\Core\Middleware\Action\ResponderTrait;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\EmptyResponse;

final class RegisterResponder implements ResponderInterface
{
    use ResponderTrait;

    /** @var RegisterUser */
    private $registration;

    public function __construct(RegisterUser $registration)
    {
        $this->registration = $registration;
    }

    public function respondToJson(ServerRequestInterface $request): ResponseInterface
    {
        //@todo add a redirect location header
        return new EmptyResponse(self::HTTP_CREATED);
    }

    public function respondToHtml(ServerRequestInterface $request): ResponseInterface
    {
        return $this->respondToJson($request);
    }
}
