<?php

declare(strict_types=1);

namespace Oro\Security\Api\User;

use Oro\Security\ReadModel\Standard\User;
use Oroshi\Core\Middleware\Action\ResponderInterface;
use Oroshi\Core\Middleware\Action\ResponderTrait;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\JsonResponse;

final class ResourceResponder implements ResponderInterface
{
    use ResponderTrait;

    /** @var User */
    private $user;

    public function __construct(User $user)
    {
        $this->user = $user;
    }

    public function respondToJson(ServerRequestInterface $request): ResponseInterface
    {
        return new JsonResponse($this->user->toNative());
    }

    public function respondToHtml(ServerRequestInterface $request): ResponseInterface
    {
        return $this->respondToJson($request);
    }
}
