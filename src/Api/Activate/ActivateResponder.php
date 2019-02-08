<?php

declare(strict_types=1);

namespace Oro\Security\Api\Activate;

use Oroshi\Core\Middleware\Action\ResponderInterface;
use Oroshi\Core\Middleware\Action\ResponderTrait;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\EmptyResponse;

final class ActivateResponder implements ResponderInterface
{
    use ResponderTrait;

    public function respondToJson(ServerRequestInterface $request): ResponseInterface
    {
        return new EmptyResponse;
    }

    public function respondToHtml(ServerRequestInterface $request): ResponseInterface
    {
        return $this->respondToJson($request);
    }
}
