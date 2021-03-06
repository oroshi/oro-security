<?php

declare(strict_types=1);

namespace Oro\Security\Api;

use Oroshi\Core\Middleware\Action\ResponderInterface;
use Oroshi\Core\Middleware\Action\ResponderTrait;
use Oroshi\Core\Middleware\ActionHandler;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\JsonResponse;

final class MessageResponder implements ResponderInterface
{
    use ResponderTrait;

    /** @var string */
    private $message;

    /** @var int */
    private $statusCode;

    public function __construct(string $message, int $statusCode = self::STATUS_OK)
    {
        $this->message = $message;
        $this->statusCode = $statusCode;
    }

    public function respondToJson(ServerRequestInterface $request): ResponseInterface
    {
        $errors = $request->getAttribute(ActionHandler::ATTR_ERRORS, []);
        if (!empty($errors)) {
            $errorCode = $request->getAttribute(ActionHandler::ATTR_ERROR_CODE)
                ?? self::STATUS_INTERNAL_SERVER_ERROR;
        }

        return new JsonResponse(
            ['message' => $this->message] +
            (!empty($errors) ? ['errors' => $errors] : []),
            $errorCode ?? $this->statusCode
        );
    }

    public function respondToHtml(ServerRequestInterface $request): ResponseInterface
    {
        return $this->respondToJson($request);
    }
}
