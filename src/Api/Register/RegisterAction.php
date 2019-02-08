<?php

declare(strict_types=1);

namespace Oro\Security\Api\Register;

use Assert\Assertion;
use Oro\Security\Api\AbstractUserAction;
use Oro\Security\Api\MessageResponder;
use Oro\Security\Api\UserActionTrait;
use Oroshi\Core\Middleware\Action\ActionInterface;
use Oroshi\Core\Middleware\ActionHandler;
use Oroshi\Core\Middleware\ValidationInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\JsonResponse;

final class RegisterAction implements ActionInterface
{
    use UserActionTrait;

    const ATTR_PAYLOAD = '@register';

    public function __invoke(ServerRequestInterface $request): ServerRequestInterface
    {
        $payload = $request->getAttribute(self::ATTR_PAYLOAD);

        try {
            $registration = $this->userService->register($payload);
            $responder = RegisterResponder::class;
            $params = [':registration' => $registration];
        } catch (\Exception $error) {
            $errorMsg = 'An unexpected error occured during registration.';
            $this->logger->error($errorMsg, ['exception' => $error]);

            $responder = MessageResponder::class;
            $params = [':message' => $errorMsg, ':statusCode' => self::STATUS_INTERNAL_SERVER_ERROR];
        }

        return $request->withAttribute(ActionHandler::ATTR_RESPONDER, [$responder, $params]);
    }

    public function registerValidator(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(
            ActionHandler::ATTR_VALIDATOR,
            [RegisterValidator::class, [':exportTo' => self::ATTR_PAYLOAD]]
        );
    }

    public function handleError(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(
            ActionHandler::ATTR_RESPONDER,
            [MessageResponder::class, [
                ':message' => 'Invalid registration request data.',
                ':statusCode' => self::STATUS_UNPROCESSABLE_ENTITY
            ]]
        );
    }

    public function isSecure(): bool
    {
        return false;
    }
}
