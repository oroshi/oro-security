<?php

declare(strict_types=1);

namespace Oro\Security\Api\Register;

use Oro\Security\Api\MessageResponder;
use Oro\Security\Api\UserActionTrait;
use Oroshi\Core\Middleware\Action\ActionInterface;
use Oroshi\Core\Middleware\ActionHandler;
use Psr\Http\Message\ServerRequestInterface;

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
            $message = 'An unexpected error occured during registration.';
            $this->logger->error($message, ['exception' => $error]);
            $responder = MessageResponder::class;
            $params = [':message' => $message, ':statusCode' => self::STATUS_INTERNAL_SERVER_ERROR];
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
}
