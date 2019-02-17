<?php

declare(strict_types=1);

namespace Oro\Security\Api\Activate;

use Oro\Security\Api\MessageResponder;
use Oro\Security\Api\UserActionTrait;
use Oroshi\Core\Middleware\ActionHandler;
use Oroshi\Core\Middleware\Action\ActionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ActivateAction implements ActionInterface
{
    use UserActionTrait;

    const ATTR_PAYLOAD = '@activate';

    public function __invoke(ServerRequestInterface $request): ServerRequestInterface
    {
        $user = $request->getAttribute(self::ATTR_PAYLOAD)['user'];

        try {
            $this->userService->activate($user);
            $responder = ActivateResponder::class;
            $params = [':user' => $user];
        } catch (\Exception $error) {
            $errMsg = 'Unexpected error occured during activation.';
            $this->logger->error($errMsg, ['exception' => $error]);
            $responder = MessageResponder::class;
            $params = [':message' => $errMsg, ':statusCode' => self::STATUS_INTERNAL_SERVER_ERROR];
        }

        return $request->withAttribute(ActionHandler::ATTR_RESPONDER, [$responder, $params]);
    }

    public function registerValidator(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(
            ActionHandler::ATTR_VALIDATOR,
            [ActivateValidator::class, [':exportTo' => self::ATTR_PAYLOAD]]
        );
    }

    public function handleError(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(
            ActionHandler::ATTR_RESPONDER,
            [MessageResponder::class, [
                ':message' => 'Invalid request data.',
                ':statusCode' => self::STATUS_UNPROCESSABLE_ENTITY
            ]]
        );
    }

    public function isSecure(): bool
    {
        return false;
    }
}
