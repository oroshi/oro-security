<?php

declare(strict_types=1);

namespace Oro\Security\Api\Login;

use Oro\Security\Api\MessageResponder;
use Oro\Security\Api\UserActionTrait;
use Oroshi\Core\Middleware\Action\ActionInterface;
use Oroshi\Core\Middleware\ActionHandler;
use Psr\Http\Message\ServerRequestInterface;

final class LoginAction implements ActionInterface
{
    use UserActionTrait;

    const ATTR_PAYLOAD = '@login';

    public function __invoke(ServerRequestInterface $request): ServerRequestInterface
    {
        $payload = array_values($request->getAttribute(self::ATTR_PAYLOAD));

        try {
            if ($user = $this->userService->authenticate(...$payload)) {
                $this->userService->login($user);
                $responder = LoginResponder::class;
                $params = [':jwt' => $this->userService->generateJWT($user)];
            } else {
                sleep(2);
                $responder = MessageResponder::class;
                $params = [':message' => 'Failed to login user.', ':statusCode' => self::STATUS_UNAUTHORIZED];
            }
        } catch (\Exception $error) {
            $message = 'Unexpected error occured during login.';
            $this->logger->error($message, ['exception' => $error->getMessage()]);
            sleep(2);
            $responder = MessageResponder::class;
            $params = [':message' => $message, ':statusCode' => self::STATUS_INTERNAL_SERVER_ERROR];
        }

        return $request->withAttribute(ActionHandler::ATTR_RESPONDER, [$responder, $params]);
    }

    public function registerValidator(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(
            ActionHandler::ATTR_VALIDATOR,
            [LoginValidator::class, [':exportTo' => self::ATTR_PAYLOAD]]
        );
    }
}
