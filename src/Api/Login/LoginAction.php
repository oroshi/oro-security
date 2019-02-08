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
            //@todo consider ignoring rapid logins by checking auth token expiry
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
            $errMsg = 'Unexpected error occured during login.';
            $this->logger->error($errMsg, ['exception' => $error->getMessage()]);
            sleep(2);
            $responder = MessageResponder::class;
            $params = [':message' => $errMsg, ':statusCode' => self::STATUS_INTERNAL_SERVER_ERROR];
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

    public function handleError(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(
            ActionHandler::ATTR_RESPONDER,
            [MessageResponder::class, [
                ':message' => 'Invalid login request data.',
                ':statusCode' => self::STATUS_UNPROCESSABLE_ENTITY
            ]]
        );
    }

    public function isSecure(): bool
    {
        return false;
    }
}
