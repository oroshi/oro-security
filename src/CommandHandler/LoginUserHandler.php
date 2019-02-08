<?php

declare(strict_types=1);

namespace Oro\Security\CommandHandler;

use Daikon\EventSourcing\Aggregate\Command\CommandHandler;
use Daikon\MessageBus\Metadata\Metadata;
use Oro\Security\User\Login\LoginUser;

final class LoginUserHandler extends CommandHandler
{
    protected function handleLoginUser(LoginUser $loginUser, Metadata $metadata): array
    {
        $user = $this->checkout(
            $loginUser->getAggregateId(),
            $loginUser->getKnownAggregateRevision()
        );

        return [$user->login($loginUser), $metadata];
    }
}
